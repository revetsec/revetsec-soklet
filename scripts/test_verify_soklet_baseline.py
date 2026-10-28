# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Negative controls for the source-built Soklet baseline and its CI integration."""

import hashlib
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("soklet_baseline", SCRIPTS / "verify-soklet-baseline.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
COMMIT = "a" * 40
JAR = b"synthetic framework JAR"
CHECKSUM = hashlib.sha256(JAR).hexdigest()
POM = '''<project xmlns="http://maven.apache.org/POM/4.0.0">
<groupId>com.soklet</groupId><artifactId>soklet</artifactId><version>4.0.0</version>
<build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId>
<configuration><release>21</release></configuration></plugin></plugins></build></project>'''


class BaselineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name)
        (self.source / "pom.xml").write_text(POM)
        self.jar = self.source / "soklet-4.0.0.jar"
        self.jar.write_bytes(JAR)
        self.head = COMMIT
        self.dirty = ""
        self.branches = "refs/remotes/origin/main"
        self.git = patch.object(VERIFIER, "git", side_effect=self.git_output).start()
        self.addCleanup(patch.stopall)

    def git_output(self, directory, *arguments):
        if arguments[0] == "rev-parse":
            return self.head
        if arguments[0] == "status":
            return self.dirty
        if arguments[0] == "for-each-ref":
            return self.branches
        raise AssertionError(arguments)

    def problems(self, commit=COMMIT, checksum=CHECKSUM, jar=True):
        return VERIFIER.verify(self.source, commit, checksum, self.jar if jar else None)

    def test_exact_source_and_artifact_pass(self):
        self.assertEqual([], self.problems())
        self.assertEqual([], self.problems(jar=False))

    def test_invalid_source_pins_fail_before_git(self):
        for pin in ("main", "v4.0.0", COMMIT[:7], COMMIT.upper(), "0" * 40, ""):
            with self.subTest(pin=pin):
                self.assertIn("commit SHA", self.problems(commit=pin)[0])
        self.git.assert_not_called()

    def test_invalid_artifact_pins_fail_before_git(self):
        for pin in ("0" * 64, CHECKSUM[:10], CHECKSUM.upper(), ""):
            with self.subTest(pin=pin):
                self.assertIn("SHA-256", self.problems(checksum=pin)[0])
        self.git.assert_not_called()

    def test_checkout_mismatch_fails(self):
        self.head = "b" * 40
        self.assertIn("checkout is", self.problems()[0])

    def test_source_edits_and_untracked_injections_fail(self):
        for status in (" M pom.xml", "?? src/main/java/com/soklet/Injected.java"):
            with self.subTest(status=status):
                self.dirty = status
                self.assertIn("source changes or untracked files", self.problems()[0])

    def test_fork_only_commit_fails(self):
        self.branches = ""
        self.assertIn("upstream branch", self.problems()[0])

    def test_wrong_coordinates_fail(self):
        for before, after in (("com.soklet", "example"), ("<artifactId>soklet<", "<artifactId>other<"),
                              ("4.0.0", "4.0.1")):
            with self.subTest(after=after):
                (self.source / "pom.xml").write_text(POM.replace(before, after))
                self.assertIn("com.soklet:soklet:4.0.0", self.problems()[0])

    def test_wrong_source_release_fails(self):
        (self.source / "pom.xml").write_text(POM.replace("<release>21<", "<release>17<"))
        self.assertIn("Java 21", self.problems()[0])

    def test_modified_or_missing_artifact_fails(self):
        self.jar.write_bytes(JAR + b"changed")
        self.assertIn("pinned SHA-256", self.problems()[0])
        self.jar.unlink()
        self.assertIn("missing", self.problems()[0])


class WorkflowBaselineTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (SCRIPTS.parent / ".github/workflows/ci.yml").read_text()
        body = self.workflow[self.workflow.index("\njobs:\n"):]
        names = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):$", body))
        self.jobs = {match.group(1): body[match.end():names[index + 1].start() if index + 1 < len(names) else len(body)]
                     for index, match in enumerate(names)}

    def test_source_and_artifact_are_pinned_once(self):
        for variable, width in (("SOKLET_SHA", 40), ("SOKLET_JAR_SHA256", 64)):
            values = re.findall(r"(?m)^  " + variable + r": '([0-9a-f]{" + str(width) + r"})'$", self.workflow)
            self.assertEqual(1, len(values))
            self.assertNotEqual("0" * width, values[0])
            self.assertEqual(1, self.workflow.count(variable + ":"))

    def test_every_build_installs_verified_framework_on_fixed_jdk_first(self):
        for name in ("test", "static-analysis", "javadoc"):
            job = self.jobs[name]
            with self.subTest(job=name):
                self.assertEqual(1, job.count("repository: soklet/soklet"))
                self.assertIn("ref: ${{ env.SOKLET_SHA }}", job)
                self.assertIn("fetch-depth: 0", job)
                self.assertIn("java-version: '21.0.11'", job)
                self.assertLess(job.index("java-version: '21.0.11'"), job.index("-f soklet/pom.xml"))
                self.assertLess(job.index("name: Verify the Soklet source pin"), job.index("-f soklet/pom.xml"))
                self.assertLess(job.index("rm -rf ~/.m2/repository/com/soklet"), job.index("-f soklet/pom.xml"))
                self.assertLess(job.index("-f soklet/pom.xml"), job.index("--jar soklet/target/soklet-4.0.0.jar"))
                self.assertLess(job.index("--jar soklet/target/soklet-4.0.0.jar"), job.index("-f adapter/pom.xml"))
        job = self.jobs["test"]
        self.assertLess(job.index("--jar soklet/target/soklet-4.0.0.jar"),
                        job.index("name: Set up Corretto ${{ matrix.jdk }} for adapter tests"))

    def test_adapter_build_and_documentation_target_java21(self):
        pom = ET.parse(SCRIPTS.parent / "pom.xml").getroot()
        ns = VERIFIER.NAMESPACES
        prefix = "m:build/m:plugins/m:plugin"
        self.assertEqual("21", pom.findtext(prefix + "[m:artifactId='maven-compiler-plugin']/m:configuration/m:release", namespaces=ns))
        self.assertEqual("21", pom.findtext(prefix + "[m:artifactId='maven-javadoc-plugin']/m:configuration/m:source", namespaces=ns))
        self.assertEqual("[21,)", pom.findtext(prefix + "[m:artifactId='maven-enforcer-plugin']/m:executions/m:execution/m:configuration/m:rules/m:requireJavaVersion/m:version", namespaces=ns))
        self.assertEqual("4.0.0", pom.findtext("m:properties/m:soklet.version", namespaces=ns))
        dependency = pom.find("m:dependencies/m:dependency[m:groupId='com.soklet']", ns)
        self.assertIsNotNone(dependency)
        self.assertEqual("${soklet.version}", dependency.findtext("m:version", namespaces=ns))
        self.assertEqual("provided", dependency.findtext("m:scope", namespaces=ns))
        self.assertNotIn("-Dsoklet.version", self.workflow)
        self.assertIn("jdk: ['21', '25', '27']", self.jobs["test"])


if __name__ == "__main__":
    unittest.main()
