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

"""Guard the published Soklet dependency and ensure CI has no source-commit pin."""

import hashlib
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def workflow_job(workflow, name):
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
                      workflow, re.M | re.S)
    if match is None:
        raise AssertionError("Missing workflow job: " + name)
    return match.group(1)


class SokletCentralDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pom = ET.parse(ROOT / "pom.xml").getroot()
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text()

    def test_pom_uses_literal_published_provided_dependency(self):
        self.assertEqual("4.0.0", self.pom.findtext("m:properties/m:soklet.version", namespaces=NS))
        dependency = self.pom.find("m:dependencies/m:dependency[m:groupId='com.soklet']", NS)
        self.assertIsNotNone(dependency)
        self.assertEqual("soklet", dependency.findtext("m:artifactId", namespaces=NS))
        self.assertEqual("${soklet.version}", dependency.findtext("m:version", namespaces=NS))
        self.assertEqual("provided", dependency.findtext("m:scope", namespaces=NS))

    def test_ci_resolves_central_dependency_without_framework_source_pin(self):
        for forbidden in ("SOKLET_SHA", "SOKLET_JAR_SHA256", "repository: soklet/soklet",
                          "verify-soklet-baseline.py", "-f soklet/pom.xml"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.workflow)
        for name in ("test", "static-analysis", "javadoc"):
            with self.subTest(job=name):
                job = workflow_job(self.workflow, name)
                self.assertIn("-f adapter/pom.xml", job)
                self.assertIn("cache: maven", job)

    def test_javadoc_index_is_bound_to_published_central_archive(self):
        manifest = json.loads((ROOT / "src/main/javadoc/links/manifest.json").read_text())
        row = next(item for item in manifest["indexes"] if item["path"] == "soklet-4.0.0/element-list")
        self.assertEqual(
            "https://repo.maven.apache.org/maven2/com/soklet/soklet/4.0.0/soklet-4.0.0-javadoc.jar",
            row["source"])
        self.assertEqual("d94685bb9813c82f8be83c71d205a2ca7911ef43c8d5623cac20a4ec5b3d1575",
                         row["archiveSha256"])
        index = ROOT / "src/main/javadoc/links" / row["path"]
        self.assertEqual(row["sha256"], hashlib.sha256(index.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
