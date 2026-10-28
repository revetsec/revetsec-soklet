#!/usr/bin/env python3
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

"""Verify the unpublished Soklet source/artifact used by this adapter, without network access."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


NAMESPACES = {"m": "http://maven.apache.org/POM/4.0.0"}


def git(directory, *arguments):
    return subprocess.run(["git", "-C", str(directory), *arguments], check=True,
                          capture_output=True, text=True).stdout.strip()


def verify(directory, expected_commit, expected_jar_sha256, jar=None):
    problems = []
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit) or expected_commit == "0" * 40:
        return ["Soklet pin must be a nonzero full 40-character lowercase commit SHA."]
    if not re.fullmatch(r"[0-9a-f]{64}", expected_jar_sha256) or expected_jar_sha256 == "0" * 64:
        return ["Soklet JAR pin must be a nonzero 64-character lowercase SHA-256."]
    actual = git(directory, "rev-parse", "HEAD")
    if actual != expected_commit:
        problems.append(f"Soklet checkout is {actual}, expected {expected_commit}.")
    if git(directory, "status", "--porcelain"):
        problems.append("Soklet checkout has source changes or untracked files.")
    if not git(directory, "for-each-ref", "--format=%(refname)",
               "--contains", expected_commit, "refs/remotes/origin/"):
        problems.append("Soklet pin is not reachable from a fetched upstream branch.")
    pom = ET.parse(directory / "pom.xml").getroot()
    def value(path):
        return pom.findtext(path, namespaces=NAMESPACES)
    if (value("m:groupId"), value("m:artifactId"), value("m:version")) != ("com.soklet", "soklet", "4.0.0"):
        problems.append("Soklet source must build com.soklet:soklet:4.0.0.")
    if value("m:build/m:plugins/m:plugin[m:artifactId='maven-compiler-plugin']/m:configuration/m:release") != "21":
        problems.append("Soklet source must target Java 21.")
    if jar is not None:
        if not jar.is_file():
            problems.append(f"Soklet JAR is missing: {jar}.")
        elif hashlib.sha256(jar.read_bytes()).hexdigest() != expected_jar_sha256:
            problems.append("Soklet JAR does not match the pinned SHA-256.")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--soklet-directory", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-jar-sha256", required=True)
    parser.add_argument("--jar", type=Path)
    args = parser.parse_args(argv)
    try:
        problems = verify(args.soklet_directory, args.expected_commit, args.expected_jar_sha256, args.jar)
    except (OSError, subprocess.CalledProcessError, ET.ParseError) as failure:
        print(f"Cannot verify Soklet baseline: {failure}", file=sys.stderr)
        return 1
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"Verified Soklet 4.0.0 source at {args.expected_commit}"
          + (" and pinned JAR." if args.jar is not None else "."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
