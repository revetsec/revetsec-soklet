# Changelog

All notable changes to revetsec-soklet are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Each release also states the minimum Revetsec core and Soklet versions it requires.

## Unreleased

Nothing has been released. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### Added

- Repository scaffold (milestone M0), with no adapter code yet:
  - a single-module Maven build for `com.revetsec:revetsec-soklet`, targeting Java 17, whose only non-test dependencies are Revetsec core, Soklet and annotation JARs, all `provided`;
  - the `com.revetsec.soklet` package;
  - contract tests for public API shape, package rules, source policy and documentation wording, copied from Revetsec core and adapted to one package;
  - CI that builds Revetsec core from a pinned commit, then this adapter on JDK 17, 21, 25 and 27, and checks the files copied from core for drift;
  - the repository documents, with `NAMING_CONVENTIONS.md` and `SECURITY.md` copied from Revetsec core.
