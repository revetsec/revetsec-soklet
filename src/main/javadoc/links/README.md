# Pinned external Javadoc indexes

These package and element indexes are inputs to Javadoc's `-linkoffline` option. The generated
hyperlinks still point to the public documentation, but the build never fetches those sites to
discover packages. `manifest.json` records, for each index, the upstream versioned archive (or Java
API index URL), its SHA-256, and the SHA-256 of the checked-in index. Indexes are stored as UTF-8
with LF line endings; where the upstream line endings differ, the original index checksum is recorded
separately.

The Java, jsr305 and JSpecify indexes and their manifest entries are copies of RevetSec core's
(`src/main/javadoc/links/` in the core repository). `scripts/verify-core-drift.py` fails when they
differ from the pinned core commit, and it checks every index here against its recorded SHA-256.

The Soklet 3.5.1 index was extracted from `soklet-3.5.1-javadoc.jar` on Maven Central. The JAR's
SHA-1 matched Central's published `.sha1`, and its SHA-256 is recorded as `archiveSha256`.

To upgrade a dependency, extract the index from that exact version's Javadoc JAR on Maven Central,
update the link target in `pom.xml` and the local directory, and record the new provenance and
checksums. Never fetch a mutable "latest" index during release packaging. A change to a shared index
is made in RevetSec core first, then copied here.

Java API links target Java 26, the pinned Javadoc JDK. The adapter's compile and runtime floor stays
Java 17. The Javadoc JAR is built from this adapter's first public type on; until then every build
passes `-Dmaven.javadoc.skip=true`.
