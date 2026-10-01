# revetsec-soklet

Revetsec helpers for [Soklet](https://www.soklet.com) applications.

**This adapter is pre-release.** OAuth callback/redirect and bearer parsing helpers are implemented; SAML and SCIM helpers remain planned. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### What Is It?

[Revetsec](https://github.com/revetsec/revetsec) is a zero-dependency Java library for OAuth 2.0 clients and resource servers, OpenID Connect relying parties, JOSE, SAML 2.0 service providers and SCIM 2.0 servers. Its core has no framework dependency: it parses raw query strings, form bodies and header values.

This adapter connects the two. Its helpers pass a Soklet `Request` to Revetsec core as raw input, and turn Revetsec results into Soklet responses. They contain no protocol logic, and every validation decision is made by Revetsec core.

Implemented static helpers:

- `SokletOAuth`: the authorization response of an OAuth or OpenID Connect callback, from a GET query or a POST form, and redirect responses with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`
- `SokletBearer`: a request's bearer token, for resource servers such as MCP endpoints
SAML HTTP-POST and SCIM helpers remain later milestone work.

### Usage

```java
AuthorizationResponse callback = SokletOAuth.authorizationResponseFor(request);
Optional<BearerToken> bearer = SokletBearer.bearerTokenFor(request);
Response redirect = SokletOAuth.redirect(authorizationUri, responseCookies);
```

The callback helper accepts GET or form POST and preserves a POST query alongside its raw body. Unsupported methods are app misuse. Configure trusted callback/provider URLs in the application. Pass the parsed callback and bound pending reference to the configured OAuth/OIDC client. A parsed bearer still requires access-token validation and an application permission check.

### Installation

Adapter 1.x requires Revetsec core 1.0.0 or later. JDK 17 or newer is required, with a minimum runtime of Java 17.0.3.

Revetsec core and Soklet are `provided` dependencies of this adapter, so your application declares all three coordinates below. This adapter currently builds against Soklet 3.5.1. It moves to Soklet 4.0 if 4.0.0 is on Maven Central before this adapter's 1.0.0.

**Nothing has been published yet, including snapshots.** Until the first release, install Revetsec core and then this adapter into your local Maven repository from their source checkouts:

```shell
$ mvn -B -ntp -f revetsec/pom.xml -DskipTests -Dmaven.javadoc.skip=true install
$ mvn -B -ntp -f revetsec-soklet/pom.xml -Dmaven.javadoc.skip=true install
```

#### Maven

```xml
<dependency>
  <groupId>com.revetsec</groupId>
  <artifactId>revetsec-soklet</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
  <groupId>com.revetsec</groupId>
  <artifactId>revetsec</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
  <groupId>com.soklet</groupId>
  <artifactId>soklet</artifactId>
  <version>3.5.1</version>
</dependency>
```

#### Gradle

A Gradle build resolves locally installed snapshots only when `mavenLocal()` is among its repositories.

```groovy
repositories {
  mavenLocal()
  mavenCentral()
}

dependencies {
  implementation 'com.revetsec:revetsec-soklet:1.0.0-SNAPSHOT'
  implementation 'com.revetsec:revetsec:1.0.0-SNAPSHOT'
  implementation 'com.soklet:soklet:3.5.1'
}
```

### Status

This adapter is **pre-release**, like Revetsec core. The helpers use only public Revetsec APIs. OAuth callbacks retain raw query/body text and every distinct materialized Content-Type value. Bearer parsing retains every distinct materialized Authorization value and rejects ambiguity in core; it grants no identity or permission. Applications select validators and make scope/authorization decisions.

Soklet represents header values as sets. Identical duplicate physical fields can be discarded before these helpers run, including fields with differently cased names. Your trusted HTTP edge must reject those duplicate Authorization and Content-Type fields; the adapter cannot recover discarded multiplicity.

Redirect helpers accept an absolute HTTP(S) URI without userinfo, reject unsafe URI text, and return 302 with no-store/no-referrer headers and optional application cookies. The app supplies the redirect URI. Core chooses and validates provider endpoints.

Revetsec has not been independently audited. That includes this adapter. Its security evidence is meant to be reproducible by anyone and will be listed in the [`docs/`](https://github.com/revetsec/revetsec/tree/main/docs) directory of the core repository as it is produced. Current evidence records its exact implementation and provider scope; later milestones remain in progress.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Development Verification

This adapter builds against Revetsec core from source. With `JAVA_HOME` pointing at JDK 17 or newer, and the core repository checked out next to this one:

```shell
$ mvn -B -ntp -f ../revetsec/pom.xml -DskipTests -Dmaven.javadoc.skip=true install
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
$ python3 scripts/verify-core-drift.py --core-directory ../revetsec
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists every check that CI runs, and explains how CI pins the core commit it builds against.

### License

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
