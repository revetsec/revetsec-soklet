# revetsec-soklet

Revetsec helpers for [Soklet](https://www.soklet.com) applications.

**This adapter is pre-release.** OAuth callback/redirect, bearer parsing, issuer transport and SAML binding helpers are implemented; SCIM schema/resource/query/response and PATCH helpers are implemented. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### What Is It?

[Revetsec](https://github.com/revetsec/revetsec) is a zero-dependency Java library for OAuth 2.0 clients and resource servers, OpenID Connect relying parties, JOSE, SAML 2.0 service providers and SCIM 2.0 servers. Its core has no framework dependency: it parses raw query strings, form bodies and header values.

This adapter connects the two. Its helpers pass a Soklet `Request` to Revetsec core as raw input, and turn Revetsec results into Soklet responses. They contain no protocol logic, and every validation decision is made by Revetsec core.

Implemented static helpers:

- `SokletOAuth`: the authorization response of an OAuth or OpenID Connect callback, from a GET query or a POST form, and redirect responses with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`
- `SokletBearer`: a request's bearer token, for resource servers such as MCP endpoints
- `SokletOAuthAuthorizationServer`: raw authorization, token, revocation and introspection input and exact-byte core response mapping

`SokletSaml` passes the original ACS POST body, Content-Type header multiplicity and raw
Redirect query to core result parsers. Its outbound Redirect helpers take core-prepared
authentication or logout results; the application supplies browser cookies and owns its
sessions. `postFormResponse` renders a core-prepared authentication or logout form. A runnable SAML
Playground is available in the core repository's unpublished `examples/playground/`.
SCIM helpers translate raw query/body data, conditional headers and core-prepared responses.

### Usage

```java
AuthorizationResponse callback = SokletOAuth.authorizationResponseFor(request);
Optional<BearerToken> bearer = SokletBearer.bearerTokenFor(request);
Response redirect = SokletOAuth.redirect(authorizationUri, responseCookies);
```

The callback helper accepts GET or form POST and preserves a POST query alongside its raw body. Unsupported methods are app misuse. Configure trusted callback/provider URLs in the application. Pass the parsed callback and bound pending reference to the configured OAuth/OIDC client. A parsed bearer still requires access-token validation and an application permission check.

### SAML HTTP-POST logout

Use `SokletSaml.postLogoutBindingResultFor(request)` on logout POST routes. It preserves the original form body, every Content-Type value and the raw query and delegates binding checks to core. The existing `postBindingResultFor` ACS helper remains response-only. A parsed logout message's kind selects core's `acceptLogoutRequestResult` or `completeLogoutResult`; parsing never authenticates a message.

Configure the SP's `postSingleLogoutServiceUrl` and the approved IdP's `postSingleLogoutService` explicitly. Emit `beginPostLogoutResult` prepared requests with `logoutPostFormResponse(prepared, cspNonce)` and `respondToPostLogoutRequestResult` prepared responses with `logoutResponsePostFormResponse(prepared, cspNonce)`. The generic `postFormResponse` also accepts both logout forms. These helpers retain core's exact UTF-8 form and no-store response headers. The application sets CSP and cookies before delivery, persists browser-bound pending state for SP logout, and owns IdP selection and local session cleanup. A pending cookie on a cross-site POST callback requires Secure, HttpOnly and SameSite=None; a server-side pending store still requires a browser-specific binding secret.

Only core-accepted logout requests release checked session selectors, and only completed responses establish protocol success. Handle rejected, unavailable and indeterminate results. Clear pending browser state after a verified terminal status or expiry; a rejected callback does not cancel a valid pending attempt. Custom pending stores must implement conditional atomic `consumeIfMatches`; the default fails closed without consuming. RelayState stays opaque and is never a redirect destination.

### Installation

Adapter 1.x requires Revetsec core 1.0.0 or later. JDK 17 or newer is required, with a minimum runtime of Java 17.0.3.

Revetsec core and Soklet are `provided` dependencies of this adapter, so your application declares all three coordinates below. This adapter requires Soklet 4.0.0 or later. Until its release is available on Maven Central, use the pinned 4.0.0 framework artifact for local builds. The recorded 3.5.1 offline Javadoc index covers only the existing common transport types and is not the runtime baseline.

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
  <version>4.0.0</version>
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
  implementation 'com.soklet:soklet:4.0.0'
}
```

### Status

This adapter is **pre-release**, like Revetsec core. The helpers use only public Revetsec APIs. OAuth callbacks retain raw query/body text and every distinct materialized Content-Type value. Bearer parsing retains every distinct materialized Authorization value and rejects ambiguity in core; it grants no identity or permission. Applications select validators and make scope/authorization decisions.

Soklet 4 represents header values as lists. These helpers collect every materialized occurrence, including identical duplicates and differently cased names, so core can reject ambiguous Authorization and Content-Type fields. The trusted HTTP edge remains responsible for framing, complete-request and header limits before materialization.

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

### OAuth issuance

`SokletOAuthAuthorizationServer` is stateless transport glue for an application-routed core `OAuthAuthorizationServer`. The application owns route/issuer association, TLS, physical duplicate rejection/framing limits, browser sessions, authentication, CSRF, consent and persistence. Core retains protocol/state rules. Helpers preserve raw query/body bytes and every distinct materialized header occurrence.

```java
OAuthAuthorizationResult result = SokletOAuthAuthorizationServer.beginAuthorizationResultFor(server, request, browserBinding);
OAuthTokenResult token = SokletOAuthAuthorizationServer.tokenResultFor(server, request);
OAuthRevocationResult revoked = SokletOAuthAuthorizationServer.revocationResultFor(server, request);
OAuthIntrospectionResult checked = SokletOAuthAuthorizationServer.introspectionResultFor(server, request);
MarshaledResponse response = SokletOAuthAuthorizationServer.responseFor(preparedCoreResponse);
```

Use each helper on its configured route. Render interactions in the app and call core directly to resume/complete consent. Metadata/JWKS use `responseFor(server.metadataResponse(method))` and `responseFor(server.jsonWebKeySetResponse(method))`. Expected failures remain core results; typed infrastructure failures propagate for mapping with `server.responseForFailure(failure)`.

`responseFor` preserves prepared bytes/status/headers and optional credential-bearing Location, bypassing JSON marshalling. Add app cookies separately and keep credential-bearing responses out of diagnostics. Soklet 4's header lists retain materialized multiplicity, including identical values and differently cased names; core rejects ambiguous protocol fields. Reject incomplete or oversized requests and enforce physical framing limits at the trusted edge. See core's unpublished self-issued MCP example for app-owned authentication and explicit volatile-storage qualification.

SCIM schema/resource/query/response transport helpers are available through `SokletScim`. They preserve raw query/body data, physical header occurrences and prepared response bytes. The PATCH helper binds ordered operations through the core parser. See the core [SCIM server guide](../revetsec/docs/scim-server-primitives.md).

Reject `request.isContentTooLarge()` before invoking any SCIM helper. Soklet discards an oversized body, so passing that incomplete request to a parser would appear to core as an empty body. Configure upstream body, complete-request and header limits before materialization. For example, after authenticating and resolving the tenant:

```java
if (request.isContentTooLarge()) {
    return SokletScim.responseFor(provider.errorResponse(ScimError.requestTooLargeInstance()));
}
ScimResourceParseResult parsed = SokletScim.resourceResultFor(provider, users, request);
```

The application composes its authentication challenge and target-specific allowed methods with the prepared transport response. Keep the existing prepared headers and body when adding a bounded host header:

```java
MarshaledResponse denied = SokletScim.responseFor(provider.errorResponse(ScimError.unauthenticatedInstance()));
return denied.copy().headers(headers ->
    headers.put("WWW-Authenticate", List.of("Bearer realm=\"scim\""))).finish();
```

A 405 response needs an `Allow` header for the actual target route, using the same copier pattern. Add only methods that route implements. Host-added headers and actual HTTP framing remain subject to the application's transport limits.
