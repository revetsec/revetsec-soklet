# Changelog

All notable changes to revetsec-soklet are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Each release also states the minimum Revetsec core and Soklet versions it requires.

## 1.0.0 (2026-11-16)

First release. Requires Revetsec core 1.0.0, Soklet 4.0.0 and Java 21 or newer.

### Added

- OAuth client transport through `SokletOAuth`: raw browser callbacks become a `SokletOAuthCallbackResult`, and core-prepared redirects are written unchanged. A successful parse grants no identity until core completes the browser-bound transaction.
- Resource-server bearer extraction through `SokletBearer`, which keeps the raw `Authorization` header occurrences for core parsing.
- Issuer transport through `SokletOAuthAuthorizationServer`: raw request helpers for application-routed issuer endpoints and exact-byte mapping of core-prepared responses.
- SAML service provider (SP) transport through `SokletSaml`, including HTTP-POST Single Logout. It preserves the original form body, every Content-Type value and the raw query.
- SCIM transport through `SokletScim` for raw query and body data, conditional headers, physical header occurrences and prepared response bytes.
- Public JSON Web Key Set publication through `JwksResponse` and `JwksMarshaledResponse`.
- Browser request-origin extraction through `SokletBrowserRequestOrigins`, which passes every raw `Sec-Fetch-Site` and `Origin` occurrence to core's `BrowserRequestOriginPolicy`.
- `SokletRequestResult`, which reports an oversized or incomplete request explicitly instead of passing a partial body to core.
