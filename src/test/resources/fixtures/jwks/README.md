# JWKS adapter certificate fixtures

These are public TEST ONLY certificates copied from Revetsec core's test
fixtures. Never use their associated keys or certificates outside tests.

- `publisher-leaf.pem` and `publisher-root.pem` form the ordered two-certificate
  chain documented in core's `fixtures/jwks/README.md`.
- `nonprod-signing.pem` is core's existing self-signed
  `fixtures/keys/sp-signing-rsa-2048-cert.pem`, used as a singleton chain for a
  distinct second RSA key.

No private key material is included here. Tests inspect the chain metadata
through the logical Soklet response body and do not depend on validity dates.
