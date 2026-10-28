# Standalone JWKS publication

Publish the public keys used for application signatures without configuring an OAuth authorization server. The application owns the URL and supplies public keys and optional metadata; the publisher prepares the JSON document and HTTP response.

The adapter offers two response variants. These factory classes return ordinary Soklet responses:

| Helper | Return type | Body | ETag | JSON serialization |
| --- | --- | --- | --- | --- |
| `JwksMarshaledResponse.from(...)` | `MarshaledResponse` | Prepared UTF-8 bytes | Strong | Prepared by Revetsec; works with Soklet's default marshaler |
| `JwksResponse.from(...)` | `Response` | Immutable `JwksResponse.Body` | Weak | Owned by the application's response marshaler |

## Complete Soklet 4 application with prepared bytes

This application publishes prod and nonprod RS384 keys and their certificate chains. Each PEM file contains one public X.509 certificate. Supply each chain in leaf-first order, followed by its issuing certificates, and adjust the intermediate/root entries to match the actual chain. The public signing key is taken from the leaf certificate.

```java
import com.revetsec.jose.JwksPublisher;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.PublishedJwk;
import com.revetsec.soklet.JwksMarshaledResponse;
import com.soklet.HttpServer;
import com.soklet.InstanceProvider;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import com.soklet.ResourceMethodResolver;
import com.soklet.SokletApplication;
import com.soklet.SokletConfig;
import com.soklet.annotation.GET;
import com.soklet.annotation.HEAD;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Set;

public final class JwksApplication {
    public static void main(String[] args) throws Exception {
        List<X509Certificate> prodChain = List.of(
            certificate(Path.of("certs/prod-leaf.pem")),
            certificate(Path.of("certs/prod-intermediate.pem")),
            certificate(Path.of("certs/prod-root.pem"))
        );
        List<X509Certificate> nonprodChain = List.of(
            certificate(Path.of("certs/nonprod-leaf.pem")),
            certificate(Path.of("certs/nonprod-intermediate.pem")),
            certificate(Path.of("certs/nonprod-root.pem"))
        );

        PublishedJwk prodKey = PublishedJwk
            .withPublicKey(prodChain.get(0).getPublicKey())
            .keyId("epic-prod")
            .algorithm(JwsAlgorithm.RS384)
            .certificateChain(prodChain)
            .build();
        PublishedJwk nonprodKey = PublishedJwk
            .withPublicKey(nonprodChain.get(0).getPublicKey())
            .keyId("epic-nonprod")
            .algorithm(JwsAlgorithm.RS384)
            .certificateChain(nonprodChain)
            .build();

        JwksPublisher publisher = JwksPublisher
            .withKeys(List.of(prodKey, nonprodKey))
            .cacheLifetime(Duration.ofHours(1))
            .build();
        JwksResource resource = new JwksResource(publisher);

        SokletConfig config = SokletConfig.withHttpServer(
                HttpServer.withPort(8080).host("127.0.0.1").build())
            .resourceMethodResolver(
                ResourceMethodResolver.fromClasses(Set.of(JwksResource.class)))
            .instanceProvider(new InstanceProvider() {
                @Override
                public <T> T provide(Class<T> type) {
                    return type == JwksResource.class
                        ? type.cast(resource)
                        : InstanceProvider.defaultInstance().provide(type);
                }
            })
            .build();

        // Uses the default ResponseMarshaler, including default HEAD handling.
        SokletApplication.run(config);
    }

    public static final class JwksResource {
        private final JwksPublisher publisher;

        public JwksResource(JwksPublisher publisher) {
            this.publisher = publisher;
        }

        @GET("/jwks")
        @HEAD("/jwks")
        public MarshaledResponse jwks(Request request) {
            return JwksMarshaledResponse.from(this.publisher, request);
        }
    }

    private static X509Certificate certificate(Path path) throws Exception {
        try (var input = Files.newInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(input);
        }
    }
}
```

Soklet's default response marshaler preserves the prepared HEAD representation length and bodyless conditional responses. No custom `ResponseMarshaler` is needed for this variant. Use a Soklet build that includes the default HEAD handling fix; it is included in the current 4.0.0 development source. This example targets Java 21+ and the updated local Revetsec and Soklet 4 builds.

Only the public key is required. `keyId`, `algorithm` and `certificateChain` are optional; omitted algorithms remain unspecified. The builder derives public JWK parameters from the key, validates a supplied algorithm against its key type, and snapshots the supplied certificate chain. The leaf certificate must match the public key. A supplied chain is checked for certificate order and signatures, and a certificate's key-usage extension must permit the appropriate signing or certificate-signing use. This does not perform PKIX trust validation or certificate validity-time checks.

The published key contains `use: "sig"`. A supplied certificate chain adds `x5c` as standard-base64 DER certificates, and `x5t` and `x5t#S256` as base64url thumbprints of the leaf certificate. No private key is accepted by this API.

Supported key and algorithm combinations are:

| Public key | Optional algorithms |
| --- | --- |
| RSA | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512` |
| EC P-256 | `ES256` |
| EC P-384 | `ES384` |
| EC P-521 | `ES512` |
| Ed25519 | `ED25519`, legacy `EDDSA` |

HMAC keys are not publishable because they are shared secrets. For a key without certificate metadata, use the same builder and omit `certificateChain(...)`.

## Typed response with application-owned serialization

Use the logical `Response` variant when application code or tests should inspect the body object before it is serialized. The publisher is the same configured instance as above; replace the resource method with:

```java
import com.revetsec.soklet.JwksResponse;
import com.soklet.Response;

@GET("/jwks")
@HEAD("/jwks")
public Response jwks(Request request) {
    return JwksResponse.from(this.publisher, request);
}
```

A successful GET carries an immutable `JwksResponse.Body`. Its `getKeys()` exposes the published keys, `toJsonObject()` returns the structured JWKS document, and `toJson()` returns JSON text. The body is absent for HEAD, 304 and error responses. This variant removes `Content-Length` and uses a weak ETag for the logical document, allowing equivalent JSON formatting chosen by the application.

The application must teach its normal response marshaler how to serialize this type. Soklet's default fallback calls an arbitrary object's `toString()`, which is diagnostic text rather than a JSON serialization contract. For example, add this resource-method handler to the application's configuration builder:

```java
import com.soklet.ResponseMarshaler;
import java.nio.charset.StandardCharsets;

ResponseMarshaler defaultMarshaler = ResponseMarshaler.defaultInstance();
ResponseMarshaler applicationMarshaler = ResponseMarshaler.builder()
    .resourceMethodHandler((request, response, resourceMethod) -> {
        if (response.getBody().orElse(null) instanceof JwksResponse.Body body) {
            return MarshaledResponse.withResponse(response)
                .body(body.toJson().getBytes(StandardCharsets.UTF_8))
                .build();
        }
        return defaultMarshaler.forResourceMethod(request, response, resourceMethod);
    })
    .build();

// Add .responseMarshaler(applicationMarshaler) to the SokletConfig builder.
```

The handler preserves the response's status, headers and cookies. Soklet calculates the final GET representation length from the serialized bytes; HEAD omits the length when the app has not produced a body. Its default HEAD handler needs no customization. An existing application JSON pipeline can instead serialize `body.toJsonObject()` using the JSON representation it supports. Preserve the JWKS document's keys and values so the weak ETag continues to identify the same logical document.

An application test can assert the typed contents directly:

```java
Response response = resource.jwks(getRequest);
JwksResponse.Body body = assertInstanceOf(
    JwksResponse.Body.class, response.getBody().orElseThrow());

assertEquals(200, response.getStatusCode());
assertEquals(List.of("epic-prod", "epic-nonprod"),
    body.getKeys().stream().map(key -> key.getKeyId().orElseThrow()).toList());
assertEquals(JwsAlgorithm.RS384, body.getKeys().get(0).getAlgorithm().orElseThrow());
assertEquals(publisher.toJsonObject(), body.toJsonObject());
```

For application code that prepares the core response separately, the exact-byte factory also accepts `com.revetsec.jose.JwksResponse`:

```java
return JwksMarshaledResponse.from(publisher.responseFor("GET"));
```

## HTTP behavior and rotation

Both variants return `application/jwk-set+json`, an ETag and public cache headers. The prepared-byte variant returns the exact JSON body and representation `Content-Length`; its ETag is strong. The logical `Response` variant returns a typed body for application serialization, omits `Content-Length` and uses a weak ETag. HEAD has no body. `If-None-Match` uses weak comparison and supports a list of tags or `*`; a matching GET or HEAD returns 304 with no body. Other methods receive 405 and `Allow: GET, HEAD`.

Repeated `If-None-Match` values are combined as a comma-separated list. The combination is bounded at 8,192 characters; oversized input receives the core publisher's 400 response. Configure container or server header limits as appropriate for your application.

The default cache lifetime is 60 seconds. `cacheLifetime(...)` accepts whole seconds from zero through one day; passing `null` restores the default. Select a lifetime that fits your key rotation policy. To rotate, construct a replacement publisher containing the active and retained verification keys and atomically replace the application's reference. Retain old public keys long enough for outstanding signatures and downstream caches. Key order is the supplied list order; changes to the document change its ETag.

## Framework baseline

These examples target Java 21 and Soklet 4.0.0 at pushed commit `61d02245c745cedf8452a1fc0a13be96f9414a9b`, including the default HEAD handling used by both variants. The framework JAR is built with Corretto 21.0.11 and verified against SHA-256 `56e37d0e8ef781822de1618595f43366df00bb29e7b486cdc5901623b83845a9`. See the [local build instructions](../CONTRIBUTING.md#local-build) while this framework release is unpublished. Revetsec core remains compatible with Java 17.
