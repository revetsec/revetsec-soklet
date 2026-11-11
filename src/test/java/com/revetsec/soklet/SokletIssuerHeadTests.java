/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.revetsec.soklet;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.server.*;
import com.revetsec.testing.ScriptedOAuthStore;
import com.soklet.*;
import com.soklet.annotation.GET;
import com.soklet.annotation.HEAD;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** The issuer's bodyless HEAD retains GET representation metadata through pinned Soklet. */
final class SokletIssuerHeadTests {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-03T12:00:00Z"), ZoneOffset.UTC);

    private static @NonNull OAuthAuthorizationServer server() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair = generator.generateKeyPair();
        return OAuthAuthorizationServer.withIssuer("https://issuer.example.test")
                .authorizationEndpoint(URI.create("https://issuer.example.test/authorize"))
                .tokenEndpoint(URI.create("https://issuer.example.test/token"))
                .jwksEndpoint(URI.create("https://issuer.example.test/jwks"))
                .clientRepository((id, budget) -> Optional.empty()).store(new ScriptedOAuthStore(CLOCK.instant())).clock(CLOCK)
                .stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("test", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).build())
                .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(
                        OAuthIssuerSigningKey.fromRsaKeyPair("test-key", pair.getPrivate(), pair.getPublic()))
                        .generation("test-generation").publishedAt(CLOCK.instant().minusSeconds(120)).build()))
                .grantPolicy((context, budget) -> OAuthAuthorizationDecision.withSubject(context.getSubject())
                        .authorizedScopesByResource(context.getAuthorizedScopesByResource()).build())
                .resources(Map.of("https://resource.example.test", Set.of("read"))).build();
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> preparedGetAndHeadRetainExactRepresentation() throws Exception {
        var server = server();
        return Stream.of("metadata", "jwks").flatMap(endpoint -> Stream.of("GET", "HEAD").map(method ->
                DynamicTest.dynamicTest(endpoint+" / "+method, () -> {
                    var prepared = prepared(server, endpoint, method); var adapted = SokletOAuthAuthorizationServer.responseFor(prepared);
                    assertEquals(prepared.getStatusCode(), adapted.getStatusCode());
                    assertEquals(prepared.getHeaders(), adapted.getHeaders());
                    assertArrayEquals(prepared.toHttpBodyWithCredentials(), bytes(adapted));
                    if (method.equals("HEAD")) {
                        assertTrue(adapted.getBody().isEmpty(), "A bodyless HEAD must not acquire an explicit zero-byte representation");
                        assertEquals(prepared(server, endpoint, "GET").getHeaders(), adapted.getHeaders());
                    } else assertTrue(adapted.getBody().isPresent());
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> defaultPipelineRetainsHeadLengthWithExplicitAndFallbackRoutes() throws Exception {
        var server = server(); var resource = new Endpoints(server);
        return paths().stream().map(path -> DynamicTest.dynamicTest(path, () -> {
            var config = SimulatorConfig.builder().httpServer().resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(Endpoints.class)))
                    .instanceProvider(provider(resource)).build();
            SokletSimulator.run(config, simulator -> {
                String endpoint = path.endsWith("metadata") ? "metadata" : "jwks";
                var expected = prepared(server, endpoint, "GET");
                var get = simulator.performHttpRequest(Request.fromRawUrl(HttpMethod.GET, path)).getMarshaledResponse();
                assertEquals(200, get.getStatusCode()); assertArrayEquals(expected.toHttpBodyWithCredentials(), bytes(get));
                assertEquals(expected.getHeaders(), withoutDate(get));
                var head = simulator.performHttpRequest(Request.fromRawUrl(HttpMethod.HEAD, path)).getMarshaledResponse();
                assertEquals(200, head.getStatusCode()); assertTrue(head.getBody().isEmpty());
                assertEquals(expected.getHeaders(), withoutDate(head));
                assertEquals(List.of(Integer.toString(bytes(get).length)), head.getHeaders().get("Content-Length"));
                assertTrue(bytes(get).length > 0);
            });
        }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> methodRejectionRemainsBodylessAndPrivate() throws Exception {
        var server = server();
        return Stream.of("metadata", "jwks").map(endpoint -> DynamicTest.dynamicTest(endpoint, () -> {
            var prepared = prepared(server, endpoint, "POST"); var adapted = SokletOAuthAuthorizationServer.responseFor(prepared);
            assertEquals(405, adapted.getStatusCode()); assertEquals(prepared.getHeaders(), adapted.getHeaders());
            assertEquals(List.of("GET, HEAD"), adapted.getHeaders().get("Allow"));
            assertEquals(List.of("no-store"), adapted.getHeaders().get("Cache-Control"));
            assertEquals(List.of("0"), adapted.getHeaders().get("Content-Length")); assertEquals(0, bytes(adapted).length);
        }));
    }

    @Test void unrelatedGetBodyStillDeterminesItsHeadLength() throws Exception {
        var resource = new Endpoints(server());
        var config = SimulatorConfig.builder().httpServer().resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(Endpoints.class)))
                .instanceProvider(provider(resource)).build();
        SokletSimulator.run(config, simulator -> {
            var head = simulator.performHttpRequest(Request.fromRawUrl(HttpMethod.HEAD, "/other")).getMarshaledResponse();
            assertEquals(200, head.getStatusCode()); assertTrue(head.getBody().isEmpty());
            assertEquals(List.of("5"), head.getHeaders().get("Content-Length"));
        });
    }

    @SuppressWarnings("NullAway") // Intentionally violates the required-argument contract.
    @Test void nullResponseRemainsProgrammerMisuse() {
        assertThrows(NullPointerException.class, () -> SokletOAuthAuthorizationServer.responseFor(null));
    }

    private static @NonNull List<@NonNull String> paths() { return List.of("/metadata", "/jwks", "/fallback/metadata", "/fallback/jwks"); }
    private static @NonNull OAuthServerResponse prepared(@NonNull OAuthAuthorizationServer server, @NonNull String endpoint, @NonNull String method) {
        return endpoint.equals("metadata") ? server.metadataResponse(method) : server.jwksResponse(method);
    }
    private static @NonNull InstanceProvider provider(@NonNull Endpoints resource) {
        return new InstanceProvider() {
            @Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type) { return type.cast(resource); }
        };
    }
    private static byte @NonNull [] bytes(@NonNull MarshaledResponse response) {
        return response.getBody().map(value -> assertInstanceOf(MarshaledResponseBody.Bytes.class, value).getBytes()).orElseGet(() -> new byte[0]);
    }
    private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> withoutDate(@NonNull MarshaledResponse response) {
        Map<String, List<String>> headers = new LinkedHashMap<>(response.getHeaders()); headers.remove("Date"); return headers;
    }
    public static final class Endpoints {
        private final @NonNull OAuthAuthorizationServer server;
        private Endpoints(@NonNull OAuthAuthorizationServer server) { this.server = server; }
        @GET("/metadata") @HEAD("/metadata")
        public @NonNull MarshaledResponse metadata(@NonNull Request request) { return SokletOAuthAuthorizationServer.responseFor(this.server.metadataResponse(request.getHttpMethod().name())); }
        @GET("/jwks") @HEAD("/jwks")
        public @NonNull MarshaledResponse jwks(@NonNull Request request) { return SokletOAuthAuthorizationServer.responseFor(this.server.jwksResponse(request.getHttpMethod().name())); }
        @GET("/fallback/metadata")
        public @NonNull MarshaledResponse fallbackMetadata(@NonNull Request request) { return metadata(request); }
        @GET("/fallback/jwks")
        public @NonNull MarshaledResponse fallbackJwks(@NonNull Request request) { return jwks(request); }
        @GET("/other")
        public @NonNull MarshaledResponse other() { return MarshaledResponse.withStatusCode(200).body("other".getBytes(StandardCharsets.US_ASCII)).build(); }
    }

    /** Optional private loopback rehearsal; excluded from ordinary unit-test socket requirements. */
    public static void main(java.lang.@NonNull String @NonNull [] arguments) throws Exception {
        var server = server(); var resource = new Endpoints(server); int port;
        try (ServerSocket reservation = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) { port = reservation.getLocalPort(); }
        var http = HttpServer.withPort(port).host("127.0.0.1").requestHandlerConcurrency(2).requestHandlerQueueCapacity(4).build();
        var config = SokletConfig.withHttpServer(http).resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(Endpoints.class)))
                .instanceProvider(provider(resource)).build();
        Soklet.run(config, () -> {
            for (String path : paths()) {
                String endpoint = path.endsWith("metadata") ? "metadata" : "jwks";
                var expected = prepared(server, endpoint, "GET"); byte[] representation = expected.toHttpBodyWithCredentials();
                try (Socket socket = new Socket("127.0.0.1", port)) {
                    socket.setSoTimeout(5_000); InputStream input = new BufferedInputStream(socket.getInputStream());
                    for (String method : List.of("GET", "HEAD", "GET")) {
                        socket.getOutputStream().write((method+" "+path+" HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nConnection: keep-alive\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                        socket.getOutputStream().flush();
                        assertEquals("HTTP/1.1 200 OK", line(input));
                        Map<String,List<String>> headers = new LinkedHashMap<>(); String field;
                        while (!(field = line(input)).isEmpty()) {
                            int colon = field.indexOf(':'); assertTrue(colon > 0);
                            headers.computeIfAbsent(field.substring(0,colon).toLowerCase(Locale.ROOT), ignored -> new ArrayList<>()).add(field.substring(colon+1).trim());
                        }
                        for (var header : expected.getHeaders().entrySet())
                            assertEquals(header.getValue(), headers.get(header.getKey().toLowerCase(Locale.ROOT)), header.getKey());
                        assertFalse(headers.containsKey("transfer-encoding"));
                        if (!method.equals("HEAD")) assertArrayEquals(representation, input.readNBytes(representation.length));
                        // The following GET status line proves the preceding HEAD leaked no body bytes.
                    }
                }
            }
        });
        System.out.println("{\"status\":\"PASS\",\"profiles\":4,\"headResponses\":4,\"getResponses\":8,\"requests\":12,\"persistentConnections\":4,\"headBodiesAbsent\":true}");
    }
    private static @NonNull String line(@NonNull InputStream input) throws IOException {
        StringBuilder text = new StringBuilder();
        while (text.length() < 8192) {
            int value = input.read(); if (value < 0) throw new EOFException("Incomplete private HTTP response");
            if (value == '\n') {
                assertTrue(!text.isEmpty() && text.charAt(text.length()-1) == '\r'); return text.substring(0,text.length()-1);
            }
            text.append((char)value);
        }
        throw new IOException("Private HTTP header line exceeded bound");
    }
}
