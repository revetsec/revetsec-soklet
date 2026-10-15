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

import com.revetsec.jose.JwksPublisher;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.PublishedJwk;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonString;
import com.soklet.HttpMethod;
import com.soklet.InstanceProvider;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
import com.soklet.Request;
import com.soklet.ResourceMethodResolver;
import com.soklet.Response;
import com.soklet.ResponseMarshaler;
import com.soklet.SimulatorConfig;
import com.soklet.SokletSimulator;
import com.soklet.annotation.GET;
import com.soklet.annotation.HEAD;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

final class JwksResponsesTests {

	@Test
	void marshaledGetAndPreparedResponsesRetainCoreStatusHeadersAndExactBytes() throws Exception {
		JwksPublisher publisher = publisher();
		com.revetsec.jose.JwksResponse prepared = publisher.responseFor("GET");
		assertSameResponse(prepared, JwksMarshaledResponse.from(prepared));
		assertSameResponse(prepared, JwksMarshaledResponse.from(publisher, request(HttpMethod.GET)));
		assertEquals(publisher.toJson(), new String(body(JwksMarshaledResponse.from(prepared)), StandardCharsets.UTF_8));
	}

	@Test
	void logicalGetHasTypedBodyWeakValidatorAndNoPrecomputedLength() throws Exception {
		JwksPublisher publisher = publisher();
		Response response = JwksResponse.from(publisher, request(HttpMethod.GET));
		assertLogicalResponse(publisher.responseFor("GET"), response);
		JwksResponse.Body body = assertInstanceOf(JwksResponse.Body.class, response.getBody().orElseThrow());
		assertEquals(publisher.getKeys(), body.getKeys());
		assertEquals(publisher.toJsonObject(), body.toJsonObject());
		assertEquals(publisher.toJson(), body.toJson());
		assertEquals(List.of("application/jwk-set+json"), response.getHeaders().get("Content-Type"));
		assertEquals(List.of("public, max-age=3600, must-revalidate"), response.getHeaders().get("Cache-Control"));
	}

	@Test
	void typedBodyExposesOrderedRs384KeysAndCertificateChainsWithoutMutableViews() throws Exception {
		List<X509Certificate> prodChain = List.of(certificate("publisher-leaf.pem"), certificate("publisher-root.pem"));
		List<X509Certificate> nonprodChain = List.of(certificate("nonprod-signing.pem"));
		PublishedJwk prod = PublishedJwk.withPublicKey(prodChain.get(0).getPublicKey()).keyId("epic-prod")
				.algorithm(JwsAlgorithm.RS384).certificateChain(prodChain).build();
		PublishedJwk nonprod = PublishedJwk.withPublicKey(nonprodChain.get(0).getPublicKey()).keyId("epic-nonprod")
				.algorithm(JwsAlgorithm.RS384).certificateChain(nonprodChain).build();
		List<PublishedJwk> input = new ArrayList<>(List.of(prod, nonprod));
		JwksPublisher publisher = JwksPublisher.fromKeys(input);
		Response response = JwksResponse.from(publisher, request(HttpMethod.GET));
		input.clear();
		JwksResponse.Body body = assertInstanceOf(JwksResponse.Body.class, response.getBody().orElseThrow());
		assertEquals(List.of("epic-prod", "epic-nonprod"), body.getKeys().stream()
				.map(key -> key.getKeyId().orElseThrow()).toList());
		for (PublishedJwk key : body.getKeys())
			assertEquals(JwsAlgorithm.RS384, key.getAlgorithm().orElseThrow());
		assertCertificateChain(prodChain, body.getKeys().get(0));
		assertCertificateChain(nonprodChain, body.getKeys().get(1));
		JsonArray jsonKeys = assertInstanceOf(JsonArray.class, body.toJsonObject().getMembers().get("keys"));
		assertEquals(List.of(prod.toJsonObject(), nonprod.toJsonObject()), jsonKeys.getElements());
		assertThrows(UnsupportedOperationException.class, () -> body.getKeys().clear());
		assertThrows(UnsupportedOperationException.class, () -> body.toJsonObject().getMembers().clear());
		assertThrows(UnsupportedOperationException.class, () -> jsonKeys.getElements().clear());
		assertThrows(UnsupportedOperationException.class, () -> response.getHeaders().clear());
		assertThrows(UnsupportedOperationException.class, () -> requireNonNull(response.getHeaders().get("ETag")).clear());
		assertFalse(body.toString().contains("epic-prod"));
		assertFalse(body.toString().contains("epic-nonprod"));
		assertFalse(body.toString().contains("x5c"));
		assertFalse(body.toString().contains(prod.toJson()));
		assertFalse(body.toString().contains(assertInstanceOf(JsonString.class, prod.toJsonObject().getMembers().get("n")).getValue()));
		assertFalse(body.toString().contains(Base64.getEncoder().encodeToString(prodChain.get(0).getEncoded())));
	}

	@Test
	void emptyLogicalDocumentStillHasATypedBody() {
		JwksPublisher publisher = JwksPublisher.fromKeys(List.of());
		Response response = JwksResponse.from(publisher, request(HttpMethod.GET));
		JwksResponse.Body body = assertInstanceOf(JwksResponse.Body.class, response.getBody().orElseThrow());
		assertEquals(List.of(), body.getKeys());
		assertEquals("{\"keys\":[]}", body.toJson());
		assertLogicalResponse(publisher.responseFor("GET"), response);
	}

	@Test
	void logicalHeadNotModifiedAndRejectionsHaveNoBodyOrPrecomputedLength() throws Exception {
		JwksPublisher publisher = publisher();
		for (HttpMethod method : List.of(HttpMethod.HEAD, HttpMethod.POST)) {
			Response response = JwksResponse.from(publisher, request(method));
			assertLogicalResponse(publisher.responseFor(method.name()), response);
			assertTrue(response.getBody().isEmpty());
		}
		for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.HEAD)) {
			Response unchanged = JwksResponse.from(publisher, conditionalRequest(method, "*"));
			assertLogicalResponse(publisher.responseFor(method.name(), "*"), unchanged);
			assertEquals(304, unchanged.getStatusCode());
			assertTrue(unchanged.getBody().isEmpty());
			Response rejected = JwksResponse.from(publisher, conditionalRequest(method, "x".repeat(8_193)));
			assertLogicalResponse(publisher.responseFor(method.name(), "x".repeat(8_193)), rejected);
			assertEquals(400, rejected.getStatusCode());
			assertTrue(rejected.getBody().isEmpty());
		}
	}

	@Test
	void marshaledHeadHasGetHeadersAndNoBodyAndOtherMethodsUseCoreRejections() throws Exception {
		JwksPublisher publisher = publisher();
		MarshaledResponse head = JwksMarshaledResponse.from(publisher.responseFor("HEAD"));
		assertSameResponse(publisher.responseFor("HEAD"), head);
		assertEquals(publisher.responseFor("GET").getHeaders(), head.getHeaders());
		assertEquals(0, body(head).length);
		assertSameResponse(publisher.responseFor("POST"), JwksMarshaledResponse.from(publisher, request(HttpMethod.POST)));
	}

	@Test
	void defaultSokletPipelineRetainsExactBodylessHeadAndNotModifiedResponses() throws Exception {
		JwksPublisher publisher = publisher();
		ExactResource resource = new ExactResource(publisher);
		SimulatorConfig config = SimulatorConfig.builder().httpServer()
				.resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(ExactResource.class)))
				.instanceProvider(provider(resource)).build();
		SokletSimulator.run(config, simulator -> {
			assertSamePipelineResponse(publisher.responseFor("GET"), simulator.performHttpRequest(request(HttpMethod.GET)).getMarshaledResponse());
			assertSamePipelineResponse(publisher.responseFor("HEAD"), simulator.performHttpRequest(request(HttpMethod.HEAD)).getMarshaledResponse());
			for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.HEAD)) {
				MarshaledResponse unchanged = simulator.performHttpRequest(conditionalRequest(method, "*")).getMarshaledResponse();
				assertSamePipelineResponse(publisher.responseFor(method.name(), "*"), unchanged);
				assertFalse(unchanged.getHeaders().containsKey("Content-Length"));
			}
			assertSamePipelineResponse(publisher.responseFor("HEAD", "\"old\""),
					simulator.performHttpRequest(conditionalRequest(HttpMethod.HEAD, "\"old\"")).getMarshaledResponse());
			assertSamePipelineResponse(publisher.responseFor("HEAD", "x".repeat(8_193)),
					simulator.performHttpRequest(conditionalRequest(HttpMethod.HEAD, "x".repeat(8_193))).getMarshaledResponse());
			MarshaledResponse unrelated = simulator.performHttpRequest(Request.fromRawUrl(HttpMethod.HEAD, "/other")).getMarshaledResponse();
			assertEquals(List.of("5"), unrelated.getHeaders().get("Content-Length"));
			assertEquals(0, body(unrelated).length);
		});
	}

	@Test
	void applicationOwnsLogicalJsonSerializationAndDefaultHeadHandlingNeedsNoHook() throws Exception {
		JwksPublisher publisher = publisher();
		LogicalResource resource = new LogicalResource(publisher);
		ResponseMarshaler marshaler = ResponseMarshaler.builder().resourceMethodHandler((request, response, method) -> {
			Object value = response.getBody().orElse(null);
			if (value instanceof JwksResponse.Body jwksBody) {
				// An application may choose different JSON whitespace without invalidating the weak validator.
				byte[] encoded = (" \n" + jwksBody.toJson() + "\n ").getBytes(StandardCharsets.UTF_8);
				return MarshaledResponse.withResponse(response).body(encoded).build();
			}
			return ResponseMarshaler.defaultInstance().forResourceMethod(request, response, method);
		}).build();
		SimulatorConfig config = SimulatorConfig.builder().httpServer().responseMarshaler(marshaler)
				.resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(LogicalResource.class)))
				.instanceProvider(provider(resource)).build();
		SokletSimulator.run(config, simulator -> {
			MarshaledResponse get = simulator.performHttpRequest(request(HttpMethod.GET)).getMarshaledResponse();
			byte[] expectedBody = (" \n" + publisher.toJson() + "\n ").getBytes(StandardCharsets.UTF_8);
			assertArrayEquals(expectedBody, body(get));
			assertNotEquals(publisher.toJson().getBytes(StandardCharsets.UTF_8).length, body(get).length);
			assertEquals(List.of(Integer.toString(expectedBody.length)), get.getHeaders().get("Content-Length"));
			assertEquals(logicalHeaders(publisher.responseFor("GET")).get("ETag"), get.getHeaders().get("ETag"));
			MarshaledResponse head = simulator.performHttpRequest(request(HttpMethod.HEAD)).getMarshaledResponse();
			assertEquals(logicalHeaders(publisher.responseFor("HEAD")), withoutDate(head));
			assertTrue(head.getBody().isEmpty());
			assertFalse(head.getHeaders().containsKey("Content-Length"));
			for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.HEAD)) {
				MarshaledResponse unchanged = simulator.performHttpRequest(conditionalRequest(method,
						requireNonNull(get.getHeaders().get("ETag")).get(0))).getMarshaledResponse();
				assertEquals(304, unchanged.getStatusCode());
				assertEquals(logicalHeaders(publisher.responseFor(method.name(), "*")), withoutDate(unchanged));
				assertTrue(unchanged.getBody().isEmpty());
			}
			MarshaledResponse unrelated = simulator.performHttpRequest(Request.fromRawUrl(HttpMethod.GET, "/other")).getMarshaledResponse();
			assertEquals("other", new String(body(unrelated), StandardCharsets.UTF_8));
			assertEquals(List.of("text/plain; charset=UTF-8"), unrelated.getHeaders().get("Content-Type"));
		});
	}

	@Test
	void strongWeakListAndWildcardConditionalsApplyToBothVariants() throws Exception {
		JwksPublisher publisher = publisher();
		String strong = requireNonNull(publisher.responseFor("GET").getHeaders().get("ETag")).get(0);
		for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.HEAD)) {
			for (String field : List.of(strong, "W/" + strong, "\"old\", W/" + strong, "*")) {
				Request request = conditionalRequest(method, field);
				Response logical = JwksResponse.from(publisher, request);
				assertLogicalResponse(publisher.responseFor(method.name(), field), logical);
				assertEquals(304, logical.getStatusCode());
				assertTrue(logical.getBody().isEmpty());
				MarshaledResponse exact = JwksMarshaledResponse.from(publisher, request);
				assertSameResponse(publisher.responseFor(method.name(), field), exact);
				assertTrue(exact.getBody().isEmpty());
			}
		}
	}

	@Test
	void conditionalRequestCombinesPhysicalOccurrencesAndCaseVariantsForBothResponses() throws Exception {
		JwksPublisher publisher = publisher();
		String etag = requireNonNull(publisher.responseFor("GET").getHeaders().get("ETag")).get(0);
		Request request = SokletRawInputTests.fromPhysicalHeaders(HttpMethod.GET, "/jwks", List.of(
				Map.entry("If-None-Match", "\"old\""), Map.entry("IF-NONE-MATCH", "W/" + etag)), null);
		MarshaledResponse exact = JwksMarshaledResponse.from(publisher, request);
		assertSameResponse(publisher.responseFor("GET", "\"old\",W/" + etag), exact);
		assertEquals(304, exact.getStatusCode());
		Response logical = JwksResponse.from(publisher, request);
		assertLogicalResponse(publisher.responseFor("GET", "\"old\",W/" + etag), logical);
		assertEquals(304, logical.getStatusCode());
		assertTrue(logical.getBody().isEmpty());
	}

	@Test
	void combinedConditionalHeaderIsBoundedAndRejectedByCoreForBothResponses() throws Exception {
		JwksPublisher publisher = publisher();
		Request atLimit = conditionalRequest(HttpMethod.GET, "x".repeat(8_192));
		assertEquals(200, JwksResponse.from(publisher, atLimit).getStatusCode());
		assertEquals(200, JwksMarshaledResponse.from(publisher, atLimit).getStatusCode());
		for (List<String> values : List.of(List.of("x".repeat(8_193)),
				List.of("x".repeat(4_096), "y".repeat(4_096)), java.util.Collections.nCopies(8_194, ""))) {
			Request request = Request.withRawUrl(HttpMethod.GET, "/jwks").headers(Map.of("If-None-Match", values)).build();
			MarshaledResponse exact = JwksMarshaledResponse.from(publisher, request);
			assertSameResponse(publisher.responseFor("GET", "x".repeat(8_193)), exact);
			assertEquals(400, exact.getStatusCode());
			Response logical = JwksResponse.from(publisher, request);
			assertLogicalResponse(publisher.responseFor("GET", "x".repeat(8_193)), logical);
			assertEquals(400, logical.getStatusCode());
			assertTrue(logical.getBody().isEmpty());
		}
	}

	@Test
	@SuppressWarnings("NullAway") // Exercises runtime checks for deliberately invalid Java callers.
	void requiredArgumentsRejectNull() throws Exception {
		JwksPublisher publisher = publisher();
		Request request = request(HttpMethod.GET);
		assertThrows(NullPointerException.class, () -> JwksMarshaledResponse.from(null));
		assertThrows(NullPointerException.class, () -> JwksMarshaledResponse.from(null, request));
		assertThrows(NullPointerException.class, () -> JwksMarshaledResponse.from(publisher, null));
		assertThrows(NullPointerException.class, () -> JwksResponse.from(null, request));
		assertThrows(NullPointerException.class, () -> JwksResponse.from(publisher, null));
	}

	private static @NonNull JwksPublisher publisher() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2_048);
		return JwksPublisher.withKeys(List.of(PublishedJwk.withPublicKey(generator.generateKeyPair().getPublic())
				.keyId("epic-prod").algorithm(JwsAlgorithm.RS384).build())).cacheLifetime(Duration.ofHours(1)).build();
	}

	private static @NonNull Request request(@NonNull HttpMethod method) {
		return Request.fromRawUrl(method, "/jwks");
	}

	private static @NonNull Request conditionalRequest(@NonNull HttpMethod method, @NonNull String field) {
		return Request.withRawUrl(method, "/jwks").headers(Map.of("If-None-Match", List.of(field))).build();
	}

	private static @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
		try (InputStream input = requireNonNull(JwksResponsesTests.class.getResourceAsStream("/fixtures/jwks/" + name))) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
		}
	}

	private static void assertCertificateChain(@NonNull List<@NonNull X509Certificate> expected, @NonNull PublishedJwk key) throws Exception {
		List<JsonString> values = new ArrayList<>();
		for (X509Certificate certificate : expected)
			values.add(JsonString.fromValue(Base64.getEncoder().encodeToString(certificate.getEncoded())));
		assertEquals(values, assertInstanceOf(JsonArray.class, key.toJsonObject().getMembers().get("x5c")).getElements());
	}

	private static @NonNull InstanceProvider provider(@NonNull Object resource) {
		return new InstanceProvider() {
			@Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type) { return type.cast(resource); }
		};
	}

	private static void assertLogicalResponse(com.revetsec.jose.@NonNull JwksResponse prepared, @NonNull Response actual) {
		assertEquals(prepared.getStatusCode(), actual.getStatusCode());
		assertEquals(logicalHeaders(prepared), actual.getHeaders());
		assertFalse(actual.getHeaders().containsKey("Content-Length"));
	}

	private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> logicalHeaders(com.revetsec.jose.@NonNull JwksResponse prepared) {
		Map<String, List<String>> headers = new LinkedHashMap<>(prepared.getHeaders());
		headers.remove("Content-Length");
		headers.computeIfPresent("ETag", (name, values) -> values.stream().map(value -> "W/" + value).toList());
		return headers;
	}

	private static void assertSameResponse(com.revetsec.jose.@NonNull JwksResponse prepared, @NonNull MarshaledResponse actual) {
		assertEquals(prepared.getStatusCode(), actual.getStatusCode());
		assertEquals(prepared.getHeaders(), actual.getHeaders());
		assertArrayEquals(prepared.toHttpBody(), body(actual));
	}

	private static void assertSamePipelineResponse(com.revetsec.jose.@NonNull JwksResponse prepared, @NonNull MarshaledResponse actual) {
		assertEquals(prepared.getStatusCode(), actual.getStatusCode());
		assertEquals(prepared.getHeaders(), withoutDate(actual));
		assertArrayEquals(prepared.toHttpBody(), body(actual));
	}

	private static byte @NonNull [] body(@NonNull MarshaledResponse response) {
		return response.getBody().map(value -> assertInstanceOf(MarshaledResponseBody.Bytes.class, value).getBytes())
				.orElseGet(() -> new byte[0]);
	}

	private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> withoutDate(@NonNull MarshaledResponse response) {
		Map<String, List<String>> fields = new LinkedHashMap<>(response.getHeaders());
		fields.remove("Date");
		return fields;
	}

	public static final class ExactResource {
		private final @NonNull JwksPublisher publisher;
		private ExactResource(@NonNull JwksPublisher publisher) { this.publisher = publisher; }
		@GET("/jwks") @HEAD("/jwks")
		public @NonNull MarshaledResponse jwks(@NonNull Request request) { return JwksMarshaledResponse.from(this.publisher, request); }
		@GET("/other")
		public @NonNull MarshaledResponse other() {
			return MarshaledResponse.withStatusCode(200).body("other".getBytes(StandardCharsets.UTF_8)).build();
		}
	}

	public static final class LogicalResource {
		private final @NonNull JwksPublisher publisher;
		private LogicalResource(@NonNull JwksPublisher publisher) { this.publisher = publisher; }
		@GET("/jwks") @HEAD("/jwks")
		public @NonNull Response jwks(@NonNull Request request) { return JwksResponse.from(this.publisher, request); }
		@GET("/other")
		public @NonNull Response other() { return Response.withStatusCode(200).body("other").build(); }
	}
}
