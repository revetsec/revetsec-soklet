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

import com.revetsec.oauth.AccessTokenValidationException;
import com.revetsec.oauth.BearerError;
import com.revetsec.oauth.BearerToken;
import com.soklet.HttpMethod;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SokletBearerTests {

	@Test
	void absentAuthorizationRemainsAbsent() {
		assertTrue(SokletBearer.bearerTokenFor(Request.fromPath(HttpMethod.GET, "/resource")).isEmpty());
	}

	@Test
	void queryBodyAndCookiesNeverSupplyCredentials() {
		Request request = Request.withRawUrl(HttpMethod.POST, "/resource?access_token=synthetic-query")
				.headers(Map.of("Content-Type", Set.of("application/x-www-form-urlencoded"),
						"Cookie", Set.of("access_token=synthetic-cookie")))
				.body("access_token=synthetic-body".getBytes(StandardCharsets.UTF_8)).build();
		assertTrue(SokletBearer.bearerTokenFor(request).isEmpty());
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> validRawBearerGrammarReachesCore() {
		return Stream.of("Bearer synthetic", "bEaReR synthetic", "Bearer  synthetic", "Bearer " + " ".repeat(57) + "synthetic",
				"Bearer A.Z-_/+~09==", "Bearer " + "a".repeat(65_536))
				.map(field -> DynamicTest.dynamicTest("valid field length " + field.length(), () -> {
					BearerToken token = SokletBearer.bearerTokenFor(request("aUtHoRiZaTiOn", Set.of(field))).orElseThrow();
					assertEquals("BearerToken{value=<redacted>}", token.toString());
					assertFalse(token.toString().contains("synthetic"));
				}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> malformedFieldsRemainFixedInvalidRequestVerdicts() {
		return Stream.of("", " ", "Basic synthetic", "Bearer", "Bearer ", "Bearer\tsynthetic", " Bearer synthetic",
				"Bearer synthetic ", "Bearer a b", "Bearer a,b", "Bearer a=tail", "Bearer =", "Bearer ü",
				"Bearer synthetic\r\nInjected: value", "Bearer " + " ".repeat(58) + "synthetic",
				"Bearer " + "a".repeat(65_537))
				.map(field -> DynamicTest.dynamicTest("malformed field length " + field.length(),
						() -> assertMalformed(request("Authorization", Set.of(field)))));
	}

	@Test
	void distinctMaterializedAuthorizationValuesReject() {
		assertMalformed(request("Authorization", Set.of("Bearer synthetic-a", "Bearer synthetic-b")));
	}

	@Test
	void differentlyCasedAuthorizationNamesCollectAllDistinctValues() throws ReflectiveOperationException {
		Request request = SokletRawInputTests.fromPhysicalHeaders(HttpMethod.GET, "/resource", List.of(
				Map.entry("Authorization", "Bearer synthetic-a"), Map.entry("authorization", "Bearer synthetic-b")), null);
		assertEquals(2, SokletOAuth.collectHeaderValues(request, "AUTHORIZATION").size());
		assertMalformed(request);
	}

	@Test
	void unrelatedHeadersNeverBecomeAuthorization() {
		Request request = Request.withRawUrl(HttpMethod.GET, "/resource")
				.headers(Map.of("Proxy-Authorization", Set.of("Bearer synthetic"),
						"X-Authorization", Set.of("Bearer synthetic"))).build();
		assertTrue(SokletBearer.bearerTokenFor(request).isEmpty());
	}

	@SuppressWarnings("NullAway") // Intentionally violates the required request contract.
	@Test
	void nullRequestFails() {
		assertThrows(NullPointerException.class, () -> SokletBearer.bearerTokenFor(null));
	}

	private static @NonNull Request request(@NonNull String name, @NonNull Set<@NonNull String> values) {
		return Request.withRawUrl(HttpMethod.GET, "/resource").headers(Map.of(name, values)).build();
	}

	private static void assertMalformed(@NonNull Request request) {
		AccessTokenValidationException failure = assertThrows(AccessTokenValidationException.class,
				() -> SokletBearer.bearerTokenFor(request));
		assertEquals(AccessTokenValidationException.Reason.MALFORMED_REQUEST, failure.getReason());
		assertEquals(BearerError.INVALID_REQUEST, failure.getBearerError());
		assertFalse(failure.toString().contains("synthetic"));
	}
}
