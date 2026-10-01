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

import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oauth.OAuthResponseException;
import com.soklet.HttpMethod;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SokletRawInputTests {

	@Test
	void helperMatchesCoreForTheUnchangedRawQuery() {
		Request request = Request.fromRawUrl(HttpMethod.GET, "/callback?code=x%252Fy&state=a%2Bb&extra=x&extra=x");
		String rawQuery = request.getRawQuery().orElseThrow();
		assertEquals("code=x%252Fy&state=a%2Bb&extra=x&extra=x", rawQuery);
		assertEquals(AuthorizationResponse.fromQueryString(rawQuery).getParameters(),
				SokletOAuth.authorizationResponseFor(request).getParameters());
	}

	@Test
	void helperMatchesCoreForUnchangedPostBytesQueryAndMime() {
		byte[] body = "code=x%252Fy&state=a%2Bb&extra=x&extra=x".getBytes(StandardCharsets.UTF_8);
		Request request = Request.withRawUrl(HttpMethod.POST, "/callback?source=raw%2Bquery")
				.headers(Map.of("cOnTeNt-TyPe", Set.of("application/x-www-form-urlencoded; charset=UTF-8")))
				.body(body).build();
		assertArrayEquals(body, request.getBody().orElseThrow());
		assertEquals(AuthorizationResponse.fromFormBody(body,
				List.of("application/x-www-form-urlencoded; charset=UTF-8"), "source=raw%2Bquery").getParameters(),
				SokletOAuth.authorizationResponseFor(request).getParameters());
	}

	@Test
	void missingContentTypeRejectsRatherThanGuessingForm() {
		assertMalformed(Request.withRawUrl(HttpMethod.POST, "/callback")
				.body("code=a&state=b".getBytes(StandardCharsets.UTF_8)).build());
	}

	@Test
	void distinctContentTypeValuesCannotBeSelectedOrJoined() {
		assertMalformed(Request.withRawUrl(HttpMethod.POST, "/callback")
				.headers(Map.of("Content-Type", Set.of("application/x-www-form-urlencoded", "text/plain")))
				.body("code=a&state=b".getBytes(StandardCharsets.UTF_8)).build());
	}

	@Test
	void differentlyCasedContentTypeNamesCollectEveryDistinctValue() throws ReflectiveOperationException {
		Request request = fromPhysicalHeaders(HttpMethod.POST, "/callback", List.of(
				Map.entry("Content-Type", "application/x-www-form-urlencoded"),
				Map.entry("CONTENT-TYPE", "application/x-www-form-urlencoded; charset=UTF-8")),
				"code=a&state=b".getBytes(StandardCharsets.UTF_8));
		assertEquals(2, SokletOAuth.collectHeaderValues(request, "Content-Type").size());
		assertMalformed(request);
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rawMimeGrammarAndCharsetRemainCoreDecisions() {
		return Stream.of("text/plain", "application/json", "application/x-www-form-urlencoded; charset=ISO-8859-1",
				"application/x-www-form-urlencoded; charset=UTF-8; charset=UTF-8",
				"application/x-www-form-urlencoded; charset", "application/x-www-form-urlencoded; charset=\"UTF-8",
				"application/x-www-form-urlencoded; boundary=" + "a".repeat(8_192))
				.map(field -> DynamicTest.dynamicTest("invalid MIME length " + field.length(),
						() -> assertMalformed(SokletOAuthTests.post("/callback", "code=a&state=b", field))));
	}

	@Test
	void invalidUtf8BodyRemainsMalformed() {
		byte[] body = new byte[]{'c', 'o', 'd', 'e', '=', (byte) 0xc3, (byte) 0x28};
		assertMalformed(Request.withRawUrl(HttpMethod.POST, "/callback")
				.headers(Map.of("Content-Type", Set.of("application/x-www-form-urlencoded"))).body(body).build());
	}

	@Test
	void overLimitBodyRemainsMalformed() {
		assertMalformed(SokletOAuthTests.post("/callback", "code=" + "a".repeat(65_536),
				"application/x-www-form-urlencoded"));
	}

	@Test
	void identicalPhysicalMultiplicityCannotBeRecoveredFromSokletHeaderSets() {
		Set<String> materialized = new HashSet<>(List.of("Bearer synthetic", "Bearer synthetic"));
		Request request = Request.withRawUrl(HttpMethod.GET, "/resource")
				.headers(Map.of("Authorization", materialized)).build();
		assertEquals(List.of("Bearer synthetic"), SokletOAuth.collectHeaderValues(request, "Authorization"));
		assertTrue(SokletBearer.bearerTokenFor(request).isPresent(),
				"The trusted edge must reject identical physical duplicates before this Set representation");
	}

	@Test
	void identicalMixedCasePhysicalAuthorizationFieldsLoseSetMultiplicity() throws ReflectiveOperationException {
		Request request = fromPhysicalHeaders(HttpMethod.GET, "/resource", List.of(
				Map.entry("Authorization", "Bearer synthetic"), Map.entry("AUTHORIZATION", "Bearer synthetic")), null);
		assertEquals(List.of("Bearer synthetic"), SokletOAuth.collectHeaderValues(request, "Authorization"));
		assertTrue(SokletBearer.bearerTokenFor(request).isPresent(),
				"The trusted edge must reject identical physical duplicates, including mixed-case names");
	}

	@Test
	void headerCollectionRetainsExactSpacesAndDoesNotMutateItsInput() {
		Request request = Request.withRawUrl(HttpMethod.GET, "/resource")
				.headers(Map.of("Authorization", Set.of("Bearer  synthetic"))).build();
		assertEquals(List.of("Bearer  synthetic"), SokletOAuth.collectHeaderValues(request, "authorization"));
		assertEquals(Set.of("Bearer  synthetic"), request.getHeaders().get("Authorization"));
	}

	private static void assertMalformed(@NonNull Request request) {
		OAuthResponseException failure = assertThrows(OAuthResponseException.class,
				() -> SokletOAuth.authorizationResponseFor(request));
		assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, failure.getReason());
	}

	/** Builds genuine Soklet Requests through the server's physical-header seam; reflection is test-only. */
	static @NonNull Request fromPhysicalHeaders(@NonNull HttpMethod httpMethod, @NonNull String url,
			@NonNull List<Map.@NonNull Entry<@NonNull String, @NonNull String>> fields, byte @Nullable [] body)
			throws ReflectiveOperationException {
		Class<?> headerType = Class.forName("com.soklet.internal.microhttp.Header");
		List<Object> physical = new ArrayList<>();
		for (Map.Entry<String, String> field : fields)
			physical.add(headerType.getConstructor(String.class, String.class).newInstance(field.getKey(), field.getValue()));
		Request.RawBuilder builder = Request.withRawUrl(httpMethod, url);
		Method method = Request.RawBuilder.class.getDeclaredMethod("microhttpHeaders", List.class);
		method.setAccessible(true);
		method.invoke(builder, physical);
		if (body != null)
			builder = builder.body(body);
		return builder.build();
	}
}
