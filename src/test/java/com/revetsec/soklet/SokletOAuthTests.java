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

import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oauth.OAuthResponseException;
import com.soklet.HttpMethod;
import com.soklet.Request;
import com.soklet.Response;
import com.soklet.ResponseCookie;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static java.util.Objects.requireNonNull;

final class SokletOAuthTests {

	@Test
	void getPreservesRawEncodingAndRouteMode() {
		AuthorizationResponse response = SokletOAuth.authorizationResponseFor(Request.fromRawUrl(HttpMethod.GET,
				"/callback?code=a%2Bb%252Fc&state=x+y&extra=%E2%98%83"));
		assertEquals("a+b%2Fc", response.getCode().orElseThrow());
		assertEquals("x y", response.getState().orElseThrow());
		assertEquals(List.of("☃"), response.getParameters().get("extra"));
		assertEquals(AuthorizationRequestOptions.ResponseMode.QUERY, response.getResponseMode());
	}

	@Test
	void getIgnoresBodyAndContentType() {
		Request request = Request.withRawUrl(HttpMethod.GET, "/callback?code=query&state=trusted-route")
				.headers(Map.of("Content-Type", Set.of("text/plain")))
				.body("code=body&state=body".getBytes(StandardCharsets.UTF_8)).build();
		assertEquals("query", SokletOAuth.authorizationResponseFor(request).getCode().orElseThrow());
	}

	@Test
	void emptyGetQueryRemainsAnEmptyUntrustedResponse() {
		assertTrue(SokletOAuth.authorizationResponseFor(Request.fromPath(HttpMethod.GET, "/callback"))
				.getParameters().isEmpty());
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> repeatedSingletonQueryParametersReject() {
		return Stream.of("code=a&code=a", "state=a&state=b", "state=a&%73tate=a", "iss=a&iss=b",
				"error=a&error=a", "code=a&error=denied")
				.map(query -> DynamicTest.dynamicTest(query, () -> assertMalformed(Request.fromRawUrl(HttpMethod.GET,
						"/callback?" + query))));
	}

	@Test
	void repeatedNonProtocolQueryValuesRemainVisible() {
		AuthorizationResponse response = SokletOAuth.authorizationResponseFor(Request.fromRawUrl(HttpMethod.GET,
				"/callback?code=a&extra=x&extra=x&extra=y"));
		assertEquals(List.of("x", "x", "y"), response.getParameters().get("extra"));
	}

	@Test
	void postPreservesRawBodyEncodingAndSafeQueryExtras() {
		Request request = post("/callback?source=a%2Bb", "code=a%2Bb%252Fc&state=x+y",
				"Application/X-WWW-Form-Urlencoded; charset=\"UTF-8\"");
		AuthorizationResponse response = SokletOAuth.authorizationResponseFor(request);
		assertEquals("a+b%2Fc", response.getCode().orElseThrow());
		assertEquals("x y", response.getState().orElseThrow());
		assertEquals(List.of("a+b"), response.getParameters().get("source"));
		assertEquals(AuthorizationRequestOptions.ResponseMode.FORM_POST, response.getResponseMode());
	}

	@Test
	void postAbsentBodyStillUsesTheRawMimeContract() {
		Request request = Request.withRawUrl(HttpMethod.POST, "/callback")
				.headers(Map.of("Content-Type", Set.of("application/x-www-form-urlencoded"))).build();
		assertTrue(SokletOAuth.authorizationResponseFor(request).getParameters().isEmpty());
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> postCannotSplitOrCollapseCallbackMembers() {
		return Stream.of("/callback?code=query", "/callback?state=query", "/callback?iss=issuer",
				"/callback?error=denied", "/callback?extra=query")
				.map(url -> DynamicTest.dynamicTest(url, () -> assertMalformed(post(url,
						"code=body&state=body&extra=body", "application/x-www-form-urlencoded"))));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> repeatedPostSingletonsReject() {
		return Stream.of("code=a&code=a", "state=a&state=b", "state=a&%73tate=a", "error=a&error=a")
				.map(body -> DynamicTest.dynamicTest(body, () -> assertMalformed(post("/callback", body,
						"application/x-www-form-urlencoded"))));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> unsupportedCallbackMethodsAreApplicationMisuse() {
		return Stream.of(HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE, HttpMethod.HEAD, HttpMethod.OPTIONS)
				.map(method -> DynamicTest.dynamicTest(method.name(), () -> {
					IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
							() -> SokletOAuth.authorizationResponseFor(Request.fromPath(method, "/callback")));
					assertEquals("OAuth callback route must use GET or POST", failure.getMessage());
				}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> redirectsPreserveSafeRawUriText() {
		return Stream.of("https://issuer.example.test/authorize?state=a%2Bb&redirect_uri=%2Fcb",
				"http://127.0.0.1:8080/authorize", "https://issuer.example.test:443/authorize",
				"HTTPS://issuer.example.test/authorize", "http://[::1]:8080/authorize",
				"https://issuer.example.test/a/../b?x=%252F#section", "https://issuer.example.test/café")
				.map(raw -> DynamicTest.dynamicTest(raw, () -> {
					URI location = URI.create(raw);
					Response response = SokletOAuth.redirect(location);
					assertRedirect(response, location.toASCIIString());
					assertTrue(response.getCookies().isEmpty());
				}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> redirectsRejectUnsafeDestinationsWithoutEchoingThem() {
		return Stream.of("/callback", "//issuer.example.test/callback", "https:opaque", "https:///callback",
				"javascript:alert(1)", "ftp://issuer.example.test/callback", "https://user:secret@issuer.example.test/",
				"https://user%40issuer.example.test@evil.example.test/", "https://issuer.example.test:65536/",
				"https://issuer.example.test/%0d%0aLocation:evil", "https://issuer.example.test/?x=%0A",
				"https://issuer.example.test/%00", "https://issuer.example.test/%09", "https://issuer.example.test/%7f")
				.map(raw -> DynamicTest.dynamicTest(raw, () -> {
					IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
							() -> SokletOAuth.redirect(URI.create(raw)));
					assertEquals("OAuth redirect requires a safe absolute HTTP(S) URI without userinfo", failure.getMessage());
					assertFalse(requireNonNull(failure.getMessage()).contains(raw));
				}));
	}

	@Test
	void redirectCopiesApplicationCookiesAndPreservesTheirAttributes() {
		ResponseCookie cookie = ResponseCookie.with("__Host-session", "synthetic")
				.secure(true).httpOnly(true).path("/").sameSite(ResponseCookie.SameSite.LAX).build();
		Set<ResponseCookie> cookies = new HashSet<>(Set.of(cookie));
		Response response = SokletOAuth.redirect(URI.create("https://issuer.example.test/authorize"), cookies);
		cookies.clear();
		assertEquals(Set.of(cookie), response.getCookies());
		assertTrue(response.getCookies().iterator().next().getSecure());
		assertTrue(response.getCookies().iterator().next().getHttpOnly());
		assertRedirect(response, "https://issuer.example.test/authorize");
	}

	@SuppressWarnings("NullAway") // Intentionally violates required-argument contracts.
	@Test
	void nullArgumentsFail() {
		assertThrows(NullPointerException.class, () -> SokletOAuth.authorizationResponseFor(null));
		assertThrows(NullPointerException.class, () -> SokletOAuth.redirect(null));
		assertThrows(NullPointerException.class, () -> SokletOAuth.redirect(URI.create("https://issuer.example.test/"), null));
	}

	static @NonNull Request post(@NonNull String url, @NonNull String body, @NonNull String contentType) {
		return Request.withRawUrl(HttpMethod.POST, url).headers(Map.of("Content-Type", Set.of(contentType)))
				.body(body.getBytes(StandardCharsets.UTF_8)).build();
	}

	private static void assertMalformed(@NonNull Request request) {
		OAuthResponseException failure = assertThrows(OAuthResponseException.class,
				() -> SokletOAuth.authorizationResponseFor(request));
		assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, failure.getReason());
	}

	private static void assertRedirect(@NonNull Response response, @NonNull String expectedLocation) {
		assertEquals(302, response.getStatusCode());
		assertEquals(Set.of(expectedLocation), response.getHeaders().get("Location"));
		assertEquals(Set.of("no-store"), response.getHeaders().get("Cache-Control"));
		assertEquals(Set.of("no-referrer"), response.getHeaders().get("Referrer-Policy"));
		assertTrue(response.getBody().isEmpty());
	}
}
