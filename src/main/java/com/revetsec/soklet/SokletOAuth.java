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
import com.soklet.HttpMethod;
import com.soklet.Request;
import com.soklet.Response;
import com.soklet.ResponseCookie;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Thin OAuth transport helpers for Soklet. Callback input remains untrusted until Revetsec core completes the
 * authorization transaction. These helpers select no provider and make no authentication or authorization decision.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class SokletOAuth {

	private SokletOAuth() {
		// Non-instantiable
	}

	/**
	 * Parses a callback using the route's GET or POST method. GET supplies the unchanged raw query; POST supplies
	 * the unchanged body, raw query and every materialized Content-Type value to core's form parser. No decoded
	 * query or form map is used. This parsing grants no identity and does not validate pending transaction state.
	 * <p>
	 * Soklet represents header values as sets. Identical physical duplicate fields, including differently cased
	 * names, can lose multiplicity before this helper sees them; a trusted edge must reject those duplicates.
	 * Distinct materialized values are preserved and rejected by core when ambiguous.
	 *
	 * @param request the application-routed callback request
	 * @return the untrusted parsed callback
	 * @throws IllegalArgumentException if the route uses neither GET nor POST
	 * @throws com.revetsec.oauth.OAuthResponseException if core rejects the raw callback or Content-Type
	 * @throws NullPointerException if request is null
	 * @since 1.0.0
	 */
	public static @NonNull AuthorizationResponse authorizationResponseFor(@NonNull Request request) {
		requireNonNull(request);
		if (request.getHttpMethod() == HttpMethod.GET)
			return AuthorizationResponse.fromQueryString(request.getRawQuery().orElse(""));
		if (request.getHttpMethod() == HttpMethod.POST)
			return AuthorizationResponse.fromFormBody(request.getBody().orElseGet(() -> new byte[0]),
					collectHeaderValues(request, "Content-Type"), request.getRawQuery().orElse(null));
		throw new IllegalArgumentException("OAuth callback route must use GET or POST");
	}

	/**
	 * Builds a 302 redirect with no-store and no-referrer headers. The application supplies a trusted destination;
	 * core remains responsible for selecting and validating provider endpoints used in its authorization flow.
	 *
	 * @param location the absolute HTTP(S) destination, without userinfo or control characters
	 * @return the redirect response
	 * @throws IllegalArgumentException if location is unsafe for an HTTP redirect
	 * @throws NullPointerException if location is null
	 * @since 1.0.0
	 */
	public static @NonNull Response redirect(@NonNull URI location) {
		return redirect(location, Set.of());
	}

	/**
	 * Builds a 302 redirect with application-owned cookies, no-store and no-referrer headers. Cookie selection
	 * and security attributes belong to the application. The destination is not derived from request headers.
	 *
	 * @param location the absolute HTTP(S) destination, without userinfo or control characters
	 * @param cookies the application's response cookies
	 * @return the redirect response
	 * @throws IllegalArgumentException if location is unsafe for an HTTP redirect
	 * @throws NullPointerException if a required argument or cookie is null
	 * @since 1.0.0
	 */
	public static @NonNull Response redirect(@NonNull URI location,
			@NonNull Set<@NonNull ResponseCookie> cookies) {
		String value = redirectLocation(requireNonNull(location));
		return Response.withStatusCode(302).cookies(Set.copyOf(requireNonNull(cookies))).headers(Map.of(
				"Location", Set.of(value),
				"Cache-Control", Set.of("no-store"),
				"Referrer-Policy", Set.of("no-referrer"))).build();
	}

	static @NonNull List<@NonNull String> collectHeaderValues(@NonNull Request request, @NonNull String name) {
		requireNonNull(request);
		requireNonNull(name);
		List<String> values = new ArrayList<>();
		for (Map.Entry<String, Set<String>> entry : request.getHeaders().entrySet())
			if (name.equalsIgnoreCase(entry.getKey()))
				values.addAll(entry.getValue());
		return List.copyOf(values);
	}

	private static @NonNull String redirectLocation(@NonNull URI location) {
		String scheme = location.getScheme();
		if (!location.isAbsolute() || location.isOpaque() || location.getHost() == null
				|| location.getHost().isEmpty() || location.getRawUserInfo() != null
				|| location.getPort() < -1 || location.getPort() > 65_535
				|| !("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme)))
			throw unsafeRedirect();
		String value = location.toASCIIString();
		for (int index = 0; index < value.length(); index++) {
			char character = value.charAt(index);
			if (character <= 0x20 || character >= 0x7f)
				throw unsafeRedirect();
			if (character == '%' && index + 2 < value.length()) {
				int high = Character.digit(value.charAt(index + 1), 16);
				int low = Character.digit(value.charAt(index + 2), 16);
				int decoded = high * 16 + low;
				if (high >= 0 && low >= 0 && (decoded < 0x20 || decoded == 0x7f))
					throw unsafeRedirect();
			}
		}
		return value;
	}

	private static @NonNull IllegalArgumentException unsafeRedirect() {
		return new IllegalArgumentException("OAuth redirect requires a safe absolute HTTP(S) URI without userinfo");
	}
}
