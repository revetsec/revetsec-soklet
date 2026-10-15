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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.oauth.server.OAuthAuthorizationResult;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.oauth.server.OAuthIntrospectionResult;
import com.revetsec.oauth.server.OAuthRevocationResult;
import com.revetsec.oauth.server.OAuthServerResponse;
import com.revetsec.oauth.server.OAuthTokenResult;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/**
 * Thin issuer transport for application-routed Soklet requests and prepared core responses. Applications own
 * route/issuer association, TLS, allocation/framing limits, sessions, authentication, consent and CSRF. These
 * helpers use no decoded query/form map and make no user or authorization decision.
 * <p>
 * Soklet 4 exposes header values as lists. Every materialized occurrence and exact string reaches core;
 * its bounds and protocol rules remain authoritative.
 * @since 1.0.0
 */
@ThreadSafe
public final class SokletOAuthAuthorizationServer {

	private SokletOAuthAuthorizationServer() {}

	/**
	 * Admits raw authorization input with an independent app-owned browser binding.
	 * @param server configured issuer
	 * @param request request on the configured authorization route
	 * @param browserBinding canonical random binding retained in the protected application session
	 * @return an oversized transport outcome or core's restricted interaction or rejection
	 * @throws NullPointerException if a required argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull SokletRequestResult<@NonNull OAuthAuthorizationResult> beginAuthorizationResultFor(@NonNull OAuthAuthorizationServer server,
			@NonNull Request request, @NonNull String browserBinding) {
		requireNonNull(server); requireNonNull(request); requireNonNull(browserBinding);
		if (Boolean.TRUE.equals(request.isContentTooLarge())) return SokletRequestResult.fromTooLarge();
		return SokletRequestResult.fromResult(server.beginAuthorizationResult(request.getHttpMethod().name(), request.getRawQuery().orElse(null),
				SokletOAuth.bodyBytesFor(request), headersFor(request), browserBinding));
	}

	/**
	 * Handles unchanged token form bytes and every materialized header occurrence.
	 * @param server configured issuer
	 * @param request request on the configured token route
	 * @return an oversized transport outcome or core's committed response or rejection
	 * @throws NullPointerException if a required argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull SokletRequestResult<@NonNull OAuthTokenResult> tokenResultFor(@NonNull OAuthAuthorizationServer server, @NonNull Request request) {
		requireNonNull(server); requireNonNull(request);
		if (Boolean.TRUE.equals(request.isContentTooLarge())) return SokletRequestResult.fromTooLarge();
		return SokletRequestResult.fromResult(server.tokenResult(request.getHttpMethod().name(), request.getRawQuery().orElse(null),
				SokletOAuth.bodyBytesFor(request), headersFor(request)));
	}

	/**
	 * Handles raw revocation input; optional endpoint configuration remains a core precondition.
	 * @param server configured issuer
	 * @param request request on the configured revocation route
	 * @return an oversized transport outcome or core's committed response or rejection
	 * @throws NullPointerException if a required argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull SokletRequestResult<@NonNull OAuthRevocationResult> revocationResultFor(@NonNull OAuthAuthorizationServer server, @NonNull Request request) {
		requireNonNull(server); requireNonNull(request);
		if (Boolean.TRUE.equals(request.isContentTooLarge())) return SokletRequestResult.fromTooLarge();
		return SokletRequestResult.fromResult(server.revokeResult(request.getHttpMethod().name(), request.getRawQuery().orElse(null),
				SokletOAuth.bodyBytesFor(request), headersFor(request)));
	}

	/**
	 * Handles raw introspection input without selecting caller/resource authorization in the adapter.
	 * @param server configured issuer
	 * @param request request on the configured introspection route
	 * @return an oversized transport outcome or core's committed response or rejection
	 * @throws NullPointerException if a required argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull SokletRequestResult<@NonNull OAuthIntrospectionResult> introspectionResultFor(@NonNull OAuthAuthorizationServer server, @NonNull Request request) {
		requireNonNull(server); requireNonNull(request);
		if (Boolean.TRUE.equals(request.isContentTooLarge())) return SokletRequestResult.fromTooLarge();
		return SokletRequestResult.fromResult(server.introspectionResult(request.getHttpMethod().name(), request.getRawQuery().orElse(null),
				SokletOAuth.bodyBytesFor(request), headersFor(request)));
	}

	/**
	 * Emits the exact prepared body, headers, status and optional credential-bearing Location without JSON
	 * marshalling or redirect regeneration. Keep this response out of diagnostics; add app cookies at the edge.
	 * @param response restricted core response, possibly containing credentials or personal data
	 * @return exact-byte Soklet response
	 * @throws NullPointerException if response is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull MarshaledResponse responseFor(@NonNull OAuthServerResponse response) {
		requireNonNull(response);
		Optional<String> location = response.getLocationWithCredentials().map(SokletOAuth::redirectLocation);
		Map<String, List<String>> headers = new LinkedHashMap<>();
		response.getHeaders().forEach((name, values) -> headers.put(name, List.copyOf(values)));
		location.ifPresent(value -> headers.put("Location", List.of(value)));
		return MarshaledResponse.withStatusCode(response.getStatusCode()).headers(headers)
				.body(response.toHttpBodyWithCredentials()).build();
	}

	/** Lazy read-only views let core check occurrence/byte bounds before copying hostile header collections. */
	private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headersFor(@NonNull Request request) {
		Map<String, List<String>> fields = request.getHeaders();
		return new AbstractMap<>() {
			@Override public @NonNull Set<Map.@NonNull Entry<@NonNull String, @NonNull List<@NonNull String>>> entrySet() {
				return new AbstractSet<>() {
					@Override public int size() { return fields.size(); }
					@Override public @NonNull Iterator<Map.@NonNull Entry<@NonNull String, @NonNull List<@NonNull String>>> iterator() {
						Iterator<Map.Entry<String, List<String>>> entries = fields.entrySet().iterator();
						return new Iterator<>() {
							@Override public boolean hasNext() { return entries.hasNext(); }
							@Override public Map.@NonNull Entry<@NonNull String, @NonNull List<@NonNull String>> next() {
								Map.Entry<String, List<String>> field = entries.next();
								List<String> values = field.getValue();
								List<String> view = new AbstractList<>() {
									@Override public int size() { return values.size(); }
									@Override public @NonNull String get(int index) {
										if (index < 0 || index >= values.size()) throw new IndexOutOfBoundsException();
										Iterator<String> iterator = values.iterator();
										for (int i = 0; i < index; i++) iterator.next();
										return iterator.next();
									}
								};
								return new SimpleImmutableEntry<>(field.getKey(), view);
							}
							};
						}
					};
				}
			};
	}
}
