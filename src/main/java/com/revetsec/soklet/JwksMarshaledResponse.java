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
import com.revetsec.jose.JwksPublisher;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Publishes standalone public JSON Web Key Sets as prepared Soklet responses. The core publisher's exact bytes,
 * strong entity tag and prepared content length are retained. Soklet's default marshaler supports this variant,
 * including HEAD. Applications choose the route and its keys; no OAuth authorization server is required.
 * For a typed body and application-owned JSON serialization, use {@link JwksResponse} instead.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class JwksMarshaledResponse {

	private JwksMarshaledResponse() {}

	/**
	 * Prepares a standalone JWKS response using every {@code If-None-Match} occurrence.
	 * HEAD responses are bodyless and retain the core publisher's GET representation length.
	 * @param publisher configured public-key publisher
	 * @param request request on the application's JWKS route
	 * @return prepared status, headers and exact body bytes in a Soklet response
	 * @throws NullPointerException if a required argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull MarshaledResponse from(@NonNull JwksPublisher publisher, @NonNull Request request) {
		requireNonNull(publisher);
		requireNonNull(request);
		return from(publisher.responseFor(request.getHttpMethod().name(), JwksRequestHeaders.ifNoneMatchFor(request)));
	}

	/**
	 * Adapts a prepared core response without JSON marshalling or header regeneration.
	 * A prepared HEAD or not-modified response has no body; its headers are retained unchanged.
	 *
	 * @param response prepared standalone JWKS response
	 * @return exact-byte Soklet response
	 * @throws NullPointerException if response is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull MarshaledResponse from(com.revetsec.jose.@NonNull JwksResponse response) {
		requireNonNull(response);
		MarshaledResponse.Builder builder = MarshaledResponse.withStatusCode(response.getStatusCode()).headers(response.getHeaders());
		byte[] body = response.toHttpBody();
		if (body.length != 0)
			builder.body(body);
		return builder.build();
	}
}
