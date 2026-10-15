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
import com.revetsec.jose.PublishedJwk;
import com.revetsec.json.JsonObject;
import com.soklet.Request;
import com.soklet.Response;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Prepares logical public JSON Web Key Set responses on application-owned Soklet routes.
 * Applications choose the route and its key set; no OAuth authorization server is required.
 * {@link #from(JwksPublisher, Request)} returns a Soklet response with a typed {@link Body} for
 * application-owned JSON serialization, weak entity tags and no prepared content length.
 * For prepared bytes and Soklet's default marshaler, use {@link JwksMarshaledResponse} instead.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class JwksResponse {

	private JwksResponse() {}

	/**
	 * Prepares a logical JWKS response for application-owned JSON serialization.
	 * A successful GET has an immutable {@link Body}; HEAD, not-modified responses and rejections have no body.
	 * Entity tags are weak document fingerprints. No content length is supplied, because the application's
	 * marshaler chooses the encoded representation. Other prepared headers are retained.
	 * The default Soklet marshaler uses diagnostic {@code toString()} output for arbitrary objects; applications
	 * must configure their JSON marshaler to serialize {@link Body#toJsonObject()} or {@link Body#toJson()}.
	 *
	 * @param publisher configured public-key publisher
	 * @param request request on the application's JWKS route
	 * @return logical response whose body is ready for application serialization or structural assertions
	 * @throws NullPointerException if a required argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull Response from(@NonNull JwksPublisher publisher, @NonNull Request request) {
		requireNonNull(publisher);
		requireNonNull(request);
		com.revetsec.jose.JwksResponse prepared = publisher.responseFor(request.getHttpMethod().name(),
				JwksRequestHeaders.ifNoneMatchFor(request));
		Map<String, List<String>> headers = new LinkedHashMap<>(prepared.getHeaders());
		headers.remove("Content-Length");
		headers.computeIfPresent("ETag", (name, values) -> values.stream().map(value -> "W/" + value).toList());
		Response.Builder builder = Response.withStatusCode(prepared.getStatusCode()).headers(headers);
		prepared.getDocument().ifPresent(document -> builder.body(new Body(publisher.getKeys(), document)));
		return builder.build();
	}

	/**
	 * Immutable public JWKS body for application serialization and structural assertions.
	 * Its keys and JSON tree come from one publisher snapshot. JSON emission is explicit; diagnostics redact
	 * key identifiers, public parameters and certificate material.
	 *
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Body {
		private final @NonNull List<@NonNull PublishedJwk> keys;
		private final @NonNull JsonObject document;

		private Body(@NonNull List<@NonNull PublishedJwk> keys, @NonNull JsonObject document) {
			this.keys = List.copyOf(keys);
			this.document = requireNonNull(document);
		}

		/**
		 * Returns the immutable public keys in publication order.
		 * @return the public key snapshot
		 * @since 1.0.0
		 */
		public @NonNull List<@NonNull PublishedJwk> getKeys() {
			return this.keys;
		}

		/**
		 * Returns the immutable public JWKS document, including certificate metadata.
		 * @return the structured document for explicit serialization or inspection
		 * @since 1.0.0
		 */
		public @NonNull JsonObject toJsonObject() {
			return this.document;
		}

		/**
		 * Serializes the complete public JWKS document as JSON text.
		 * @return the JSON text, including configured identifiers and certificate metadata
		 * @since 1.0.0
		 */
		public @NonNull String toJson() {
			return this.document.toJson();
		}

		/**
		 * Describes the body without key or certificate contents.
		 * @return a redacted description
		 * @since 1.0.0
		 */
		@Override
		public @NonNull String toString() {
			return "JwksResponse.Body{keyCount=" + this.keys.size() + "}";
		}
	}

}
