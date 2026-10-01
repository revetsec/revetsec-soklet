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

import com.revetsec.oauth.BearerToken;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.Optional;

/**
 * Raw Authorization-header transport for Soklet resource servers. Parsing a bearer credential grants no identity
 * or permission; the application validates it through core and makes its own scope and object decisions.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class SokletBearer {

	private SokletBearer() {
		// Non-instantiable
	}

	/**
	 * Parses every materialized Authorization value, collecting field names case-insensitively without trimming or
	 * splitting their contents. Only absent headers return empty. Query, body and cookies are never credential
	 * transports here. All grammar and credential-size decisions remain in Revetsec core.
	 * <p>
	 * Soklet's sets cannot reveal identical physical duplicate values, including fields with differently cased
	 * names. A trusted edge must reject those duplicates; this helper cannot recover multiplicity already discarded.
	 * Distinct materialized values remain ambiguous and are rejected by core.
	 *
	 * @param request the resource request
	 * @return an absent or unverified bearer credential
	 * @throws com.revetsec.oauth.AccessTokenValidationException if core rejects the header input
	 * @throws NullPointerException if request is null
	 * @since 1.0.0
	 */
	public static @NonNull Optional<@NonNull BearerToken> bearerTokenFor(@NonNull Request request) {
		return BearerToken.fromAuthorizationHeaderValues(SokletOAuth.collectHeaderValues(request, "Authorization"));
	}
}
