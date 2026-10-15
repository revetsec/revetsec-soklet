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
import com.revetsec.oauth.BearerTokenResult;
import com.google.errorprone.annotations.CheckReturnValue;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;

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
	 * Parses all materialized Authorization values as an absent, unverified present or malformed result.
	 * Every materialized header value is retained, including identical duplicates and differently cased field names.
	 * Query, body and cookies are never bearer transports. Core owns the credential grammar and size limit.
	 *
	 * @param request the resource request
	 * @return the raw-header parsing outcome
	 * @throws NullPointerException if request is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull BearerTokenResult bearerTokenResultFor(@NonNull Request request) {
		return BearerToken.fromAuthorizationHeaderValuesResult(SokletOAuth.collectHeaderValues(request, "Authorization"));
	}

}
