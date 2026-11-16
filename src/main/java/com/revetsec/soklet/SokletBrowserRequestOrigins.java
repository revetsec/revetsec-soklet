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
import com.revetsec.BrowserRequestOriginPolicy;
import com.revetsec.BrowserRequestOriginResult;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Soklet request extraction for Revetsec's browser request-origin policy.
 * <p>
 * The helper installs no filter and changes no application state. Soklet exposes materialized header values; if a
 * trusted HTTP edge collapses physically identical duplicate fields before Soklet receives them, that edge must
 * reject the duplicates itself.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class SokletBrowserRequestOrigins {
    private SokletBrowserRequestOrigins() { }

    /**
     * Checks the request method and all materialized {@code Sec-Fetch-Site} and {@code Origin} values.
     *
     * @param policy configured core policy
     * @param request routed request
     * @return closed request-origin outcome
     * @throws NullPointerException if an argument is {@code null}
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull BrowserRequestOriginResult browserRequestOriginResultFor(
            @NonNull BrowserRequestOriginPolicy policy, @NonNull Request request) {
        requireNonNull(request);
        return requireNonNull(policy).checkResult(request.getHttpMethod().name(),
                SokletOAuth.collectHeaderValues(request, "Sec-Fetch-Site"),
                SokletOAuth.collectHeaderValues(request, "Origin"));
    }
}
