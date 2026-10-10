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
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlPostForm;
import com.revetsec.saml.SamlAuthenticationRequestResult;
import com.revetsec.saml.SamlLogoutRedirectResult;
import com.revetsec.saml.SamlLogoutResponseRedirectResult;
import com.revetsec.saml.SamlRedirectBindingMessage;
import com.revetsec.saml.SamlRedirectBindingParseResult;
import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import com.soklet.Response;
import com.soklet.ResponseCookie;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Thin SAML transport helpers for application-routed Soklet endpoints. Core performs all SAML
 * parsing, signature, pending, audience and replay decisions. The application owns cookies,
 * IdP selection, local sessions and response policy.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class SokletSaml {
    private SokletSaml() { }

    /**
     * Parses a raw ACS POST body and every materialized Content-Type value, preserving duplicates.
     *
     * @param request application-routed ACS request
     * @return core's untrusted POST-binding parse result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull SamlPostBindingParseResult postBindingResultFor(@NonNull Request request) {
        requireNonNull(request);
        if (request.getHttpMethod() != HttpMethod.POST)
            throw new IllegalArgumentException("SAML ACS route requires POST");
        return SamlPostBindingMessage.fromFormBodyResult(
                request.getBody().orElseGet(() -> new byte[0]),
                SokletOAuth.collectHeaderValues(request, "Content-Type"),
                request.getRawQuery().orElse(null));
    }

    /**
     * Parses the untouched query string for HTTP-Redirect logout signature verification.
     *
     * @param request application-routed logout GET request
     * @return core's untrusted Redirect-binding parse result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull SamlRedirectBindingParseResult redirectBindingResultFor(@NonNull Request request) {
        requireNonNull(request);
        if (request.getHttpMethod() != HttpMethod.GET)
            return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        return SamlRedirectBindingMessage.fromRawQueryResult(request.getRawQuery().orElse(""));
    }

    /**
     * Sends a core-prepared authentication Redirect with no-store and no-referrer headers.
     *
     * @param prepared core-prepared authentication request
     * @param cookies application-selected response cookies
     * @return Soklet redirect response
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull Response authenticationRedirect(
            SamlAuthenticationRequestResult.@NonNull Prepared prepared,
            @NonNull Set<@NonNull ResponseCookie> cookies) {
        return preparedRedirect(requireNonNull(prepared).getRedirectUri(), cookies);
    }

    /**
     * Sends a core-prepared SP logout Redirect.
     *
     * @param prepared core-prepared logout request
     * @param cookies application-selected response cookies
     * @return Soklet redirect response
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull Response logoutRedirect(SamlLogoutRedirectResult.@NonNull Prepared prepared,
            @NonNull Set<@NonNull ResponseCookie> cookies) {
        return preparedRedirect(requireNonNull(prepared).getRedirectUri(), cookies);
    }

    /**
     * Sends a core-prepared answer to an IdP logout request.
     *
     * @param prepared core-prepared logout response
     * @param cookies application-selected response cookies
     * @return Soklet redirect response
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull Response logoutResponseRedirect(
            SamlLogoutResponseRedirectResult.@NonNull Prepared prepared,
            @NonNull Set<@NonNull ResponseCookie> cookies) {
        return preparedRedirect(requireNonNull(prepared).getRedirectUri(), cookies);
    }

    private static @NonNull Response preparedRedirect(@NonNull URI destination,
            @NonNull Set<@NonNull ResponseCookie> cookies) {
        if (!"https".equalsIgnoreCase(requireNonNull(destination).getScheme()))
            throw new IllegalArgumentException("SAML Redirect requires HTTPS");
        return SokletOAuth.redirect(destination, requireNonNull(cookies));
    }

    /**
     * Sends a core-prepared POST form with no-store headers. The application sets a CSP header
     * appropriate to its page and chooses the pending cookie before calling this helper.
     *
     * @param form core-prepared POST AuthnRequest form
     * @param cspNonce application-generated nonce, or null for manual submission
     * @return exact UTF-8 HTML response
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull MarshaledResponse postFormResponse(@NonNull SamlPostForm form,
            @Nullable String cspNonce) {
        requireNonNull(form);
        Map<String, List<String>> headers = new HashMap<>();
        form.getHeaders().forEach((name, value) -> headers.put(name, List.of(value)));
        return MarshaledResponse.withStatusCode(200).headers(Map.copyOf(headers))
                .body(form.toHtml(cspNonce).getBytes(StandardCharsets.UTF_8)).build();
    }
}
