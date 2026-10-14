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
import com.revetsec.scim.ScimAttributeSelectionResult;
import com.revetsec.scim.ScimIfMatchResult;
import com.revetsec.scim.ScimIfNoneMatchResult;
import com.revetsec.scim.ScimQueryParseResult;
import com.revetsec.scim.ScimPatchParseResult;
import com.revetsec.scim.ScimResource;
import com.revetsec.scim.ScimResourceParseResult;
import com.revetsec.scim.ScimResourceType;
import com.revetsec.scim.ScimResponse;
import com.revetsec.scim.ScimServiceProvider;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.AbstractList;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Thin SCIM transport helpers for application-routed Soklet endpoints. Applications select the authenticated caller,
 * tenant, resource type and transaction, and enforce route methods. Each parser invokes one core operation using the
 * unchanged materialized raw query, body and physical header occurrences.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class SokletScim {
    private SokletScim() { }

    /** Parses the untouched resource-list query.
     * @param provider the application's configured service provider
     * @param resourceType the application-selected registered resource type
     * @param request the materialized routed request
     * @return the core query result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimQueryParseResult queryResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType resourceType, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(request);
        return provider.parseQueryResult(resourceType, request.getRawQuery().orElse(""));
    }

    /** Parses unchanged SearchRequest bytes and original Content-Type occurrences.
     * @param provider the application's configured service provider
     * @param resourceType the application-selected registered resource type
     * @param request the materialized routed request
     * @return the core query result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimQueryParseResult searchRequestResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType resourceType, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(request);
        return provider.parseSearchRequestResult(resourceType, headerValues(request, "Content-Type"),
                request.getBody().orElseGet(() -> new byte[0]));
    }

    /** Parses unchanged create-resource bytes and original Content-Type occurrences.
     * @param provider the application's configured service provider
     * @param resourceType the application-selected registered resource type
     * @param request the materialized routed request
     * @return the core candidate resource result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimResourceParseResult resourceResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType resourceType, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(request);
        return provider.parseResourceResult(resourceType, headerValues(request, "Content-Type"),
                request.getBody().orElseGet(() -> new byte[0]));
    }

    /** Parses unchanged replacement bytes against the application-selected current resource.
     * @param provider the application's configured service provider
     * @param resourceType the application-selected registered resource type
     * @param current the authoritative current resource used by the application transaction
     * @param request the materialized routed request
     * @return the core replacement candidate result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimResourceParseResult replacementResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType resourceType, @NonNull ScimResource current, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(current); requireNonNull(request);
        return provider.parseReplacementResult(resourceType, current, headerValues(request, "Content-Type"),
                request.getBody().orElseGet(() -> new byte[0]));
    }

    /** Parses unchanged PatchOp bytes and original Content-Type occurrences.
     * @param provider the application's configured service provider
     * @param resourceType the application-selected registered resource type
     * @param request the materialized routed request
     * @return the core schema-bound PATCH request result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimPatchParseResult patchRequestResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType resourceType, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(request);
        return provider.parsePatchRequestResult(resourceType, headerValues(request, "Content-Type"),
                request.getBody().orElseGet(() -> new byte[0]));
    }

    /** Parses resource-response selection from the unchanged raw query.
     * @param provider the application's configured service provider
     * @param resourceType the application-selected registered resource type
     * @param request the materialized routed request
     * @return the core attribute-selection result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimAttributeSelectionResult attributeSelectionResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResourceType resourceType, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(resourceType); requireNonNull(request);
        return provider.parseAttributeSelectionResult(resourceType, request.getRawQuery().orElse(""));
    }

    /** Checks every original If-Match occurrence against the same current resource used by the application write.
     * @param provider the application's configured service provider
     * @param current the authoritative current resource
     * @param request the materialized routed request
     * @return the core conditional result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimIfMatchResult ifMatchResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResource current, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(current); requireNonNull(request);
        return provider.checkIfMatchResult(headerValues(request, "If-Match"), current);
    }

    /** Checks every original If-None-Match occurrence for application-routed GET or HEAD handling.
     * @param provider the application's configured service provider
     * @param current the authoritative current resource
     * @param request the materialized routed request
     * @return the core conditional result
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull ScimIfNoneMatchResult ifNoneMatchResultFor(@NonNull ScimServiceProvider provider,
            @NonNull ScimResource current, @NonNull Request request) {
        requireNonNull(provider); requireNonNull(current); requireNonNull(request);
        return provider.checkIfNoneMatchResult(headerValues(request, "If-None-Match"), current);
    }

    /** Emits exactly the core-prepared status, header occurrences and body bytes, which may contain personal data.
     * @param response the restricted core-prepared response
     * @return the exact-byte Soklet response
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull MarshaledResponse responseFor(@NonNull ScimResponse response) {
        requireNonNull(response);
        MarshaledResponse.Builder builder = MarshaledResponse.withStatusCode(response.getStatusCode()).headers(response.getHeaders());
        byte[] bytes = response.toHttpBodyWithPersonalData();
        // Soklet requires no entity for 204/304; supplying even a zero-length entity is rejected at dispatch.
        if (bytes.length > 0) builder.body(bytes);
        return builder.build();
    }

    /** A bounded core parser can inspect occurrence counts before any hostile collection is copied or joined. */
    private static @NonNull List<@NonNull String> headerValues(@NonNull Request request, @NonNull String name) {
        return new HeaderValues(request.getHeaders(), name);
    }

    @ThreadSafe
    private static final class HeaderValues extends AbstractList<@NonNull String> {
        private final @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> fields;
        private final @NonNull String name;
        private HeaderValues(@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> fields, @NonNull String name) {
            this.fields = fields; this.name = name;
        }
        @Override public int size() {
            long count = 0;
            for (Map.Entry<String, List<String>> field : fields.entrySet()) if (sameName(name, field.getKey())) {
                count += field.getValue().size();
                if (count >= Integer.MAX_VALUE) return Integer.MAX_VALUE;
            }
            return (int) count;
        }
        @Override public @NonNull String get(int index) {
            if (index < 0) throw new IndexOutOfBoundsException();
            for (Map.Entry<String, List<String>> field : fields.entrySet()) if (sameName(name, field.getKey())) {
                List<String> values = field.getValue();
                if (index < values.size()) return values.get(index);
                index -= values.size();
            }
            throw new IndexOutOfBoundsException();
        }
    }

    private static boolean sameName(@NonNull String expected, @NonNull String actual) {
        if (expected.length() != actual.length()) return false;
        for (int index = 0; index < expected.length(); ++index) {
            char left = expected.charAt(index), right = actual.charAt(index);
            if (left >= 'A' && left <= 'Z') left = (char) (left + 32);
            if (right >= 'A' && right <= 'Z') right = (char) (right + 32);
            if (left != right) return false;
        }
        return true;
    }
}
