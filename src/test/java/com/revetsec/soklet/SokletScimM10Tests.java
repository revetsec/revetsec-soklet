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

import com.revetsec.scim.*;
import com.revetsec.scim.ScimObserver.Operation;
import com.revetsec.scim.ScimObserver.Outcome;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
import com.soklet.Request;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Independent M10 transport assertions against materialized Soklet requests and bounded core responses. */
final class SokletScimM10Tests {
    private static final @NonNull ScimResourceType USER = ScimResourceType.userInstance();
    private static final @NonNull String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";

    @Test void queryUsesRawMultiplicityAndNumericNormalizationRatherThanDecodedQueryMaps() {
        ScimServiceProvider provider = provider();
        Request request = Request.fromRawUrl(HttpMethod.GET, "/scim/Users?count=-1&startIndex=0&attributes=userName");
        ScimQuery query = assertInstanceOf(ScimQueryParseResult.Succeeded.class, SokletScim.queryResultFor(provider, USER, request)).getQuery();
        assertEquals(0, query.getCount()); assertEquals(-1L, query.getRequestedCount().orElseThrow());
        assertEquals(1L, query.getStartIndex().orElseThrow()); assertSame(USER, query.getResourceType());
        assertTrue(query.getAttributeSelection().isExplicit());
        Request repeated = Request.fromRawUrl(HttpMethod.GET, "/scim/Users?count=1&count=2");
        assertInstanceOf(ScimQueryParseResult.Rejected.class, SokletScim.queryResultFor(provider, USER, repeated));
        Request encoded = Request.fromRawUrl(HttpMethod.GET, "/scim/Users?count=%252D1");
        assertInstanceOf(ScimQueryParseResult.Rejected.class, SokletScim.queryResultFor(provider, USER, encoded));
    }

    @Test void selectionPreservesRawEncodingAndRejectsAmbiguousProjectionInsteadOfChoosingOne() {
        ScimServiceProvider provider = provider();
        Request valid = Request.fromRawUrl(HttpMethod.GET, "/scim/Users/u?attributes=userName%2CdisplayName");
        ScimAttributeSelection selection = assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                SokletScim.attributeSelectionResultFor(provider, USER, valid)).getAttributeSelection();
        assertTrue(selection.isExplicit()); assertEquals(2, selection.getIncludedAttributes().size());
        Request both = Request.fromRawUrl(HttpMethod.GET, "/scim/Users/u?attributes=userName&excludedAttributes=displayName");
        assertInstanceOf(ScimAttributeSelectionResult.Rejected.class, SokletScim.attributeSelectionResultFor(provider, USER, both));
    }

    @Test void createPassesExactJsonBytesAndTreatsMissingBodyAndDuplicateContentTypeAsCoreRejections() throws ReflectiveOperationException {
        ScimServiceProvider provider = provider();
        byte[] bytes = ("{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"a+b%20c\"}").getBytes(StandardCharsets.UTF_8);
        Request request = Request.withRawUrl(HttpMethod.POST, "/scim/Users").headers(Map.of("cOnTeNt-TyPe", List.of("application/scim+json"))).body(bytes).build();
        ScimResource parsed = assertInstanceOf(ScimResourceParseResult.Succeeded.class, SokletScim.resourceResultFor(provider, USER, request)).getResource();
        assertEquals("a+b%20c", ScimUser.fromResource(parsed).getUserName());
        assertArrayEquals(bytes, request.getBody().orElseThrow());
        Request repeated = SokletRawInputTests.fromPhysicalHeaders(HttpMethod.POST, "/scim/Users",
                List.of(Map.entry("Content-Type", "application/json"), Map.entry("CONTENT-TYPE", "application/json")), bytes);
        assertSame(ScimError.unsupportedMediaTypeInstance(), assertInstanceOf(ScimResourceParseResult.Rejected.class,
                SokletScim.resourceResultFor(provider, USER, repeated)).getError());
        Request missing = Request.withRawUrl(HttpMethod.POST, "/scim/Users").headers(Map.of("Content-Type", List.of("application/json"))).build();
        assertInstanceOf(ScimResourceParseResult.Rejected.class, SokletScim.resourceResultFor(provider, USER, missing));
    }

    @Test void malformedUtf8AndDuplicateJsonMembersReachStrictCoreParsing() {
        ScimServiceProvider provider = provider();
        Request invalidUtf8 = Request.withRawUrl(HttpMethod.POST, "/scim/Users").headers(Map.of("Content-Type", List.of("application/json")))
                .body(new byte[]{'{', '"', 'x', '"', ':', '"', (byte) 0xc3, (byte) 0x28, '"', '}'}).build();
        assertInstanceOf(ScimResourceParseResult.Rejected.class, SokletScim.resourceResultFor(provider, USER, invalidUtf8));
        Request duplicate = json(HttpMethod.POST, "/scim/Users", "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"a\",\"USERNAME\":\"b\"}");
        assertInstanceOf(ScimResourceParseResult.Rejected.class, SokletScim.resourceResultFor(provider, USER, duplicate));
    }

    @Test void searchAndReplacementUseTheirOriginalBodiesAndTheAuthoritativeCurrentResource() {
        ScimServiceProvider provider = provider();
        Request search = json(HttpMethod.POST, "/scim/Users/.search", "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],\"count\":2}");
        assertEquals(2, assertInstanceOf(ScimQueryParseResult.Succeeded.class,
                SokletScim.searchRequestResultFor(provider, USER, search)).getQuery().getCount());
        ScimResource current = resource();
        Request replacement = json(HttpMethod.PUT, "/scim/Users/u", "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"new-name\"}");
        ScimResource updated = assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                SokletScim.replacementResultFor(provider, USER, current, replacement)).getResource();
        assertEquals("new-name", ScimUser.fromResource(updated).getUserName());
        assertEquals("u", updated.getId().orElseThrow());
        assertEquals("old-name", ScimUser.fromResource(current).getUserName());
    }

    @Test void conditionalsPreserveEveryPhysicalOccurrenceAndCoreWeakComparison() throws ReflectiveOperationException {
        ScimServiceProvider provider = provider(); ScimResource current = resource();
        Request match = SokletRawInputTests.fromPhysicalHeaders(HttpMethod.PUT, "/scim/Users/u",
                List.of(Map.entry("If-Match", "\"old\""), Map.entry("IF-MATCH", "\"v\"")), null);
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, SokletScim.ifMatchResultFor(provider, current, match));
        Request malformed = SokletRawInputTests.fromPhysicalHeaders(HttpMethod.PUT, "/scim/Users/u",
                List.of(Map.entry("If-Match", "*"), Map.entry("if-match", "\"v\"")), null);
        assertSame(ScimError.invalidSyntaxInstance(), assertInstanceOf(ScimIfMatchResult.Rejected.class,
                SokletScim.ifMatchResultFor(provider, current, malformed)).getError());
        Request read = Request.withRawUrl(HttpMethod.GET, "/scim/Users/u").headers(Map.of("If-None-Match", List.of("\"v\""))).build();
        assertInstanceOf(ScimIfNoneMatchResult.NotModified.class, SokletScim.ifNoneMatchResultFor(provider, current, read));
        Request stale = Request.withRawUrl(HttpMethod.PUT, "/scim/Users/u").headers(Map.of("If-Match", List.of("\"old\""))).build();
        assertEquals(412, assertInstanceOf(ScimIfMatchResult.Rejected.class, SokletScim.ifMatchResultFor(provider, current, stale)).getError().getStatusCode());
    }

    @Test void preparedResponsePassesExactStatusHeaderOccurrencesAndBytesForErrorsAndBodylessResponses() {
        ScimServiceProvider provider = provider();
        ScimResponse error = provider.errorResponse(ScimError.invalidValueInstance());
        ScimResponse modified = assertInstanceOf(ScimResponseResult.Prepared.class, provider.notModifiedResponseResult(resource())).getResponse();
        for (ScimResponse response : List.of(error, modified, provider.noContentResponse())) {
            MarshaledResponse emitted = SokletScim.responseFor(response);
            assertEquals(response.getStatusCode(), emitted.getStatusCode());
            assertArrayEquals(response.toHttpBodyWithPersonalData(), assertInstanceOf(MarshaledResponseBody.Bytes.class, emitted.getBody().orElseThrow()).getBytes());
            response.getHeaders().forEach((name, values) -> assertEquals(values, emitted.getHeaders().get(name)));
        }
    }

    @Test void aFramedBodyHelperInvokesExactlyOneCoreLifecycleOperation() {
        CountingObserver observer = new CountingObserver();
        ScimServiceProvider provider = ScimServiceProvider.builder().baseUri(URI.create("https://example.com/scim/"))
                .resourceTypes(List.of(USER)).observer(observer).build();
        Request request = json(HttpMethod.POST, "/scim/Users", "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"fixture\"}");
        assertInstanceOf(ScimResourceParseResult.Succeeded.class, SokletScim.resourceResultFor(provider, USER, request));
        assertEquals(1, observer.begins.get()); assertEquals(1, observer.ends.get());
        assertEquals(Operation.RESOURCE_CREATE, observer.operation.get());
        assertEquals(Outcome.SUCCEEDED, observer.outcome.get());
    }

    @Test @SuppressWarnings("NullAway") void requiredReferencesRejectNullAsProgrammingErrors() {
        ScimServiceProvider provider = provider(); Request request = Request.fromRawUrl(HttpMethod.GET, "/scim/Users");
        assertThrows(NullPointerException.class, () -> SokletScim.queryResultFor(null, USER, request));
        assertThrows(NullPointerException.class, () -> SokletScim.queryResultFor(provider, null, request));
        assertThrows(NullPointerException.class, () -> SokletScim.queryResultFor(provider, USER, null));
        assertThrows(NullPointerException.class, () -> SokletScim.replacementResultFor(provider, USER, null, request));
        assertThrows(NullPointerException.class, () -> SokletScim.responseFor(null));
    }

    private static @NonNull ScimServiceProvider provider() {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.com/scim/")).resourceTypes(List.of(USER)).build();
    }
    private static @NonNull ScimResource resource() {
        return ScimResource.withResourceType(USER).document(JsonObject.builder()
                .put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(USER_SCHEMA))))
                .put("id", "u").put("userName", "old-name").put("meta", JsonObject.builder().put("version", "W/\"v\"").build()).build()).build();
    }
    private static @NonNull Request json(@NonNull HttpMethod method, @NonNull String path, @NonNull String body) {
        return Request.withRawUrl(method, path).headers(Map.of("Content-Type", List.of("application/scim+json")))
                .body(body.getBytes(StandardCharsets.UTF_8)).build();
    }

    @ThreadSafe private static final class CountingObserver implements ScimObserver {
        private final @NonNull AtomicInteger begins = new AtomicInteger();
        private final @NonNull AtomicInteger ends = new AtomicInteger();
        private final @NonNull AtomicReference<@Nullable Operation> operation = new AtomicReference<>();
        private final @NonNull AtomicReference<@Nullable Outcome> outcome = new AtomicReference<>();
        @Override public void willProcess(@NonNull Operation kind) { begins.incrementAndGet(); operation.set(kind); }
        @Override public void didProcess(@NonNull Operation kind, @NonNull Outcome result) { ends.incrementAndGet(); operation.set(kind); outcome.set(result); }
    }
}
