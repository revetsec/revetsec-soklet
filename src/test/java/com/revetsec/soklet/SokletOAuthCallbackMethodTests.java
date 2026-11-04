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

import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.OAuthException;
import com.soklet.HttpMethod;
import com.soklet.InstanceProvider;
import com.soklet.Request;
import com.soklet.ResourceMethodResolver;
import com.soklet.Response;
import com.soklet.SimulatorConfig;
import com.soklet.SokletSimulator;
import com.soklet.annotation.GET;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Unsupported transport methods must never produce a callback for transaction completion. */
final class SokletOAuthCallbackMethodTests {
    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> unsupportedMethodsRejectRegardlessOfDiscardedBody() {
        return Arrays.stream(HttpMethod.values()).filter(method -> method != HttpMethod.GET && method != HttpMethod.POST)
                .flatMap(method -> Stream.of(false, true).map(discarded -> DynamicTest.dynamicTest(method+" / discarded="+discarded, () -> {
                    Request request = Request.withRawUrl(method, "/callback?code=synthetic-code&state=synthetic-state")
                            .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded")))
                            .body("code=body-code&state=body-state".getBytes(StandardCharsets.US_ASCII))
                            .contentTooLarge(discarded).build();
                    var rejected = assertInstanceOf(SokletOAuthCallbackResult.Rejected.class,
                            assertDoesNotThrow(() -> SokletOAuth.authorizationResponseResultFor(request)));
                    assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, rejected.getReason());
                    assertFalse(rejected.toString().contains("synthetic-code"));
                    assertFalse(rejected.toString().contains("synthetic-state"));
                })));
    }

    @Test void supportedGetRetainsRawQueryMode() {
        var parsed = assertInstanceOf(SokletOAuthCallbackResult.Succeeded.class,
                SokletOAuth.authorizationResponseResultFor(Request.fromRawUrl(HttpMethod.GET,
                        "/callback?code=a%2Bb%252Fc&state=x+y"))).getResponse();
        assertEquals("a+b%2Fc", parsed.getCode().orElseThrow());
        assertEquals("x y", parsed.getState().orElseThrow());
        assertEquals(AuthorizationRequestOptions.ResponseMode.QUERY, parsed.getResponseMode());
    }

    @Test void supportedPostRetainsBodyAndMode() {
        var parsed = assertInstanceOf(SokletOAuthCallbackResult.Succeeded.class,
                SokletOAuth.authorizationResponseResultFor(Request.withRawUrl(HttpMethod.POST, "/callback?tenant=one")
                        .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded")))
                        .body("code=a%2Bb&state=x+y".getBytes(StandardCharsets.US_ASCII)).build())).getResponse();
        assertEquals("a+b", parsed.getCode().orElseThrow());
        assertEquals("x y", parsed.getState().orElseThrow());
        assertEquals(List.of("one"), parsed.getParameters().get("tenant"));
        assertEquals(AuthorizationRequestOptions.ResponseMode.FORM_POST, parsed.getResponseMode());
    }

    @Test void supportedDiscardedBodiesRemainTooLarge() {
        for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.POST))
            assertInstanceOf(SokletOAuthCallbackResult.TooLarge.class, SokletOAuth.authorizationResponseResultFor(
                    Request.withRawUrl(method, "/callback?code=ignored").contentTooLarge(true).build()));
    }

    @SuppressWarnings("NullAway") // Intentionally violates the required-argument contract.
    @Test void nullRequestRemainsProgrammerMisuse() {
        assertThrows(NullPointerException.class, () -> SokletOAuth.authorizationResponseResultFor(null));
    }

    @Test void headFallbackToGetRouteRejectsWithoutOfferingCallbackToApplication() throws Exception {
        CallbackResource resource = new CallbackResource();
        InstanceProvider provider = new InstanceProvider() {
            @Override public <T> @NonNull T provide(@NonNull Class<@NonNull T> type) { return type.cast(resource); }
        };
        SimulatorConfig config = SimulatorConfig.builder().httpServer()
                .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(CallbackResource.class)))
                .instanceProvider(provider).build();
        SokletSimulator.run(config, simulator -> {
            var head = simulator.performHttpRequest(Request.fromRawUrl(HttpMethod.HEAD, "/callback?code=synthetic&state=pending"))
                    .getMarshaledResponse();
            assertEquals(405, head.getStatusCode());
            assertEquals(1, resource.visits);
            assertEquals(0, resource.callbacksOffered);
            assertEquals(200, simulator.performHttpRequest(Request.fromRawUrl(HttpMethod.GET,
                    "/callback?code=synthetic&state=pending")).getMarshaledResponse().getStatusCode());
            assertEquals(2, resource.visits);
            assertEquals(1, resource.callbacksOffered);
        });
    }

    public static final class CallbackResource {
        private int visits;
        private int callbacksOffered;
        @GET("/callback")
        public @NonNull Response callback(@NonNull Request request) {
            this.visits++;
            var parsed = SokletOAuth.authorizationResponseResultFor(request);
            if (parsed instanceof SokletOAuthCallbackResult.Rejected)
                return Response.withStatusCode(405).headers(Map.of("Allow", List.of("GET, POST"))).build();
            if (!(parsed instanceof SokletOAuthCallbackResult.Succeeded)) return Response.withStatusCode(413).build();
            this.callbacksOffered++;
            return Response.withStatusCode(200).build();
        }
    }
}
