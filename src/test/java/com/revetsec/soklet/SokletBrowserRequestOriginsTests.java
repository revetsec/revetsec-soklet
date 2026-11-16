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

import com.revetsec.BrowserRequestOriginPolicy;
import com.revetsec.BrowserRequestOriginResult;
import com.soklet.HttpMethod;
import com.soklet.Request;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class SokletBrowserRequestOriginsTests {
    private static final BrowserRequestOriginPolicy POLICY = BrowserRequestOriginPolicy
            .withAllowedOrigins(Set.of(URI.create("https://app.example.com"))).build();

    @Test
    void extractsMethodAndEveryMaterializedHeaderValue() {
        Request allowed = Request.withRawUrl(HttpMethod.POST, "/action").headers(Map.of(
                "Sec-Fetch-Site", List.of("same-origin"), "Origin", List.of("null"))).build();
        assertEquals(BrowserRequestOriginResult.Basis.SAME_ORIGIN,
                assertInstanceOf(BrowserRequestOriginResult.Allowed.class,
                        SokletBrowserRequestOrigins.browserRequestOriginResultFor(POLICY, allowed)).getBasis());

        Request duplicate = Request.withRawUrl(HttpMethod.POST, "/action")
                .headers(Map.of("Origin", List.of("https://app.example.com", "https://app.example.com"))).build();
        assertEquals(BrowserRequestOriginResult.Reason.MALFORMED,
                assertInstanceOf(BrowserRequestOriginResult.Rejected.class,
                        SokletBrowserRequestOrigins.browserRequestOriginResultFor(POLICY, duplicate)).getReason());
    }
}
