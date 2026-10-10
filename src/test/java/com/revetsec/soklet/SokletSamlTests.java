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

import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlRedirectBindingParseResult;
import com.revetsec.saml.SamlAuthenticationRequestResult;
import com.revetsec.saml.SamlIdentityProvider;
import com.revetsec.saml.SamlServiceProvider;
import com.revetsec.saml.InMemorySamlReplayCache;
import com.soklet.HttpMethod;
import com.soklet.Request;
import com.soklet.Response;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class SokletSamlTests {
    @Test
    void postPassesExactBodyAndDuplicateHeaderValuesToCore() {
        byte[] body = "SAMLResponse=PGEvPg%3D%3D&RelayState=a%2Bb"
                .getBytes(StandardCharsets.US_ASCII);
        Request request = Request.withRawUrl(HttpMethod.POST, "/acs")
                .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded")))
                .body(body).build();
        var parsed = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SokletSaml.postBindingResultFor(request));
        assertEquals("a+b", parsed.getMessage().getRelayState().orElseThrow());

        Request duplicated = Request.withRawUrl(HttpMethod.POST, "/acs")
                .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded",
                        "application/x-www-form-urlencoded"))).body(body).build();
        assertEquals(SamlPostBindingParseResult.Reason.CONTENT_TYPE,
                assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                        SokletSaml.postBindingResultFor(duplicated)).getReason());
    }

    @Test
    void redirectUsesRawQueryAndRejectsMethodMismatch() {
        Request request = Request.fromRawUrl(HttpMethod.GET,
                "/slo?SAMLRequest=not-base64&SigAlg=x&Signature=y");
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SokletSaml.redirectBindingResultFor(request));
        assertThrows(IllegalArgumentException.class,
                () -> SokletSaml.postBindingResultFor(request));
    }

    @Test
    void outboundRedirectUsesCorePreparedRequestAndNoStore() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-10-10T00:00:00Z"), ZoneOffset.UTC);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/")
                .connectionId("local-test")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(generator.generateKeyPair().getPublic())).build();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 8)).clock(clock).build();
        SamlAuthenticationRequestResult.Prepared prepared = assertInstanceOf(
                SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp));
        Response response = SokletSaml.authenticationRedirect(prepared, Set.of());
        assertEquals(302, response.getStatusCode());
        assertEquals(List.of("no-store"), response.getHeaders().get("Cache-Control"));
        assertEquals(List.of(prepared.getRedirectUri().toString()), response.getHeaders().get("Location"));
    }
}
