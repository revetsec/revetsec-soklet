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
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlLogoutPostResult;
import com.revetsec.saml.SamlLogoutResponsePostResult;
import com.revetsec.saml.SamlLogoutRequestResult;
import com.revetsec.saml.SamlLogoutResult;
import com.revetsec.saml.SamlLogoutStatus;
import com.revetsec.saml.SamlRedirectBindingParseResult;
import com.revetsec.saml.SamlAuthenticationRequestResult;
import com.revetsec.saml.SamlIdentityProvider;
import com.revetsec.saml.SamlServiceProvider;
import com.revetsec.saml.InMemorySamlReplayCache;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
    void logoutPostPreservesKindRelayAndStrictRawTransportChecks() {
        String payload = "PGEvPg%3D%3D";
        for (String field : List.of("SAMLRequest", "SAMLResponse")) {
            byte[] body = (field + "=" + payload + "&RelayState=alpha%2Bbeta").getBytes(StandardCharsets.US_ASCII);
            Request request = Request.withRawUrl(HttpMethod.POST, "/logout?tenant=one")
                    .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded"))).body(body).build();
            SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                    SokletSaml.postLogoutBindingResultFor(request)).getMessage();
            assertEquals("SAMLRequest".equals(field) ? SamlPostBindingMessage.Kind.REQUEST
                    : SamlPostBindingMessage.Kind.RESPONSE, message.getKind());
            assertEquals("alpha+beta", message.getRelayState().orElseThrow());
            Request polluted = Request.withRawUrl(HttpMethod.POST, "/logout?RelayState=evil")
                    .headers(request.getHeaders()).body(body).build();
            assertEquals(SamlPostBindingParseResult.Reason.QUERY, assertInstanceOf(
                    SamlPostBindingParseResult.Rejected.class, SokletSaml.postLogoutBindingResultFor(polluted)).getReason());
            Request duplicated = Request.withRawUrl(HttpMethod.POST, "/logout")
                    .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded",
                            "application/x-www-form-urlencoded"))).body(body).build();
            assertEquals(SamlPostBindingParseResult.Reason.CONTENT_TYPE, assertInstanceOf(
                    SamlPostBindingParseResult.Rejected.class, SokletSaml.postLogoutBindingResultFor(duplicated)).getReason());
        }
        Request requestAtAcs = Request.withRawUrl(HttpMethod.POST, "/acs")
                .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded")))
                .body(("SAMLRequest=" + payload).getBytes(StandardCharsets.US_ASCII)).build();
        assertInstanceOf(SamlPostBindingParseResult.Rejected.class, SokletSaml.postBindingResultFor(requestAtAcs));
        assertThrows(IllegalArgumentException.class,
                () -> SokletSaml.postLogoutBindingResultFor(Request.fromRawUrl(HttpMethod.GET, "/logout")));
    }

    @Test
    void logoutFormsAndCallbacksUseCoreValidationAndReplayFence() throws Exception {
        SamlPostLogoutFixture fixture = new SamlPostLogoutFixture();
        SamlLogoutPostResult.Prepared begin = assertInstanceOf(SamlLogoutPostResult.Prepared.class,
                fixture.sp.beginPostLogoutResult(fixture.idp, fixture.session));
        String nonce = "abcdefghijklmnopqrstuvwxyz012345";
        MarshaledResponse outbound = SokletSaml.logoutPostFormResponse(begin, nonce);
        assertEquals(200, outbound.getStatusCode());
        assertEquals(List.of("no-store"), outbound.getHeaders().get("Cache-Control"));
        assertEquals(List.of("no-referrer"), outbound.getHeaders().get("Referrer-Policy"));
        assertArrayEquals(begin.getPostForm().toHtml(nonce).getBytes(StandardCharsets.UTF_8),
                assertInstanceOf(MarshaledResponseBody.Bytes.class, outbound.getBody().orElseThrow()).getBytes());
        assertTrue(begin.getPostForm().getFields().containsKey("SAMLRequest"));
        assertFalse(begin.getPostForm().getFields().containsKey("SAMLResponse"));
        Request response = logoutPostRequest(fixture.responseBody(begin.getPendingLogout()));
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SokletSaml.postLogoutBindingResultFor(response)).getMessage();
        var pending = fixture.pendingSource(begin.getPendingLogout());
        assertInstanceOf(SamlLogoutResult.Succeeded.class,
                fixture.sp.completeLogoutResult(message, pending, fixture.idp));
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                fixture.sp.completeLogoutResult(message, pending, fixture.idp));

        SamlPostBindingMessage request = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SokletSaml.postLogoutBindingResultFor(logoutPostRequest(fixture.requestBody("_idp-logout")))).getMessage();
        var accepted = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                fixture.sp.acceptLogoutRequestResult(request, fixture.idp));
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                fixture.sp.acceptLogoutRequestResult(request, fixture.idp));
        SamlLogoutResponsePostResult.Prepared reply = assertInstanceOf(SamlLogoutResponsePostResult.Prepared.class,
                fixture.sp.respondToPostLogoutRequestResult(accepted.getRequest(), fixture.idp, SamlLogoutStatus.SUCCESS));
        MarshaledResponse answer = SokletSaml.logoutResponsePostFormResponse(reply, null);
        assertEquals(200, answer.getStatusCode());
        assertArrayEquals(reply.getPostForm().toHtml(null).getBytes(StandardCharsets.UTF_8), assertInstanceOf(MarshaledResponseBody.Bytes.class, answer.getBody().orElseThrow()).getBytes());
        assertTrue(reply.getPostForm().getFields().containsKey("SAMLResponse"));
        assertFalse(reply.getPostForm().getFields().containsKey("SAMLRequest"));
    }

    private static @NonNull Request logoutPostRequest(byte @NonNull [] body) {
        return Request.withRawUrl(HttpMethod.POST, "/logout")
                .headers(Map.of("Content-Type", List.of("application/x-www-form-urlencoded"))).body(body).build();
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
