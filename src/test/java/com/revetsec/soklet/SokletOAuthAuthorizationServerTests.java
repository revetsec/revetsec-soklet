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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.server.*;
import com.soklet.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Stream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import static org.junit.jupiter.api.Assertions.*;

final class SokletOAuthAuthorizationServerTests {
 private static final String RESOURCE="https://resource.example/mcp",REDIRECT="https://client.example/cb?original=%2f";
 private static final String BINDING="A".repeat(43),VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-06T12:00:00Z"),ZoneOffset.UTC);
 private static @NonNull OAuthAuthorizationServer server(boolean failing) throws Exception {
  var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair pair=generator.generateKeyPair();
  var client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
    .allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build();
  byte[] sealing=new byte[32];for(int i=0;i<32;i++)sealing[i]=(byte)(i+1);
  var server=OAuthAuthorizationServer.withIssuer("https://issuer.example").authorizationEndpoint(URI.create("https://issuer.example/authorize"))
    .tokenEndpoint(URI.create("https://issuer.example/token")).jsonWebKeySetEndpoint(URI.create("https://issuer.example/jwks"))
    .revocationEndpoint(URI.create("https://issuer.example/revoke")).introspectionEndpoint(URI.create("https://issuer.example/introspect"))
    .clientRepository((id,b)->Optional.of(client)).store(new Store(failing)).clock(CLOCK)
    .stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("seal",Base64.getEncoder().encodeToString(sealing))).build())
    .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",pair.getPrivate(),pair.getPublic())).generation("g1").publishedAt(CLOCK.instant().minusSeconds(120)).build()))
    .grantPolicy((c,b)->OAuthAuthorizationDecision.withSubject(c.getSubject()).authorizedScopesByResource(c.getAuthorizedScopesByResource()).build())
    .resources(Map.of(RESOURCE,Set.of("read"))).build();
  if(!failing) {assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer());server.establishNewSubject("subject");}
  return server;
 }
 private static @NonNull Request post(@NonNull String url,byte @NonNull [] body,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields) {
  return Request.withRawUrl(HttpMethod.POST,url).headers(fields).body(body).build();
 }
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields() {return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> rawFields(@NonNull Request request) {
  Map<String,List<String>> out=new LinkedHashMap<>();request.getHeaders().forEach((k,v)->out.put(k,List.copyOf(v)));return out;
 }
 private static byte @NonNull [] body(@NonNull MarshaledResponse response) {
  return assertInstanceOf(MarshaledResponseBody.Bytes.class,response.getBody().orElseThrow()).getBytes();
 }
 private static void same(@NonNull OAuthServerResponse a,@NonNull OAuthServerResponse b) {
  assertEquals(a.getStatusCode(),b.getStatusCode());assertEquals(a.getHeaders(),b.getHeaders());assertArrayEquals(a.toHttpBodyWithCredentials(),b.toHttpBodyWithCredentials());assertEquals(a.getLocationWithCredentials(),b.getLocationWithCredentials());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> rawFormsRemainCoreDecisions() {
  return Stream.of("grant_type=authorization_code&code=%FF","grant_type=refresh_token&grant_type=authorization_code","grant_type=%","grant_type=client_credentials","grant_type=refresh_token&client_id=client&refresh_token=x","a="+"x".repeat(65536))
   .map(form->DynamicTest.dynamicTest("raw form bytes "+form.length(),()->{
    var s=server(false);var request=post("/token",form.getBytes(StandardCharsets.UTF_8),fields());
    same(assertInstanceOf(OAuthTokenResult.Rejected.class,s.tokenResult("POST",null,request.getBody().orElseThrow(),rawFields(request))).getResponse(),
      assertInstanceOf(OAuthTokenResult.Rejected.class,SokletOAuthAuthorizationServer.tokenResultFor(s,request)).getResponse());
   }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyDistinctPhysicalFieldReachesCore() {
  return Stream.of("Content-Type","Authorization","Content-Encoding").map(name->DynamicTest.dynamicTest(name,()->{
   var s=server(false);var request=SokletRawInputTests.fromPhysicalHeaders(HttpMethod.POST,"/token",List.of(Map.entry("Content-Type","application/x-www-form-urlencoded"),Map.entry(name,name.equals("Content-Type")?"text/plain":"first"),Map.entry(name.toUpperCase(Locale.ROOT),"second")),"grant_type=authorization_code".getBytes(StandardCharsets.UTF_8));
   same(assertInstanceOf(OAuthTokenResult.Rejected.class,s.tokenResult("POST",null,request.getBody().orElseThrow(),rawFields(request))).getResponse(),assertInstanceOf(OAuthTokenResult.Rejected.class,SokletOAuthAuthorizationServer.tokenResultFor(s,request)).getResponse());
  }));
 }
 @Test void methodAndQueryRejectionsUsePreparedCoreResponses() throws Exception {
  var s=server(false);var request=Request.fromRawUrl(HttpMethod.GET,"/token?raw=x%2By");
  same(assertInstanceOf(OAuthTokenResult.Rejected.class,s.tokenResult("GET","raw=x%2By",new byte[0],Map.of())).getResponse(),assertInstanceOf(OAuthTokenResult.Rejected.class,SokletOAuthAuthorizationServer.tokenResultFor(s,request)).getResponse());
  assertEquals(405,assertInstanceOf(OAuthRevocationResult.Rejected.class,SokletOAuthAuthorizationServer.revocationResultFor(s,request)).getResponse().getStatusCode());
  assertEquals(405,assertInstanceOf(OAuthIntrospectionResult.Rejected.class,SokletOAuthAuthorizationServer.introspectionResultFor(s,request)).getResponse().getStatusCode());
 }
 @Test void authorizationRetainsEncodedRedirectRawQueryAndIndependentBinding() throws Exception {
  var s=server(false);String query="client_id=client&response_type=code&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&code_challenge="+CHALLENGE+"&code_challenge_method=S256&state=raw%2Bstate";
  var request=Request.fromRawUrl(HttpMethod.GET,"/authorize?"+query);
  var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,SokletOAuthAuthorizationServer.beginAuthorizationResultFor(s,request,BINDING)).getInteraction();
  assertInstanceOf(OAuthAuthorizationResult.Rejected.class,s.resumeAuthorizationResult(interaction.getInteractionValue(),"B".repeat(42)+"A"));
  var completed=assertInstanceOf(OAuthAuthorizationResult.Completed.class,s.completeAuthorizationResult(interaction.getInteractionValue(),BINDING,OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build()));
  var prepared=completed.getResponse();var response=SokletOAuthAuthorizationServer.responseFor(prepared);
  assertEquals(303,response.getStatusCode());assertEquals(List.of(prepared.getLocationWithCredentials().orElseThrow().toASCIIString()),response.getHeaders().get("Location"));assertArrayEquals(prepared.toHttpBodyWithCredentials(),body(response));
  assertTrue(Objects.requireNonNull(response.getHeaders().get("Location")).iterator().next().startsWith(REDIRECT+"&code="));
  String location=prepared.getLocationWithCredentials().orElseThrow().toString();String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
  String form="grant_type=authorization_code&client_id=client&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&code="+code+"&code_verifier="+VERIFIER;
  var token=assertInstanceOf(OAuthTokenResult.Succeeded.class,SokletOAuthAuthorizationServer.tokenResultFor(s,post("/token",form.getBytes(StandardCharsets.UTF_8),fields()))).getResponse();
  assertArrayEquals(token.toHttpBodyWithCredentials(),body(SokletOAuthAuthorizationServer.responseFor(token)));
 }
 @Test void metadataJwksAndHeadEmitExactBodies() throws Exception {
  var s=server(false);for(var prepared:List.of(s.metadataResponse("GET"),s.metadataResponse("HEAD"),s.jsonWebKeySetResponse("GET"),s.jsonWebKeySetResponse("HEAD"))) {
   var response=SokletOAuthAuthorizationServer.responseFor(prepared);assertEquals(prepared.getStatusCode(),response.getStatusCode());assertArrayEquals(prepared.toHttpBodyWithCredentials(),body(response));
   prepared.getHeaders().forEach((k,v)->assertEquals(List.copyOf(v),response.getHeaders().get(k)));
  }
 }
 @Test void infrastructureFailurePropagatesAsTypedFailure() throws Exception {
  var s=server(true);String query="client_id=client&response_type=code&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&code_challenge="+CHALLENGE+"&code_challenge_method=S256";
  var failure=assertThrows(OAuthServerException.class,()->SokletOAuthAuthorizationServer.beginAuthorizationResultFor(s,Request.fromRawUrl(HttpMethod.GET,"/authorize?"+query),BINDING));assertFalse(Objects.requireNonNull(failure.getMessage()).contains("private-storage-diagnostic"));
 }
 @Test @SuppressWarnings("NullAway") void requiredPrimaryArgumentsRejectNull() throws Exception {
  var s=server(false);var r=Request.fromPath(HttpMethod.GET,"/");
  assertThrows(NullPointerException.class,()->SokletOAuthAuthorizationServer.tokenResultFor(null,r));assertThrows(NullPointerException.class,()->SokletOAuthAuthorizationServer.tokenResultFor(s,null));
  assertThrows(NullPointerException.class,()->SokletOAuthAuthorizationServer.beginAuthorizationResultFor(s,r,null));assertThrows(NullPointerException.class,()->SokletOAuthAuthorizationServer.responseFor(null));
 }
 private static final class Store implements OAuthAuthorizationServerStore {
  private final Map<OAuthStoreKey,OAuthStoreEntry> rows=new LinkedHashMap<>();private final boolean failing;
  Store(boolean failing) {this.failing=failing;}
  @Override public synchronized @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget) {if(failing)throw new IllegalStateException("private-storage-diagnostic");return Optional.ofNullable(rows.get(key));}
  @Override public synchronized @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget) {
   if(failing)throw new IllegalStateException("private-storage-diagnostic");
   for(var condition:tx.getConditions()) {var present=rows.get(condition.getKey());if(!condition.getExpectedVersion().equals(present==null?Optional.empty():Optional.of(present.getVersion())))return OAuthStoreCommitStatus.CONFLICT;}
   for(var mutation:tx.getMutations()) {if(mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE)rows.remove(mutation.getKey());else rows.put(mutation.getKey(),mutation.getEntry().orElseThrow());}
   return OAuthStoreCommitStatus.COMMITTED;
  }
 }
}
