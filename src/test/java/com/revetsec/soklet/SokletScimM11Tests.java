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

import static org.junit.jupiter.api.Assertions.*;
import com.revetsec.scim.*;
import com.soklet.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** PATCH transport uses unchanged bytes and all physical Content-Type fields exactly once. */
class SokletScimM11Tests {
    private static final @NonNull ScimResourceType GROUP=ScimResourceType.groupInstance();
    private static final @NonNull String BODY="{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"fixture-member\"}]}]}";
    private static @NonNull ScimServiceProvider provider(@NonNull ScimObserver observer) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(GROUP)).serviceProviderConfig(ScimServiceProviderConfig.builder().patchSupported(true).build())
                .stringMatching((path,definition,op,left,right)->ScimStringMatchResult.fromMatched(left.equals(right)))
                .observer(observer).build();
    }
    private static @NonNull Request request(@NonNull String body) {
        return Request.withRawUrl(HttpMethod.PATCH,"/scim/Groups/fixture").headers(Map.of("Content-Type",List.of("application/scim+json")))
                .body(body.getBytes(StandardCharsets.UTF_8)).build();
    }
    @Test void patchHelperBindsMemberIdsAndInvokesOneCoreOperation() {
        CountingObserver observer=new CountingObserver();ScimServiceProvider p=provider(observer);
        ScimPatchRequest patch=assertInstanceOf(ScimPatchParseResult.Succeeded.class,SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(p,GROUP,request(BODY)))).getPatchRequest();
        assertSame(GROUP,patch.getResourceType());assertEquals(1,patch.getOperations().size());
        assertEquals(ScimPatchOperationType.ADD,patch.getOperations().get(0).getOperationType());
        assertEquals(1,observer.starts.get());assertEquals(1,observer.ends.get());
        assertEquals(List.of("fixture-member"),assertInstanceOf(ScimMembershipPatchResult.Reduced.class,
                p.reduceMembershipPatchResult(patch)).getMembershipPatch().getSteps().get(0).getValues());
    }
    @Test void duplicatePhysicalMediaTypesAndWrongTypesReachCoreWithoutJoining() throws ReflectiveOperationException {
        ScimServiceProvider p=provider(ScimObserver.disabledInstance());
        Request duplicate=SokletRawInputTests.fromPhysicalHeaders(HttpMethod.PATCH,"/scim/Groups/fixture",
                List.of(Map.entry("Content-Type","application/scim+json"),Map.entry("content-type","application/scim+json")),BODY.getBytes(StandardCharsets.UTF_8));
        assertSame(ScimError.unsupportedMediaTypeInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(p,GROUP,duplicate))).getError());
        Request unsupported=Request.withRawUrl(HttpMethod.PATCH,"/scim/Groups/fixture")
                .headers(Map.of("Content-Type",List.of("text/plain"))).body(BODY.getBytes(StandardCharsets.UTF_8)).build();
        assertSame(ScimError.unsupportedMediaTypeInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(p,GROUP,unsupported))).getError());
    }
    @Test void materializedMissingAndMalformedBodiesRemainCoreRejections() {
        ScimServiceProvider p=provider(ScimObserver.disabledInstance());
        Request missing=Request.withRawUrl(HttpMethod.PATCH,"/scim/Groups/fixture")
                .headers(Map.of("Content-Type",List.of("application/scim+json"))).build();
        assertInstanceOf(ScimPatchParseResult.Rejected.class,SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(p,GROUP,missing)));
        assertSame(ScimError.invalidSyntaxInstance(),assertInstanceOf(ScimPatchParseResult.Rejected.class,
                SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(p,GROUP,request("{broken")))).getError());
    }
    @Test @SuppressWarnings("NullAway") void requiredReferencesFailAsProgrammingErrors() {
        ScimServiceProvider p=provider(ScimObserver.disabledInstance());Request r=request(BODY);
        assertThrows(NullPointerException.class,()->SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(null,GROUP,r)));
        assertThrows(NullPointerException.class,()->SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(p,null,r)));
        assertThrows(NullPointerException.class,()->SokletTransportFixtures.completed(SokletScim.patchRequestResultFor(p,GROUP,null)));
    }
    @ThreadSafe private static final class CountingObserver implements ScimObserver {
        private final @NonNull AtomicInteger starts=new AtomicInteger(), ends=new AtomicInteger();
        @Override public void willProcess(ScimObserver.@NonNull Operation op) {if(op==ScimObserver.Operation.PATCH_PARSE) starts.incrementAndGet();}
        @Override public void didProcess(ScimObserver.@NonNull Operation op,ScimObserver.@NonNull Outcome outcome) {
            if(op==ScimObserver.Operation.PATCH_PARSE) {assertEquals(ScimObserver.Outcome.SUCCEEDED,outcome);ends.incrementAndGet();}
        }
    }
}
