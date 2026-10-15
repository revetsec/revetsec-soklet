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

/**
 * Revetsec helpers for <a href="https://www.soklet.com">Soklet</a> applications.
 * <p>
 * The helpers are static classes. They pass a Soklet {@code Request} to Revetsec core as raw input (query string,
 * form body, header values) and turn Revetsec results into Soklet responses. They contain no protocol logic: every
 * validation decision is made by Revetsec core, through its public API only.
 * <p>
 * {@link com.revetsec.soklet.SokletOAuth} handles raw GET and form-post callbacks plus trusted redirects;
 * {@link com.revetsec.soklet.SokletBearer} exposes absent, unverified present and malformed Authorization results.
 * {@link com.revetsec.soklet.SokletOAuthAuthorizationServer} admits raw issuer requests and emits prepared responses;
 * {@link com.revetsec.soklet.SokletSaml} and {@link com.revetsec.soklet.SokletScim} provide corresponding SAML and SCIM
 * transport helpers. {@link com.revetsec.soklet.JwksMarshaledResponse} publishes standalone public key sets as
 * prepared bytes; {@link com.revetsec.soklet.JwksResponse} supplies typed bodies with application-owned JSON
 * serialization. Soklet 4 retains header values as lists; the helpers pass every materialized occurrence to core.
 * The OAuth callback helper returns an explicit oversized outcome for bodies Soklet discarded. Issuer, SAML POST
 * and SCIM body helpers return {@link com.revetsec.soklet.SokletRequestResult}: oversized bodies never invoke core,
 * while a completed transport carries the actual protocol result. A trusted edge
 * still enforces complete-request, physical framing and header limits before materialization.
 * <p>
 * Revetsec core and Soklet are {@code provided} dependencies of this adapter, so an application declares both.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NullMarked
package com.revetsec.soklet;

import org.jspecify.annotations.NullMarked;
