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
 * RevetSec helpers for <a href="https://www.soklet.com">Soklet</a> applications.
 * <p>
 * The helpers are static classes. They pass a Soklet {@code Request} to RevetSec core as raw input (query string,
 * form body, header values) and turn RevetSec results into Soklet responses. They contain no protocol logic: every
 * validation decision is made by RevetSec core, through its public API only.
 * <p>
 * RevetSec core and Soklet are {@code provided} dependencies of this adapter, so an application declares both.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.soklet;

import org.jspecify.annotations.NullMarked;
