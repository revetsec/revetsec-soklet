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

import org.jspecify.annotations.NonNull;

/** Extracts the completed transport in tests whose request body is known to be complete. */
final class SokletTransportFixtures {
    private SokletTransportFixtures() { }

    static <T> @NonNull T completed(@NonNull SokletRequestResult<@NonNull T> transport) {
        if (transport instanceof SokletRequestResult.Completed<T> completed) return completed.getResult();
        throw new AssertionError("Expected complete fixture request: " + transport);
    }
}
