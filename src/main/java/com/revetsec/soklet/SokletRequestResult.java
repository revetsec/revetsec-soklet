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

import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * The transport outcome of delivering a complete Soklet request to a core protocol operation. An oversized body
 * discarded by Soklet never invokes the core operation. A completed transport carries the actual core result;
 * it does not imply protocol acceptance, authentication, authorization or mutation success.
 * <p>
 * Only adapter operations construct these outcomes. Later releases may add variants; consuming switches should
 * include a rejecting default branch. This wrapper never mutates its result.
 *
 * @param <T> the core operation's result type
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public abstract sealed class SokletRequestResult<T>
        permits SokletRequestResult.Completed, SokletRequestResult.TooLarge {
    SokletRequestResult() { }

    static <T> @NonNull SokletRequestResult<@NonNull T> fromResult(@NonNull T result) {
        return new Completed<>(requireNonNull(result));
    }
    static <T> @NonNull SokletRequestResult<@NonNull T> fromTooLarge() { return new TooLarge<>(); }

    /**
     * Returns the transport outcome without body, credentials or protocol data.
     * @return redacted description
     * @since 1.0.0
     */
    @Override public final @NonNull String toString() {
        return "SokletRequestResult{outcome=" + getClass().getSimpleName() + ", data=<redacted>}";
    }

    /**
     * The complete materialized request reached the core operation. Its own result still determines acceptance.
     * @param <T> the core operation's result type
     * @author <a href="https://www.revetkn.com">Mark Allen</a>
     * @since 1.0.0
     */
    @ThreadSafe
    public static final class Completed<T> extends SokletRequestResult<@NonNull T> {
        private final @NonNull T result;
        private Completed(@NonNull T result) { this.result = result; }
        /**
         * Returns the actual core outcome, including any protocol rejection or infrastructure disposition.
         * @return core operation result
         * @since 1.0.0
         */
        public @NonNull T getResult() { return this.result; }
    }

    /**
     * Soklet discarded the oversized body. No core operation ran and no pending state or mutation was consumed.
     * @param <T> the core operation's result type
     * @author <a href="https://www.revetkn.com">Mark Allen</a>
     * @since 1.0.0
     */
    @ThreadSafe
    public static final class TooLarge<T> extends SokletRequestResult<@NonNull T> {
        private TooLarge() { }
    }
}
