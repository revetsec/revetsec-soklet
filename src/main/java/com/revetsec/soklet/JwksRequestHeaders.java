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

import com.soklet.Request;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;

/** Combines physical conditional header occurrences within the core publisher's input bound. */
final class JwksRequestHeaders {

	private static final int MAXIMUM_CONDITIONAL_HEADER_CHARACTERS = 8_192;

	private JwksRequestHeaders() {}

	static @Nullable String ifNoneMatchFor(@NonNull Request request) {
		StringBuilder combined = new StringBuilder();
		boolean present = false;
		for (Map.Entry<String, List<String>> field : request.getHeaders().entrySet()) {
			if (!"If-None-Match".equalsIgnoreCase(field.getKey()))
				continue;
			for (String value : field.getValue()) {
				int separator = present ? 1 : 0;
				if (value.length() > MAXIMUM_CONDITIONAL_HEADER_CHARACTERS - combined.length() - separator)
					return "x".repeat(MAXIMUM_CONDITIONAL_HEADER_CHARACTERS + 1);
				if (present)
					combined.append(',');
				combined.append(value);
				present = true;
			}
		}
		return present ? combined.toString() : null;
	}
}
