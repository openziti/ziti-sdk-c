// Copyright (c) 2026.  NetFoundry Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ZITI_SDK_GLOB_MATCH_H
#define ZITI_SDK_GLOB_MATCH_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// true if `pattern` contains glob wildcard characters ('*' or '?') rather than being a
// literal string.
bool ziti_glob_has_wildcard(const char *pattern);

// simple glob match -- '*' matches any run of characters (including none, and including
// path separators), '?' matches exactly one character. A literal pattern (no wildcard
// characters) matches only its exact string. `case_insensitive` selects whether comparison
// is case-sensitive (e.g. for matching process paths, Windows/macOS compare
// case-insensitively while Linux compares case-sensitively).
bool ziti_glob_match(const char *pattern, const char *candidate, bool case_insensitive);

// true if `path` ends with the literal " (deleted)" suffix the Linux kernel appends to a
// /proc/<pid>/exe readlink target whose underlying inode has been unlinked (the running
// binary was replaced or removed on disk). That target names no real file -- a wildcard
// pattern ending in '*' would otherwise happily absorb the suffix and match it.
bool ziti_path_has_deleted_suffix(const char *path);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_GLOB_MATCH_H
