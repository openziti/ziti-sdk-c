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

#include "glob_match.h"

#include <ctype.h>
#include <string.h>

bool ziti_glob_has_wildcard(const char *pattern) {
    return strpbrk(pattern, "*?") != NULL;
}

static bool chars_equal(char a, char b, bool case_insensitive) {
    if (case_insensitive) {
        return tolower((unsigned char)a) == tolower((unsigned char)b);
    }
    return a == b;
}

bool ziti_glob_match(const char *pattern, const char *candidate, bool case_insensitive) {
    const char *p = pattern;
    const char *s = candidate;
    const char *star_p = NULL;
    const char *star_s = NULL;

    while (*s) {
        if (*p == '?' || (*p != '\0' && *p != '*' && chars_equal(*p, *s, case_insensitive))) {
            p++;
            s++;
        } else if (*p == '*') {
            star_p = p++;
            star_s = s;
        } else if (star_p != NULL) {
            p = star_p + 1;
            s = ++star_s;
        } else {
            return false;
        }
    }

    while (*p == '*') {
        p++;
    }

    return *p == '\0';
}
