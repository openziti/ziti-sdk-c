// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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

#ifndef ZITI_SDK_E2EE_COMMON_H
#define ZITI_SDK_E2EE_COMMON_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

static inline const char* to_hex(const uint8_t *bin, unsigned len) {
    static char buf[1024];
    const uint8_t *b = bin;
    char *p = buf;
    while (b - bin < len && p - buf < sizeof(buf) - 2) {
        uint8_t hi = *b >> 4;
        uint8_t lo = *b & 0x0F;
        *p++ = (char)( hi < 10 ? '0' + hi : 'a' + hi - 10 );
        *p++ = (char)( lo < 10 ?  '0' + lo : 'a' + lo - 10 );
        b++;
    }
    *p = '\0';
    return buf;
}

#define ZITI_E2EE_DEBUG 0

#if ZITI_E2EE_DEBUG
#define PRINT_BYTES(label, buf, len) do { \
    ZITI_LOG(DEBUG, "%s: %s", label, to_hex(buf, (unsigned)len)); \
} while(0)
#else
#define PRINT_BYTES(label, buf, len) do {} while(0)
#endif


#ifdef __cplusplus
}
#endif

#endif // ZITI_SDK_E2EE_COMMON_H
