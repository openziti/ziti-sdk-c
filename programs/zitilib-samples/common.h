// Copyright (c) 2025. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//
// Created by eugene on 8/6/25.
//

#ifndef ZITI_SDK_COMMON_H
#define ZITI_SDK_COMMON_H

#include <ziti/zitilib.h>

#include <stdint.h>

/**
 * Loads and completes authentication steps if necessary.
 *
 * @param identity
 * @return
 */
static inline ziti_handle_t init_context(const char *identity) {
    Ziti_lib_init();

    ziti_handle_t ztx;
    int rc = Ziti_load_context(&ztx, identity);
    if (rc != ZITI_OK) {
        fprintf(stderr, "failed to load ziti context from %s: %s\n", identity, ziti_errorstr(rc));
        return ZITI_INVALID_HANDLE;
    }
    return ztx;
}

#endif //ZITI_SDK_COMMON_H
