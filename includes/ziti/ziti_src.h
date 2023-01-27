// Copyright (c) 2023.  NetFoundry Inc.
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

/**
 * @file ziti_src.h
 * @brief header file for ziti_src, which can be used as a source link in um_http requests
 *
 * @see programs/sample_http_link.c
 */

#ifndef ZITI_SDK_ZITI_SRC_H
#define ZITI_SDK_ZITI_SRC_H

#include <tlsuv/http.h>
#include <ziti/ziti.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize a `um_http_src_t` handle
 * 
 * @param l the uv loop
 * @param zl the um_http_src_t to initialize
 * @param svc the name of the service to be dialed
 * @param ztx the initialized ziti_context
 */
int ziti_src_init(uv_loop_t *l, tlsuv_src_t *zl, const char *svc, ziti_context ztx);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_SRC_H