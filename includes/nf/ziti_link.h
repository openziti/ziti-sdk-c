/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * @file ziti_link.h
 * @brief header file for ziti_link, which can be used as a custom source link in um_http requests
 *
 * @see sample/um-curl.c
 */

#ifndef NF_ZITI_LINK_H
#define NF_ZITI_LINK_H

#include <uv_mbed/um_http.h>
#include <nf/ziti.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ziti_link_s ziti_link_t;
typedef void (*ziti_link_close_cb)(ziti_link_t *zl);

/**
 * Inherits from uv_link_t, passed in to `um_http_set_link_source` to register
 * as a custom source link for `um_http`.
 */
typedef struct ziti_link_s {
    UV_LINK_FIELDS
    um_http_t *clt;
    nf_connection conn;
    nf_context nfc;
    char *service;
    um_http_custom_connect_cb connect_cb;
    ziti_link_close_cb close_cb;
} ziti_link_t;

/**
 * Initialize a `ziti_link_t` handle
 * 
 * @param zl the ziti_link to initialize
 * @param clt the um_http client to connect as source link
 * @param svc the name of the service to be dialed
 * @param nfc the initialized nf_context
 */
int ziti_link_init(ziti_link_t *zl, um_http_t *clt, const char *svc, nf_context nfc, ziti_link_close_cb close_cb);

#ifdef __cplusplus
}
#endif

#endif //NF_ZITI_LINK_H