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

#ifndef ZITI_EXT_OIDC_H
#define ZITI_EXT_OIDC_H

#include <stdbool.h>
#include <uv.h>
#include <ziti/ziti_model.h>
#include "tlsuv/http.h"
#include "jwt.h"

#ifdef __cplusplus
extern "C" {
#endif

enum ext_oidc_status {
    EXT_OIDC_TOKEN_OK  = 0,
    EXT_OIDC_CONFIG_FAILED = 1,
    EXT_OIDC_TOKEN_FAILED = 2,
    EXT_OIDC_RESTART     = 3,
};

typedef struct ext_oidc_client_s ext_oidc_client_t;
typedef void (*ext_oidc_token_cb)(ext_oidc_client_t *, enum ext_oidc_status, const void *data);
typedef void (*ext_oidc_close_cb)(ext_oidc_client_t *);
typedef void (*ext_oidc_link_cb)(ext_oidc_client_t *, const char *link, void *ctx);

struct ext_oidc_client_s {
    void *data;
    tlsuv_http_t http;

    ziti_jwt_signer signer_cfg;

    ext_oidc_token_cb token_cb;
    ext_oidc_close_cb close_cb;

    ext_oidc_link_cb link_cb;
    void *link_ctx;

    cstr name;
    cstr issuer;
    void *config;
    void *tokens;
    const char *refresh_grant;

    zt_jwt current;
    zt_jwt refresh_token;
    int64_t refresh_token_exp;
    int refresh_failures;
    tlsuv_http_req_t *refresh_req;

    uv_timer_t *timer;

    tlsuv_http_pair *auth_params;
    int auth_params_count;

    struct auth_req *request;

    // browser callback held open until controller verdict (or watchdog fires)
    uv_os_sock_t pending_sock;
    uv_timer_t *pending_timer;
};

// init
int ext_oidc_client_init(uv_loop_t *loop, ext_oidc_client_t *clt,
                     const struct ziti_jwt_signer_s *cfg);

void ext_oidc_client_set_link_cb(ext_oidc_client_t *clt, ext_oidc_link_cb, void *ctx);

// acquire an access token and start refresh cycle
// oidc_token_cb will be called on the first auth and on every refresh
int ext_oidc_client_start(ext_oidc_client_t *clt, ext_oidc_token_cb);

// force token refresh ahead of normal cycle, error if called prior to ext_oidc_client_start
int ext_oidc_client_refresh(ext_oidc_client_t *clt);

// close
int ext_oidc_client_close(ext_oidc_client_t *clt, ext_oidc_close_cb);

// signal the result of the wider auth flow (controller acceptance/rejection of the JWT)
// so the deferred browser callback page can be written and closed.
// no-op if no callback is pending.
void ext_oidc_client_finalize(ext_oidc_client_t *clt, bool ok, const char *error_msg);

#ifdef __cplusplus
};
#endif

#endif //ZITI_EXT_OIDC_H
