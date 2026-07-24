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

#ifndef ZITI_SDK_OIDC_H
#define ZITI_SDK_OIDC_H

#include "auth_method.h"
#include "jwt.h"
#include "tlsuv/http.h"
#include <stc/cstr.h>
#include <uv.h>
#include <ziti/ziti_model.h>

#ifdef __cplusplus
extern "C" {
#endif

enum oidc_status {
    OIDC_TOKEN_OK  = 0,
    OIDC_TOTP_NEEDED = 1,
    OIDC_TOTP_FAILED = 2,
    OIDC_TOTP_SUCCESS = 3,
    OIDC_TOKEN_FAILED = 4,
    OIDC_RESTART     = 5,
    OIDC_EXT_JWT_NEEDED = 6,
};

typedef struct oidc_client_s oidc_client_t;
typedef void (*oidc_config_cb)(oidc_client_t *, int, const char *);
typedef void (*oidc_token_cb)(oidc_client_t *, enum oidc_status, const void *data);
typedef void (*oidc_close_cb)(oidc_client_t *);

struct oidc_client_s {
    void *data;
    cstr provider_url;
    tlsuv_http_t http;
    tls_context *tls;
    zt_x509 *x509;

    oidc_config_cb config_cb;
    oidc_token_cb token_cb;
    oidc_close_cb close_cb;

    void *config;
    zt_jwt current;
    zt_jwt refresh_token;

    uv_timer_t *timer;
    model_map ext_tokens; // map[issuer -> zt_jwt_t]

    bool configuring;
    bool need_refresh;
    struct auth_req *request;
    tlsuv_http_req_t *refresh_req;
    int refresh_failures;

    // auth-method facade (populated only by new_oidc_auth)
    ziti_auth_method_t api;
    uv_loop_t *loop;
    model_list urls;
    model_list_iter cur_url;
    auth_state_cb auth_cb;
    void *auth_cb_ctx;
    auth_mfa_cb mfa_cb;
    struct timeval expiration;
    bool started;
};

// init
int oidc_client_init(uv_loop_t *loop, oidc_client_t *clt,
                     const char *provider, tls_context *tls);
int oidc_client_set_cfg(oidc_client_t *clt, const char *provider);

// configure client
int oidc_client_configure(oidc_client_t *clt, oidc_config_cb);

// acquire access token and start refresh cycle
// oidc_token_cb will be called on first auth and on every refresh
int oidc_client_start(oidc_client_t *clt, oidc_token_cb);

int oidc_client_mfa(oidc_client_t *clt, const char *code);

// force token refresh ahead of normal cycle, error if called prior to oidc_client_start
int oidc_client_refresh(oidc_client_t *clt);

// close
int oidc_client_close(oidc_client_t *clt, oidc_close_cb);

#ifdef __cplusplus
};
#endif

#endif //ZITI_SDK_OIDC_H
