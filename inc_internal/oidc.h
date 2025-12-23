//
// 	Copyright NetFoundry Inc.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

#ifndef ZITI_SDK_OIDC_H
#define ZITI_SDK_OIDC_H

#include <uv.h>
#include <ziti/ziti_model.h>
#include "tlsuv/http.h"

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
    tlsuv_http_t http;

    ziti_jwt_signer signer_cfg;

    oidc_config_cb config_cb;
    oidc_token_cb token_cb;
    oidc_close_cb close_cb;

    char name[32];
    void *config;
    void *tokens;

    uv_timer_t *timer;
    char *jwt_token_auth;

    struct auth_req *request;
    tlsuv_http_req_t *refresh_req;
};

// init
int oidc_client_init(uv_loop_t *loop, oidc_client_t *clt,
                     const struct ziti_jwt_signer_s *cfg, tls_context *tls);
int oidc_client_set_cfg(oidc_client_t *clt, const struct ziti_jwt_signer_s *cfg);

// configure client
int oidc_client_configure(oidc_client_t *clt, oidc_config_cb);

// acquire access token and start refresh cycle
// oidc_token_cb will be called on first auth and on every refresh
int oidc_client_start(oidc_client_t *clt, oidc_token_cb);

int oidc_client_mfa(oidc_client_t *clt, const char *code);

int oidc_client_token(oidc_client_t *clt, const char *token);

// force token refresh ahead of normal cycle, error if called prior to oidc_client_start
int oidc_client_refresh(oidc_client_t *clt);

// close
int oidc_client_close(oidc_client_t *clt, oidc_close_cb);

#ifdef __cplusplus
};
#endif

#endif //ZITI_SDK_OIDC_H
