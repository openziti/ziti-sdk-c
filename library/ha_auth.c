// Copyright (c) 2023. NetFoundry Inc.
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

#include "auth_method.h"
#include "oidc.h"
#include "utils.h"
#include "ziti/errors.h"
#include <assert.h>
#include <stdlib.h>

#define HA_AUTH(s) container_of((s), struct ha_auth_s, api)
#define HA_AUTH_FROM_OIDC(o) container_of((o), struct ha_auth_s, oidc)

static void ha_auth_free(ziti_auth_method_t *self);
static int ha_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx);
static int ha_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb);
static int ha_auth_stop(ziti_auth_method_t *self);
static int ha_auth_refresh(ziti_auth_method_t *self);
static int ha_ext_jwt(ziti_auth_method_t *self, const char *token);

struct ha_auth_s {
    ziti_auth_method_t api;

    auth_state_cb cb;
    void *cb_ctx;

    model_list urls;
    oidc_client_t oidc;
    ziti_jwt_signer config;
    auth_mfa_cb mfa_cb;
};


ziti_auth_method_t *new_ha_auth(uv_loop_t *l, model_list* urls, tls_context *tls) {
    struct ha_auth_s *auth = calloc(1, sizeof(*auth));

    auth->api = (ziti_auth_method_t){
        .kind = HA,
        .start = ha_auth_start,
        .stop = ha_auth_stop,
        .force_refresh = ha_auth_refresh,
        .submit_mfa = ha_auth_mfa,
        .free = ha_auth_free,
        .set_ext_jwt = ha_ext_jwt,
    };

    const char *s;
    MODEL_LIST_FOREACH(s, *urls) {
        struct tlsuv_url_s u;
        tlsuv_parse_url(&u, s);
        char *url;
        const char *end = NULL;
        if (u.path) {
            end = u.path;
        } else if (u.query) {
            end = u.query - 1;
        }
        if (end == NULL) {
            url = strdup(s);
        } else {
            url = calloc(1, end - s + 1);
            memcpy(url, s, end - s);
        }
        model_list_append(&auth->urls, url);
    }
    auth->config = (ziti_jwt_signer){
        .client_id = "openziti",
        .name = "ziti-internal-oidc",
        .enabled = true,
        .provider_url = (char*) model_list_head(&auth->urls),
    };


    oidc_client_init(l, &auth->oidc, &auth->config, tls);
    return &auth->api;
}

static void close_cb(oidc_client_t *oidc) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    free(auth);
}

static void ha_auth_free(ziti_auth_method_t *self) {
    struct ha_auth_s *auth = HA_AUTH(self);
    oidc_client_close(&auth->oidc, close_cb);
}

static void token_cb(oidc_client_t *oidc, int status, const char *token) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    if (auth->cb) {
        if (status == OIDC_TOKEN_OK) {
            auth->cb(auth->cb_ctx, ZitiAuthStateFullyAuthenticated, (void*)token);
        } else if (status == OIDC_TOTP_NEEDED) {
            auth->cb(auth->cb_ctx, ZitiAuthStatePartiallyAuthenticated,
                     (void *) &ZITI_MFA);
        } else if (status == OIDC_TOTP_FAILED) {
            if (auth->mfa_cb) {
                auth->mfa_cb(auth->cb_ctx, ZITI_MFA_INVALID_TOKEN);
            }
        } else if (status == UV_ECONNREFUSED) {
            // rotate to next url
            char *url = model_list_pop(&auth->urls);
            model_list_append(&auth->urls, url);
            auth->config.provider_url = model_list_head(&auth->urls);
            oidc_client_set_cfg(&auth->oidc, &auth->config);
        } else {
            char err[128];
            snprintf(err, sizeof(err), "failed to auth: %d", status);
            auth->cb(auth->cb_ctx, ZitiAuthStateUnauthenticated, &(ziti_error){
                .err = status,
                .message = err});
        }
    }
}

static void config_cb(oidc_client_t *oidc, int status, const char *err) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    if (status == 0) {
        oidc_client_start(oidc, token_cb);
    } else {
        ZITI_LOG(ERROR, "failed to configure OIDC[%s] client: %d/%s",
                 auth->config.provider_url, status, err);
    }
}

static int ha_ext_jwt(ziti_auth_method_t *self, const char *token) {
    struct ha_auth_s *auth = HA_AUTH(self);
    oidc_client_token(&auth->oidc, token);
    return 0;
}

static int ha_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx) {
    struct ha_auth_s *auth = HA_AUTH(self);
    auth->cb = cb;
    auth->cb_ctx = ctx;

    return oidc_client_configure(&auth->oidc, config_cb);
}

static int ha_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb) {
    struct ha_auth_s *auth = HA_AUTH(self);
    auth->mfa_cb = cb;
    oidc_client_mfa(&auth->oidc, code);
    return ZITI_OK;
}

static int ha_auth_stop(ziti_auth_method_t *self) {
    struct ha_auth_s *auth = HA_AUTH(self);
    auth->cb = NULL;
    auth->cb_ctx = NULL;
    return 0;
}

static int ha_auth_refresh(ziti_auth_method_t *self) {
    struct ha_auth_s *auth = HA_AUTH(self);

    return oidc_client_refresh(&auth->oidc);
}
