// Copyright (c) 2023-2024. NetFoundry Inc.
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

struct ha_auth_s {
    ziti_auth_method_t api;

    auth_state_cb cb;
    void *cb_ctx;

    model_list urls;
    oidc_client_t oidc;
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
    };

    const char *u;
    MODEL_LIST_FOREACH(u, *urls) {
        model_list_append(&auth->urls, strdup(u));
    }

    oidc_client_init(l, &auth->oidc, (char*)model_list_head(&auth->urls), tls);
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
        if (status == 0) {
            auth->cb(auth->cb_ctx, ZitiAuthStateFullyAuthenticated, (void*)token);
        } else if (status == UV_ECONNREFUSED) {
            // rotate to next url
            char *url = model_list_pop(&auth->urls);
            model_list_append(&auth->urls, url);
            oidc_client_set_url(&auth->oidc, model_list_head(&auth->urls));
        } else {
            char err[128];
            snprintf(err, sizeof(err), "failed to auth: %d", status);
            auth->cb(auth->cb_ctx, ZitiAuthStateUnauthenticated, err);
        }
    }
}

static void config_cb(oidc_client_t *oidc, int status, const char *err) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    if (status == 0) {
        oidc_client_start(oidc, token_cb);
    }

    assert(status == 0);
}

static int ha_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx) {
    struct ha_auth_s *auth = HA_AUTH(self);
    auth->cb = cb;
    auth->cb_ctx = ctx;

    return oidc_client_configure(&auth->oidc, config_cb);
}

static int ha_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb) {
    struct ha_auth_s *auth = HA_AUTH(self);

    ZITI_LOG(WARN, "not implemented");
    return ZITI_WTF;
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
