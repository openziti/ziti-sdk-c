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

#include "buffer.h"
#include "ziti/ziti_buffer.h"

#define HA_AUTH(s) container_of((s), struct ha_auth_s, api)
#define HA_AUTH_FROM_OIDC(o) container_of((o), struct ha_auth_s, oidc)

static void ha_auth_free(ziti_auth_method_t *self);
static int ha_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx);
static int ha_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb);
static int ha_auth_stop(ziti_auth_method_t *self);
static int ha_auth_refresh(ziti_auth_method_t *self);
static const struct timeval *ha_expiration(ziti_auth_method_t *self);
static int ha_ext_jwt(ziti_auth_method_t *self, const char *token);
static int ha_set_endpoint(ziti_auth_method_t *self, const api_path *api);
static void config_cb(oidc_client_t *oidc, int status, const char *err);
static cstr internal_oidc_path(const char *base, const char *path);

struct ha_auth_s {
    ziti_auth_method_t api;

    uv_loop_t *loop;
    auth_state_cb cb;
    void *cb_ctx;

    model_list urls;
    model_list_iter cur_url;

    oidc_client_t oidc;
    bool started;
    auth_mfa_cb mfa_cb;
    struct timeval expiration;
};

ziti_auth_method_t *new_oidc_auth(uv_loop_t *l, const api_path *api, tls_context *tls) {
    struct ha_auth_s *auth = calloc(1, sizeof(*auth));

    auth->api = (ziti_auth_method_t){
        .kind = OIDC,
        .start = ha_auth_start,
        .set_endpoint = ha_set_endpoint,
        .stop = ha_auth_stop,
        .force_refresh = ha_auth_refresh,
        .expiration = ha_expiration,
        .submit_mfa = ha_auth_mfa,
        .free = ha_auth_free,
        .set_ext_jwt = ha_ext_jwt,
    };

    const char *u;
    FOR(u, api->base_urls) {
        model_list_append(&auth->urls, strdup(u));
    }
    auth->cur_url = model_list_iterator(&auth->urls);
    u = model_list_it_element(auth->cur_url);

    auth->loop = l;
    cstr oidc_url = internal_oidc_path(u, api->path);
    oidc_client_init(l, &auth->oidc, cstr_str(&oidc_url), tls);
    cstr_drop(&oidc_url);
    return (ziti_auth_method_t*)auth;
}

static cstr internal_oidc_path(const char *base, const char *path) {
    struct tlsuv_url_s base_url = {};
    tlsuv_parse_url(&base_url, base);

    cstr result = cstr_from_fmt("%.*s://%.*s",
        (int)base_url.scheme_len, base_url.scheme,
        (int)base_url.hostname_len, base_url.hostname);
    if (base_url.port) {
        cstr_append_fmt(&result, ":%d", base_url.port);
    }

    // older controllers did not have path in the base URL
    if (base_url.path) {
        cstr_append_n(&result, base_url.path, (isize)base_url.path_len);
    } else if (path) {
        cstr_append(&result, path);
    }

    return result;
}

static int ha_set_endpoint(ziti_auth_method_t *self, const api_path *api) {
    struct ha_auth_s *auth = HA_AUTH(self);

    model_list_clear(&auth->urls, free);
    const char *u;
    FOR(u, api->base_urls) {
        model_list_append(&auth->urls, strdup(u));
    }
    auth->cur_url = model_list_iterator(&auth->urls);
    u = model_list_it_element(auth->cur_url);

    cstr oidc_url = internal_oidc_path(u, api->path);
    oidc_client_set_cfg(&auth->oidc, cstr_str(&oidc_url));
    cstr_drop(&oidc_url);

    return oidc_client_configure(&auth->oidc, config_cb);
}


static void close_cb(oidc_client_t *oidc) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    model_list_clear(&auth->urls, free);
    free(auth);
}

static void ha_auth_free(ziti_auth_method_t *self) {
    struct ha_auth_s *auth = HA_AUTH(self);
    oidc_client_close(&auth->oidc, close_cb);
}

static void set_expiration(struct ha_auth_s *auth, const char *token) {
    json_object *payload = json_tokener_parse(jwt_payload(token));
    json_object *exp = json_object_object_get(payload, "exp");
    if (exp) {
        int exp_time = json_object_get_int(exp);
        auth->expiration.tv_sec = exp_time;
        auth->expiration.tv_usec = 0;
    } else {
        auth->expiration = (struct timeval){};
    }
    json_object_put(payload);
}

static void token_cb(oidc_client_t *oidc, enum oidc_status status, const void *data) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    char err[128];

    auth->expiration = (struct timeval){};
    if (auth->cb) {
        switch (status) {
            case OIDC_TOKEN_OK:
                set_expiration(auth, (const char*)data);
                auth->cb(auth->cb_ctx, ZitiAuthStateFullyAuthenticated, data);
                break;
            case OIDC_EXT_JWT_NEEDED:
                auth->cb(auth->cb_ctx, ZitiAuthStatePartiallyAuthenticated, data);
                break;
            case OIDC_TOTP_NEEDED:
                auth->cb(auth->cb_ctx, ZitiAuthStatePartiallyAuthenticated, (void *) &ZITI_MFA);
                break;
            case OIDC_TOTP_FAILED:
                assert(auth->mfa_cb != NULL);
                auth->mfa_cb(auth->cb_ctx, ZITI_MFA_INVALID_TOKEN);
                auth->mfa_cb = NULL;
                break;
            case OIDC_TOTP_SUCCESS:
                assert(auth->mfa_cb != NULL);
                auth->mfa_cb(auth->cb_ctx, ZITI_OK);
                auth->mfa_cb = NULL;
                break;
            case OIDC_TOKEN_FAILED:
                snprintf(err, sizeof(err), "failed to auth: %d", status);
                auth->cb(auth->cb_ctx, ZitiAuthStateUnauthenticated, &(ziti_error){
                        .err = status,
                        .message = err});
                break;
            case OIDC_RESTART:
                ZITI_LOG(DEBUG, "restarting internal OIDC flow");
                oidc_client_start(&auth->oidc, token_cb);
                break;
        }
    }
}

static void config_cb(oidc_client_t *oidc, int status, const char *err) {
    ZITI_LOG(DEBUG, "oidc config callback: %d/%s", status, err);
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    if (status == 0) {
        if (auth->started) {
            oidc_client_refresh(oidc);
        } else {
            auth->started = true;
            oidc_client_start(oidc, token_cb);
        }
    } else {
        const char *prev_url = model_list_it_element(auth->cur_url);
        auth->cur_url = model_list_it_next(auth->cur_url);
        if (auth->cur_url == NULL) {
            ZITI_LOG(ERROR, "failed to configure OIDC[%s] (no more URLs to try): %d/%s",
                     prev_url, status, err);
            if (auth->cb) {
                ziti_error error = {
                    .err = status,
                    .message = err,
                };
                auth->cb(auth->cb_ctx, ZitiAuthImpossibleToAuthenticate, &error);
            }
            return;
        }

        ZITI_LOG(DEBUG, "failed to configure OIDC[%s] client: %d/%s",
                 prev_url, status, err);

        const char *u = model_list_it_element(auth->cur_url);
        cstr oidc_url = internal_oidc_path(u, "/oidc");
        ZITI_LOG(DEBUG, "trying next url[%s]", cstr_str(&oidc_url));
        oidc_client_set_cfg(oidc, cstr_str(&oidc_url));
        oidc_client_configure(&auth->oidc, config_cb);
        cstr_drop(&oidc_url);
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
    if (oidc_client_mfa(&auth->oidc, code) != 0) {
        ZITI_LOG(WARN, "failed to submit MFA code");
        auth->mfa_cb = NULL;
        return ZITI_MFA_EXISTS;
    }
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

static const struct timeval *ha_expiration(ziti_auth_method_t *self) {
    struct ha_auth_s *auth = HA_AUTH(self);
    if (auth->expiration.tv_sec > 0) return &auth->expiration;
    return NULL;
}