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
static int ha_ext_jwt(ziti_auth_method_t *self, const char *token);
static int ha_set_endpoint(ziti_auth_method_t *self, const api_path *api);
static void config_cb(oidc_client_t *oidc, int status, const char *err);
static char* internal_oidc_path(const api_path *api);

struct ha_auth_s {
    ziti_auth_method_t api;

    uv_loop_t *loop;
    auth_state_cb cb;
    void *cb_ctx;

    oidc_client_t oidc;
    ziti_jwt_signer config;
    auth_mfa_cb mfa_cb;
};

ziti_auth_method_t *new_oidc_auth(uv_loop_t *l, const api_path *api, tls_context *tls) {
    struct ha_auth_s *auth = calloc(1, sizeof(*auth));

    auth->api = (ziti_auth_method_t){
        .kind = OIDC,
        .start = ha_auth_start,
        .set_endpoint = ha_set_endpoint,
        .stop = ha_auth_stop,
        .force_refresh = ha_auth_refresh,
        .submit_mfa = ha_auth_mfa,
        .free = ha_auth_free,
        .set_ext_jwt = ha_ext_jwt,
    };

    auth->loop = l;
    auth->config = (ziti_jwt_signer){
            .client_id = "openziti",
            .name = "ziti-internal-oidc",
            .enabled = true,
            .provider_url = internal_oidc_path(api),
            .target_token = ziti_target_token_access_token,
    };
    model_list_append(&auth->config.scopes, "offline_access");

    oidc_client_init(l, &auth->oidc, &auth->config, tls);
    return (ziti_auth_method_t*)auth;
}

static char *internal_oidc_path(const api_path *api) {
    struct tlsuv_url_s base_url = {};
    tlsuv_parse_url(&base_url, api->base_urls[0]);

    string_buf_t *url_buf = new_string_buf();
    string_buf_fmt(url_buf, "%.*s://%.*s",
        (int)base_url.scheme_len, base_url.scheme,
        (int)base_url.hostname_len, base_url.hostname);
    if (base_url.port) {
        string_buf_fmt(url_buf, ":%d", base_url.port);
    }
    // older controllers did not have path in the base URL
    if (base_url.path) {
        string_buf_appendn(url_buf, base_url.path, base_url.path_len);
    } else if (api->path) {
        string_buf_append(url_buf, api->path);
    }

    char *url = string_buf_to_string(url_buf, NULL);
    delete_string_buf(url_buf);
    return url;
}

static int ha_set_endpoint(ziti_auth_method_t *self, const api_path *api) {
    struct ha_auth_s *auth = HA_AUTH(self);
    char *ep = internal_oidc_path(api);
    if (auth->config.provider_url && strcmp(ep, auth->config.provider_url) == 0) {
        free(ep);
        return -1;
    }

    FREE(auth->config.provider_url);
    auth->config.provider_url = ep;

    oidc_client_set_cfg(&auth->oidc, &auth->config);
    return oidc_client_configure(&auth->oidc, config_cb);
}


static void close_cb(oidc_client_t *oidc) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    free((char*)auth->config.provider_url);
    model_list_clear(&auth->config.scopes, NULL);
    free(auth);
}

static void ha_auth_free(ziti_auth_method_t *self) {
    struct ha_auth_s *auth = HA_AUTH(self);
    oidc_client_close(&auth->oidc, close_cb);
}

static void token_cb(oidc_client_t *oidc, enum oidc_status status, const char *token) {
    struct ha_auth_s *auth = HA_AUTH_FROM_OIDC(oidc);
    char err[128];

    if (auth->cb) {
        switch (status) {
            case OIDC_TOKEN_OK:
                auth->cb(auth->cb_ctx, ZitiAuthStateFullyAuthenticated, (void*)token);
                break;
            case OIDC_EXT_JWT_NEEDED:
                auth->cb(auth->cb_ctx, ZitiAuthStatePartiallyAuthenticated, (void *)token);
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
