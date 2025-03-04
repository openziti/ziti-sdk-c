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

#include <ziti/ziti_events.h>
#include "zt_internal.h"
#include "oidc.h"

static void ext_oath_cfg_cb(oidc_client_t *oidc, int status, const char *err) {
    ziti_context ztx = oidc->data;
    ziti_event_t ev = {
            .type = ZitiAuthEvent,
    };
    if (status == 0) {
        ev.auth = (struct ziti_auth_event){
                .action = ziti_auth_login_external,
                .type = "oidc",
                .detail = oidc->http.host,
        };
    } else {
        ZTX_LOG(ERROR, "OIDC provider configuration failed: %s", err);
        ev.auth = (struct ziti_auth_event){
                .action = ziti_auth_cannot_continue,
                .type = "oidc",
                .detail = err,
        };
    }

    ziti_send_event(ztx, &ev);
}

static void ext_signers_cb(ziti_context ztx, int status, ziti_jwt_signer_array signers, void *ctx) {

    if (status != ZITI_OK) {
        ZTX_LOG(WARN, "failed to get external signers: %s", ziti_errorstr(status));
        return;
    }

    ziti_event_t ev = {
            .type = ZitiAuthEvent,
            .auth = (struct ziti_auth_event){
                    .action = ziti_auth_select_external,
                    .type = "oidc",
                    .providers = signers,
            },
    };
    ziti_send_event(ztx, &ev);
}

int ztx_init_external_auth(ziti_context ztx, const ziti_jwt_signer *oidc_cfg) {
    if (oidc_cfg != NULL) {
        NEWP(oidc, oidc_client_t);
        oidc_client_init(ztx->loop, oidc, oidc_cfg, NULL);
        oidc->data = ztx;
        ztx->ext_auth = oidc;
        return oidc_client_configure(oidc, ext_oath_cfg_cb);
    }

    ziti_get_ext_jwt_signers(ztx, ext_signers_cb, ztx);
    return ZITI_OK;
}

static void internal_link_cb(oidc_client_t *oidc, const char *url, void *ctx) {
    ziti_context ztx = oidc->data;
    ZITI_LOG(INFO, "received link request: %s", url);
    if (ztx->ext_launch_cb) {
        ztx->ext_launch_cb(ztx, url, ztx->ext_launch_ctx);
    }
    ztx->ext_launch_cb = NULL;
    ztx->ext_launch_ctx = NULL;
}

static void ext_token_cb(oidc_client_t *oidc, enum oidc_status status, const char *data) {
    ziti_context ztx = oidc->data;
    switch (status) {
        case OIDC_TOKEN_OK: {
            const char *token = data;
            ZITI_LOG(DEBUG, "received access token: %.*s...", 20, token);
            ztx->auth_method->set_ext_jwt(ztx->auth_method, token);
            ztx->auth_method->start(ztx->auth_method, ztx_auth_state_cb, ztx);
            break;
        }
        case OIDC_RESTART: {
            ziti_event_t ev = {
                    .type = ZitiAuthEvent,
                    .auth = {
                            .type = ziti_auth_query_types.name(ziti_auth_query_type_EXT_JWT),
                            .action = ziti_auth_login_external,
                            .detail = ztx->ext_auth->signer_cfg.name,
                    }
            };
            ziti_send_event(ztx, &ev);
            break;
        }
        default: {
            const char *message = data;
            ZTX_LOG(WARN, "failed to get external authentication token: %d", status);
            char err[256];
            snprintf(err, sizeof(err), "failed to get external auth token: %s", message);
            ztx_auth_state_cb(ztx, ZitiAuthImpossibleToAuthenticate, &(ziti_error) {
                    .err = status,
                    .message = message,
            });
        }
    }
}

extern int ziti_ext_auth(ziti_context ztx,
                         void (*ziti_ext_launch)(ziti_context, const char*, void *), void *ctx) {
    if (ztx->ext_auth == NULL) {
        return ZITI_INVALID_STATE;
    }

    switch (ztx->auth_state) {
        case ZitiAuthStateAuthStarted:
        case ZitiAuthStateFullyAuthenticated:
            return ZITI_INVALID_STATE;
        case ZitiAuthStatePartiallyAuthenticated:
        case ZitiAuthStateUnauthenticated:
        case ZitiAuthImpossibleToAuthenticate:
            break;
    }

    ztx->ext_launch_cb = ziti_ext_launch;
    ztx->ext_launch_ctx = ctx;
    oidc_client_set_link_cb(ztx->ext_auth, internal_link_cb, NULL);
    return oidc_client_start(ztx->ext_auth, ext_token_cb);
}

extern int ziti_ext_auth_token(ziti_context ztx, const char *token) {
    if (ztx->auth_method) {
        ztx->auth_method->set_ext_jwt(ztx->auth_method, token);
        return 0;
    }

    return ZITI_INVALID_STATE;
}