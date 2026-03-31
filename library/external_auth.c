// Copyright (c) 2026.  NetFoundry Inc
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

#include "ext_oidc.h"
#include "zt_internal.h"
#include <assert.h>
#include <ziti/ziti_events.h>

static void ext_token_cb(ext_oidc_client_t *oidc, enum ext_oidc_status status, const void *data);

static void ext_oath_cfg_cb(ext_oidc_client_t *oidc, int status, const char *err) {
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
        NEWP(oidc, ext_oidc_client_t);
        int rc = ext_oidc_client_init(ztx->loop, oidc, oidc_cfg);
        if (rc != ZITI_OK) {
            free(oidc);
            ZTX_LOG(ERROR, "failed to initialize OIDC client: %s", ziti_errorstr(rc));
            return rc;
        }
        oidc->data = ztx;
        ztx->ext_auth = oidc;
        ext_oath_cfg_cb(oidc, 0, NULL);
        return 0;
    }

    return ziti_get_ext_jwt_signers(ztx, ext_signers_cb, ztx);
}

static void internal_link_cb(ext_oidc_client_t *oidc, const char *url, void *ctx) {
    ziti_context ztx = oidc->data;
    ZITI_LOG(INFO, "received link request: %s", url);
    if (ztx->ext_launch_cb) {
        ztx->ext_launch_cb(ztx, url, ztx->ext_launch_ctx);
    }
    ztx->ext_launch_cb = NULL;
    ztx->ext_launch_ctx = NULL;
}

static void ext_token_cb(ext_oidc_client_t *oidc, enum ext_oidc_status status, const void *data) {
    ziti_context ztx = oidc->data;
    enum ziti_auth_action action = ziti_auth_login_external;
    const char *err = NULL;
    switch (status) {
        case EXT_OIDC_TOKEN_OK: {
            ziti_ext_auth_token(ztx, (const char*)data);
            return;
        }
        case EXT_OIDC_CONFIG_FAILED: {
            err = (const char*)data;
            action = ziti_auth_cannot_continue;
            ZTX_LOG(WARN, "failed to configure external signer: %s", err);
            break;
        }
        case EXT_OIDC_RESTART: {
            action = ziti_auth_login_external;
            break;
        }
        case EXT_OIDC_TOKEN_FAILED: {
            action = ziti_auth_cannot_continue;
            err = data;
            ZTX_LOG(WARN, "failed to get external authentication token: %d/%s", status, err);
        }
    }

    if (ztx->auth_state != ZitiAuthStateFullyAuthenticated) {
        ziti_event_t ev = {
            .type = ZitiAuthEvent,
            .auth = {
                .type = ziti_auth_query_types.name(ziti_auth_query_type_EXT_JWT),
                .action = action,
                .error = err,
                .detail = ztx->ext_auth->signer_cfg.name,
            }};
        ziti_send_event(ztx, &ev);
    }
}

extern int ziti_ext_auth(ziti_context ztx,
                         void (*ziti_ext_launch)(ziti_context, const char*, void *), void *ctx) {
    if (ztx->ext_auth == NULL) {
        return ZITI_INVALID_STATE;
    }

    ztx->ext_launch_cb = ziti_ext_launch;
    ztx->ext_launch_ctx = ctx;
    ext_oidc_client_set_link_cb(ztx->ext_auth, internal_link_cb, NULL);
    ext_oidc_client_start(ztx->ext_auth, ext_token_cb);
    return ZITI_OK;
}

static void ztx_on_token_enroll(ziti_enrollment_cert_resp *cert_resp, const ziti_error *error, void *ctx) {
    ziti_context ztx = ctx;
    assert(ztx->auth_method);

    if (error) {
        ZTX_LOG(WARN, "enrollToCert failed: %s", error->message);
        ziti_send_event(ztx, &(ziti_event_t){
                .type = ZitiAuthEvent,
                .auth = {
                        .action = ziti_auth_cannot_continue,
                        .type = "enrollToCert",
                        .error = error->message,
                },
        });
        if (cert_resp) { free_ziti_enrollment_cert_resp_ptr(cert_resp); }
        return;
    }

    ZTX_LOG(DEBUG, "enroll response: cert_resp=%p cert_pem=%s cas_pem=%s",
            cert_resp,
            cert_resp ? (cert_resp->client_cert_pem ? "present" : "NULL") : "N/A",
            cert_resp ? (cert_resp->cas_pem ? "present" : "NULL") : "N/A");

    if (cert_resp && cert_resp->client_cert_pem) {
        ZTX_LOG(INFO, "received client certificate from enrollToCert");

        // store cert in config for persistence
        FREE(ztx->config.id.cert);
        ztx->config.id.cert = strdup(cert_resp->client_cert_pem);

        if (cert_resp->cas_pem) {
            FREE(ztx->config.id.ca);
            ztx->config.id.ca = strdup(cert_resp->cas_pem);
        }

        // store key PEM in config for persistence
        if (ztx->id_creds.key) {
            char *key_pem = NULL;
            size_t key_pem_len = 0;
            if (ztx->id_creds.key->to_pem(ztx->id_creds.key, &key_pem, &key_pem_len) == 0) {
                FREE(ztx->config.id.key);
                ztx->config.id.key = key_pem;
            }
        }

        // load cert into TLS credentials
        if (ztx->tlsCtx->load_cert(&ztx->id_creds.cert,
                                    cert_resp->client_cert_pem,
                                    strlen(cert_resp->client_cert_pem)) != 0) {
            ZTX_LOG(ERROR, "failed to load enrolled certificate");
        } else {
            ztx->tlsCtx->set_own_cert(ztx->tlsCtx, ztx->id_creds.key, ztx->id_creds.cert);
        }

        // notify app to persist the updated config
        ztx_config_update(ztx);
    }

    ztx->auth_method->start(ztx->auth_method, ztx_auth_state_cb, ztx);
    if (cert_resp) { free_ziti_enrollment_cert_resp_ptr(cert_resp); }
}

extern int ziti_ext_auth_token(ziti_context ztx, const char *token) {
    ZTX_LOG(DEBUG, "received access token: %s", jwt_payload(token));
    assert(ztx->auth_method);

    NEWP(jwt, zt_jwt);
    if (zt_jwt_parse(token, jwt) != 0) {
        ZTX_LOG(WARN, "failed to parse JWT token");
        free(jwt);
        return ZITI_JWT_INVALID;
    }
    ZTX_LOG(DEBUG, "received access token: %s", json_object_get_string(jwt->claims));
    zt_jwt *prev = model_map_set(&ztx->ext_jwt_tokens, cstr_str(&jwt->issuer), jwt);
    zt_jwt_drop(prev);
    free(prev);

    ztx->auth_method->set_ext_jwt(ztx->auth_method, token);

    // create identity if needed and allowed
    if (ztx->identity_data == NULL && ztx->id_creds.cert == NULL) {
        ZTX_LOG(INFO, "no credentials present trying just-in-time enrollment");

        char *csr = NULL;
        bool cert_enroll = ztx->ext_auth && ztx->ext_auth->signer_cfg.can_cert_enroll;
        if (cert_enroll) {
            const char *ctrl_ver = ztx_get_controller(ztx)->version.version;
            if (ctrl_ver) {
                const char *vnum = ctrl_ver[0] == 'v' ? ctrl_ver + 1 : ctrl_ver;
                int major = atoi(vnum);
                if (major == 0) {
                    ZTX_LOG(DEBUG, "controller %s is a dev build, assuming enrollToCert support", ctrl_ver);
                } else if (major < 2) {
                    ZTX_LOG(ERROR, "controller %s does not support enrollToCert (requires v2.0+)", ctrl_ver);
                    return ZITI_INVALID_STATE;
                }
            }
            ZTX_LOG(INFO, "enrollToCert enabled, generating CSR");
            if (ztx->id_creds.key == NULL) {
                if (ztx->enroll_key_cb) {
                    char *key_pem = NULL;
                    int rc = ztx->enroll_key_cb(ztx, &key_pem, ztx->enroll_key_ctx);
                    if (rc != ZITI_OK || key_pem == NULL) {
                        ZTX_LOG(ERROR, "enroll_key_cb failed to provide private key");
                        FREE(key_pem);
                        return rc != ZITI_OK ? rc : ZITI_KEY_GENERATION_FAILED;
                    }
                    if (ztx->tlsCtx->load_key(&ztx->id_creds.key, key_pem, strlen(key_pem)) != 0) {
                        ZTX_LOG(ERROR, "failed to load private key from enroll_key_cb");
                        FREE(key_pem);
                        return ZITI_KEY_LOAD_FAILED;
                    }
                    FREE(ztx->config.id.key);
                    ztx->config.id.key = key_pem;
                } else if (ztx->tlsCtx->generate_key(&ztx->id_creds.key) != 0) {
                    ZTX_LOG(ERROR, "failed to generate private key for enrollToCert");
                    return ZITI_KEY_GENERATION_FAILED;
                }
            }
            size_t csr_len = 0;
            if (ztx->tlsCtx->generate_csr_to_pem(ztx->id_creds.key, &csr, &csr_len,
                                                   "O", "OpenZiti",
                                                   "CN", "enrollToCert",
                                                   NULL) != 0) {
                ZTX_LOG(ERROR, "failed to generate CSR for enrollToCert");
                return ZITI_CSR_GENERATION_FAILED;
            }
        }

        ziti_ctrl_enroll_token(ztx_get_controller(ztx), token, csr, ztx_on_token_enroll, ztx);
        free(csr);
        return ZITI_OK;
    }

    if (ztx->auth_state == ZitiAuthStateUnauthenticated) {
        ZTX_LOG(DEBUG, "initiating authentication flow");
        ztx->auth_method->start(ztx->auth_method, ztx_auth_state_cb, ztx);
    }
    return ZITI_OK;
}