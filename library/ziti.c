// Copyright (c) 2022-2024. NetFoundry Inc.
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

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <uv.h>

#include "deadline.h"
#include "oidc.h"
#include "utils.h"
#include "zt_internal.h"
#include "auth_queries.h"


#if _WIN32

#include <windows.h>

#endif

#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#elif _WIN32
#define MAXPATHLEN 260
#else
#define MAXPATHLEN 4096
#endif
#endif

#define ONE_DAY (60 * 60 * 24)

#define ztx_controller(ztx) \
((ztx)->ctrl.url ? (ztx)->ctrl.url : (ztx)->config.controller_url)

int code_to_error(const char *code);

static void version_pre_auth_cb(const ziti_version *version, const ziti_error *err, void *ctx);
static void update_ctrl_status(ziti_context ztx, int code, const char *msg);

static void edge_routers_cb(ziti_edge_router_array ers, const ziti_error *err, void *ctx);

static void ziti_init_async(ziti_context ztx, void *data);

static void ziti_re_auth(ziti_context ztx);

static void ztx_prepare(uv_prepare_t *prep);
static void grim_reaper(ziti_context ztx);

static void ztx_work_async(uv_async_t *ar);

static void ziti_stop_internal(ziti_context ztx, void *data);

static void ziti_start_internal(ziti_context ztx, void *init_req);

static void set_service_posture_policy_map(ziti_service *service);

static void shutdown_and_free(ziti_context ztx);

static void ca_bundle_cb(char *pkcs7, const ziti_error *err, void *ctx);

static void update_identity_data(ziti_identity_data *data, const ziti_error *err, void *ctx);

static void on_create_cert(ziti_create_api_cert_resp *resp, const ziti_error *e, void *ctx);

static int ztx_init_controller(ziti_context ztx);
static void ztx_config_update(ziti_context ztx);

static void api_session_cb(ziti_api_session *, const ziti_error *, void *);

static uint32_t ztx_seq;

struct ztx_req_s {
    struct ziti_ctx *ztx;
    void  (*cb)();
    void *cb_ctx;
};

static const char *all_configs[] = { "all", NULL };

static ziti_options default_options = {
        .disabled = false,
        .config_types = all_configs,
        .refresh_interval = 0,
        .api_page_size = 25,
};

static size_t parse_ref(const char *val, const char **res) {
    size_t len = 0;
    *res = NULL;
    if (val != NULL) {
        if (strncmp("file:", val, 5) == 0) {
            // load file
            struct tlsuv_url_s url;
            tlsuv_parse_url(&url, val);
            size_t start = strlen(val) - strlen(url.path);
            *res = url.path;
            len = url.path_len;
        } else if (strncmp("pem:", val, 4) == 0) {
            // load inline PEM
            *res = val + 4;
            len = strlen(val + 4) + 1;
        } else {
            *res = val;
            len = strlen(val) + 1;
        }
    }
    return len;
}

ziti_controller* ztx_get_controller(ziti_context ztx) {
    return &ztx->ctrl;
}

static int init_tls_from_config(tls_context *tls, ziti_config *cfg, struct tls_credentials *creds) {
    PREP(ziti);

    if (cfg->id.key == NULL) {
        return 0;
    }
    tlsuv_private_key_t pk;

    TRY(ziti, load_key_internal(tls, &pk, cfg->id.key));

    tlsuv_certificate_t c = NULL;
    if (cfg->id.cert) {
        const char *cert;
        size_t cert_len = parse_ref(cfg->id.cert, &cert);
        TRY(ziti, tls->load_cert(&c, cert, cert_len));
    }
    TRY(ziti, tls->set_own_cert(tls, pk, c));

    CATCH(ziti) {
        return ERR(ziti);
    }
    if (creds) {
        if (creds->key) {
            creds->key->free(creds->key);
        }
        if (creds->cert) {
            creds->cert->free(creds->cert);
        }

        creds->key = pk;
        creds->cert = c;
    }
    return ZITI_OK;
}

int load_tls(ziti_config *cfg, tls_context **ctx, struct tls_credentials *creds) {

    // load ca from ziti config if present
    const char *ca;
    size_t ca_len = parse_ref(cfg->id.ca, &ca);
    tls_context *tls = default_tls_context(ca, ca_len);
    if (tls->allow_partial_chain) {
        tls->allow_partial_chain(tls, true);
    }

    int rc = ZITI_OK;
    if (cfg->id.key != NULL) {
        rc = init_tls_from_config(tls, cfg, creds);
    }

    if (rc == ZITI_OK) {
        *ctx = tls;
    } else {
        tls->free_ctx(tls);
        *ctx = NULL;
    }
    return rc;
}

int ziti_set_client_cert(ziti_context ztx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len) {
    tlsuv_private_key_t pk;
    tlsuv_certificate_t c;
    if (ztx->tlsCtx->load_key(&pk, key_buf, key_len)) {
        return ZITI_KEY_LOAD_FAILED;
    }

    if (ztx->tlsCtx->load_cert(&c, cert_buf, cert_len)) {
        pk->free(pk);
        return ZITI_INVALID_AUTHENTICATOR_CERT;
    }

    if (ztx->tlsCtx->set_own_cert(ztx->tlsCtx, pk, c)) {
        return ZITI_INVALID_CERT_KEY_PAIR;
    }

    return ZITI_OK;
}

extern bool ziti_is_enabled(ziti_context ztx) {
    return ztx->enabled;
}

extern void ziti_set_enabled(ziti_context ztx, bool enabled) {
    ziti_queue_work(ztx, enabled ? ziti_start_internal : ziti_stop_internal, NULL);
}

void ziti_set_auth_started(ziti_context ztx) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->auth_state, ZitiAuthStateAuthStarted);
    FREE(ztx->session_token);
}

void ziti_set_unauthenticated(ziti_context ztx, const ziti_error *err) {
    if (err) {
        ZITI_LOG(WARN, "auth error: %s", err->message);
    }

    ZTX_LOG(DEBUG, "setting auth_state[%d] to %d", ztx->auth_state, ZitiAuthStateUnauthenticated);
    ztx->auth_state = ZitiAuthStateUnauthenticated;
    FREE(ztx->session_token);

    if (ztx->session_creds.cert || ztx->session_creds.key) {
        if (ztx->tlsCtx) {
            ztx->tlsCtx->set_own_cert(ztx->tlsCtx, NULL, NULL);
        }

        if (ztx->session_creds.cert) {
            ztx->session_creds.cert->free(ztx->session_creds.cert);
            ztx->session_creds.cert = NULL;
        }

        if (ztx->session_creds.key) {
            ztx->session_creds.key->free(ztx->session_creds.key);
            ztx->session_creds.key = NULL;
        }
        init_tls_from_config(ztx->tlsCtx, &ztx->config, &ztx->id_creds);
    }

    model_map_clear(&ztx->sessions, (void (*)(void *)) free_ziti_session_ptr);

    ziti_ctrl_clear_api_session(ztx_get_controller(ztx));

    if (err && !ztx->closing) {
        ziti_send_event(ztx, &(ziti_event_t) {
                .type = ZitiContextEvent,
                .ctx = (struct ziti_context_event) {
                        .err = err->message,
                        .ctrl_status = (int) err->err,
                },
        });
    }
}

void ziti_set_impossible_to_authenticate(ziti_context ztx, const ziti_error *err) {
    if (err->err == UV_ECONNREFUSED) {
        if (ztx->auth_method->set_endpoint &&
            ztx->auth_method->set_endpoint(ztx->auth_method, ztx_controller(ztx)) == 0) {
            ZTX_LOG(DEBUG, "updating internal OIDC endpoint[%s]", ztx_controller(ztx));
            return;
        }
    }

    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->auth_state, ZitiAuthImpossibleToAuthenticate);
    FREE(ztx->session_token);
    ziti_ctrl_clear_api_session(ztx_get_controller(ztx));
    ziti_send_event(ztx, &(ziti_event_t){
        .type = ZitiContextEvent,
        .ctx = (struct ziti_context_event){
                .ctrl_status = ZITI_AUTHENTICATION_FAILED,
                .err = err->message,
        }
    });
}

void ziti_set_partially_authenticated(ziti_context ztx, const ziti_auth_query_mfa *mfa_q) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->auth_state, ZitiAuthStatePartiallyAuthenticated);
    update_ctrl_status(ztx, ZITI_PARTIALLY_AUTHENTICATED, NULL);

    ziti_event_t ev = {
            .type = ZitiAuthEvent,
            .auth = {
                    .type = ziti_auth_query_types.name(mfa_q->type_id),
            }
    };
    switch (mfa_q->type_id) {
        case ziti_auth_query_type_MFA:
        case ziti_auth_query_type_TOTP:
            ev.auth.action = ziti_auth_prompt_totp;
            ev.auth.detail = mfa_q->provider;
            break;
        case ziti_auth_query_type_EXT_JWT: {
            const char *name;
            ziti_jwt_signer *signer;
            MODEL_MAP_FOREACH(name, signer, &ztx->ext_signers) {
                if (strcmp(mfa_q->id, signer->id) == 0) {
                    break;
                }
            }
            if (signer == NULL) {
                ZTX_LOG(ERROR, "cannot continue auth: signer with id[%s] not found", mfa_q->id);
                ev.auth.action = ziti_auth_cannot_continue;
                ev.auth.detail = "signer not found";
            } else {
                ztx_init_external_auth(ztx, signer);
                ev.auth.action = ziti_auth_login_external;
                ev.auth.detail = signer->name;
            }
            break;
        }
        case ziti_auth_query_type_Unknown:
        default:
            ev.auth.action = ziti_auth_cannot_continue;
            ev.auth.detail = "unsupported secondary auth method";
            break;
    }

    ziti_send_event(ztx, &ev);
}

static void ctrl_list_cb(ziti_controller_detail_array ctrls, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    if (err) {
        ZTX_LOG(WARN, "failed to list HA controllers %s/%s", err->code, err->message);
        return;
    }
    
    const char *url;
    model_map diff = {};
    MODEL_LIST_FOREACH(url, ztx->config.controllers) {
        model_map_set(&diff, url, url);
    }
    model_list_clear(&ztx->config.controllers, NULL);

    model_map old_details = ztx->ctrl_details;
    ztx->ctrl_details = (model_map){};

    bool changed = false;
    for (int i = 0; ctrls[i] != NULL; i++) {
        ziti_controller_detail *detail = ctrls[i];
        const api_address *edge_api = model_list_head(&detail->apis.edge);

        if (edge_api && edge_api->url) {
            ZTX_LOG(INFO, "controller[%s/%s] url[%s]", detail->name, detail->id, edge_api->url);

            model_map_set(&ztx->ctrl_details, detail->id, detail);

            char *old_url = model_map_remove(&diff, edge_api->url);
            if (old_url == NULL) {
                changed = true;
            } else {
                free(old_url);
            }

            model_list_append(&ztx->config.controllers, strdup(edge_api->url));
        } else {
            ZTX_LOG(INFO, "controller[%s/%s]: no Edge API", detail->name, detail->id);
            free_ziti_controller_detail_ptr(detail);
        }
    }
    changed = changed || (model_map_size(&diff) > 0);

    if (changed) {
        ztx_config_update(ztx);
    }

    model_map_clear(&diff, free);
    model_map_clear(&old_details, (void (*)(void *)) free_ziti_controller_detail_ptr);
    free(ctrls);
}

void ziti_set_fully_authenticated(ziti_context ztx, const char *session_token) {
    assert(session_token);
    ZTX_LOG(DEBUG, "setting auth_state[%d] to %d",
            ztx->auth_state, ZitiAuthStateFullyAuthenticated);
    ztx->auth_state = ZitiAuthStateFullyAuthenticated;

    if (ztx->session_token == NULL || strcmp(ztx->session_token, session_token) != 0) {
        free(ztx->session_token);
        ztx->session_token = strdup(session_token);
    }
    ziti_controller *ctrl = ztx_get_controller(ztx);
    if (ztx->auth_method->kind == HA) {
        ziti_ctrl_set_token(ztx_get_controller(ztx), session_token);
        ziti_ctrl_list_controllers(ctrl, ctrl_list_cb, ztx);

        const char* er_name;
        ziti_channel_t *ch;
        MODEL_MAP_FOREACH(er_name, ch, &ztx->channels) {
            ziti_channel_update_token(ch, session_token);
        }
    }
    ziti_ctrl_get_well_known_certs(ctrl, ca_bundle_cb, ztx);
    ziti_ctrl_current_api_session(ctrl, api_session_cb, ztx);
    ziti_ctrl_current_identity(ctrl, update_identity_data, ztx);

    tlsuv_private_key_t pk;
    if (ztx->id_creds.key == NULL) {
        if (ztx->session_creds.key == NULL) {
            ztx->tlsCtx->generate_key(&ztx->session_creds.key);
        }
        pk = ztx->session_creds.key;
    } else {
        pk = ztx->id_creds.key;
    }

    if (ztx->id_creds.cert == NULL && ztx->session_creds.cert == NULL) {
        char common_name[128];
        snprintf(common_name, sizeof(common_name), "%s-%u-%" PRIu64,
                 APP_ID ? APP_ID : "ziti-sdk-c",
                 ztx->id, uv_now(ztx->loop));

        size_t csr_len;
        ztx->tlsCtx->generate_csr_to_pem(pk, &ztx->sessionCsr, &csr_len,
                                         "O", "OpenZiti",
                                         "OU", "ziti-sdk",
                                         "CN", common_name,
                                         NULL);

        ziti_ctrl_create_api_certificate(ztx_get_controller(ztx), ztx->sessionCsr, on_create_cert, ztx);
    }

    ziti_services_refresh(ztx, true);
    ziti_posture_init(ztx, 20);
}

void ziti_force_api_session_refresh(ziti_context ztx) {
    ZTX_LOG(DEBUG, "forcing session refresh");
    ztx->auth_method->force_refresh(ztx->auth_method);
}

const char* ziti_get_api_session_token(ziti_context ztx) {
    if (ztx->auth_state == ZitiAuthStateFullyAuthenticated) {
        return ztx->session_token;
    }
    return NULL;
}

static void ziti_stop_internal(ziti_context ztx, void *data) {
    if (ztx->enabled) {
        ZTX_LOG(INFO, "disabling Ziti Context");

        metrics_rate_close(&ztx->up_rate);
        metrics_rate_close(&ztx->down_rate);

        if (ztx->auth_method) {
            ztx->auth_method->stop(ztx->auth_method);
        }

        // stop updates
        clear_deadline(&ztx->refresh_deadline);

        if (ztx->posture_checks) {
            ziti_posture_checks_free(ztx->posture_checks);
            ztx->posture_checks = NULL;
        }

        model_map_clear(&ztx->sessions, (void (*)(void *)) free_ziti_session_ptr);

        // close all channels
        ziti_close_channels(ztx, ZITI_DISABLED);

        FREE(ztx->last_update);
        const char *svc_name;
        ziti_service *svc;
        ziti_event_t ev = {0};
        ev.type = ZitiServiceEvent;
        ev.service.removed = calloc(model_map_size(&ztx->services) + 1, sizeof(ziti_service *));
        int idx = 0;
        model_map_iter it = model_map_iterator(&ztx->services);
        while (it) {
            ev.service.removed[idx++] = model_map_it_value(it);
            it = model_map_it_remove(it);
        }

        if (ztx->auth_method) {
            ztx->auth_method->free(ztx->auth_method);
            ztx->auth_method = NULL;
        }

        if (ztx->ext_auth) {
            oidc_client_close(ztx->ext_auth, (oidc_close_cb) free);
            ztx->ext_auth = NULL;
        }

        ziti_send_event(ztx, &ev);
        free_ziti_service_array(&ev.service.removed);

        ziti_ctrl_cancel(ztx_get_controller(ztx));
        // logout
        ziti_ctrl_clear_api_session(ztx_get_controller(ztx));
        update_ctrl_status(ztx, ZITI_DISABLED, ziti_errorstr(ZITI_DISABLED));
        ztx->enabled = false;
    }
}

static void ziti_start_internal(ziti_context ztx, void *init_req) {
    if (!ztx->enabled) {
        ZTX_LOG(INFO, "enabling Ziti Context");
        ztx->enabled = true;

        int rc = load_tls(&ztx->config, &ztx->tlsCtx, &ztx->id_creds);
        if (rc != 0) {
            ZITI_LOG(ERROR, "invalid TLS config: %s", ziti_errorstr(rc));
            ziti_event_t ev = {
                    .type = ZitiContextEvent,
                    .ctx = {
                        .ctrl_status = rc,
                    }
            };
            ziti_send_event(ztx, &ev);
            return;
        }

        ZTX_LOG(INFO, "using tlsuv[%s/%s]", tlsuv_version(),
                ztx->tlsCtx->version ? ztx->tlsCtx->version() : "unspecified");

        rc = ztx_init_controller(ztx);
        if (rc != ZITI_OK) {
            ztx->enabled = false;
            return;
        }

        ZTX_LOG(DEBUG, "using metrics interval: %d", (int) ztx->opts.metrics_type);
        metrics_rate_init(&ztx->up_rate, ztx->opts.metrics_type);
        metrics_rate_init(&ztx->down_rate, ztx->opts.metrics_type);

        uv_prepare_start(&ztx->prepper, ztx_prepare);
        ztx->start = uv_now(ztx->loop);
        ziti_set_unauthenticated(ztx, NULL);

        ziti_re_auth(ztx);
    }
}

static void on_ctrl_list_change(ziti_context ztx, const model_map *endpoints) {
    if (ztx->opts.event_cb && (ztx->opts.events & ZitiContextEvent)) {
        size_t count = model_map_size(endpoints);
        struct ctrl_detail_s *details = (count > 0) ? calloc(count, sizeof(struct ctrl_detail_s)) : NULL;
        size_t idx = 0;
        const char *url;
        ziti_controller_detail *d;
        MODEL_MAP_FOREACH(url, d, endpoints) {
            details[idx].url = url;
            details[idx].id = d->id;
            details[idx].online = d->is_online;
            idx++;
        }
        ziti_send_event(ztx, &(ziti_event_t){
            .type = ZitiContextEvent,
            .ctx = {
                    .err = NULL,
                    .ctrl_count = count,
                    .ctrl_details = details,
            },
        });

        free(details);
    }
}

static void on_ctrl_redirect(const char *new_addr, void *ctx) {
    ziti_context ztx = ctx;

    model_list_iter it = model_list_iterator(&ztx->config.controllers);
    while(it) {
        char *addr = (char*)model_list_it_element(it);
        if (strcasecmp(addr, ztx->config.controller_url) == 0) {
            it = model_list_it_remove(it);
            free(addr);
        }
    }
    FREE(ztx->config.controller_url);
    ztx->config.controller_url = strdup(new_addr);
    model_list_append(&ztx->config.controllers, strdup(new_addr));
    
    ztx_config_update(ztx);
}

static int ztx_init_controller(ziti_context ztx) {
    ziti_event_t ev = {
            .type = ZitiContextEvent,
    };

    int rc = ziti_ctrl_init(ztx->loop, &ztx->ctrl, &ztx->config.controllers, ztx->tlsCtx);
    if (rc != 0) {
        ZITI_LOG(ERROR, "no valid controllers found");
        ev.ctx.ctrl_status = rc;
        ziti_send_event(ztx, &ev);
        return ZITI_INVALID_CONFIG;
    }

    ZTX_LOG(INFO, "Loading ziti context with controller[%s]", ztx_controller(ztx));
    ziti_ctrl_set_callbacks(ztx_get_controller(ztx), ztx, on_ctrl_redirect,
                            (ziti_ctrl_change_cb) on_ctrl_list_change);
    if (ztx->opts.api_page_size != 0) {
        ziti_ctrl_set_page_size(ztx_get_controller(ztx), ztx->opts.api_page_size);
    }
    return 0;
}

static void ziti_init_async(ziti_context ztx, void *data) {
    ztx->id = ztx_seq++;
    uv_loop_t *loop = ztx->w_async.loop;
    
    uv_prepare_init(loop, &ztx->prepper);
    ztx->prepper.data = ztx;
    uv_unref((uv_handle_t *) &ztx->prepper);

    metrics_init(5, (time_fn)uv_now, loop);

    if (!ztx->opts.disabled) {
        ziti_start_internal(ztx, NULL);
    } else {
        ziti_event_t ev = {
                .type = ZitiContextEvent,
                .ctx = {
                        .ctrl_status = ZITI_DISABLED,
                }
        };
        ziti_send_event(ztx, &ev);
    }
}

static void ext_jwt_singers_cb(ziti_jwt_signer_array signers, const ziti_error *err, void *ctx) {
    struct ztx_req_s *req = ctx;

    struct ziti_ctx *ztx = req->ztx;
    ziti_ext_signers_cb cb = (ziti_ext_signers_cb) req->cb;
    if (err) {
        ZTX_LOG(WARN, "failed to get external auth providers: %s", err->message);
        CALL_CB(cb, ztx, (int)err->err, NULL, req->cb_ctx);
    } else {
        model_map_clear(&ztx->ext_signers, (void (*)(void *)) free_ziti_jwt_signer_ptr);
        ziti_jwt_signer *s;
        FOR(s, signers) {
            if (s->provider_url && s->client_id) {
                model_map_set(&ztx->ext_signers, s->name, s);
            } else {
                ZTX_LOG(INFO, "ext signer[%s] cannot be used: provider_url and client_id are required", s->name);
                free_ziti_jwt_signer_ptr(s);
            }
        }
        int idx = 0;
        const char *n;
        MODEL_MAP_FOREACH(n, s, &ztx->ext_signers) {
            signers[idx++] = s;
        }
        signers[idx] = NULL;

        ZTX_LOG(DEBUG, "%zd external auth providers available", model_map_size(&ztx->ext_signers));
        CALL_CB(cb, ztx, ZITI_OK, signers, req->cb_ctx);
        free(signers);
    }
    free(req);
}

int ziti_get_ext_jwt_signers(ziti_context ztx, ziti_ext_signers_cb cb, void *ctx) {
    NEWP(req, struct ztx_req_s);
    req->ztx = ztx;
    req->cb = cb;
    req->cb_ctx = ctx;

    ziti_ctrl_list_ext_jwt_signers(ztx_get_controller(ztx), ext_jwt_singers_cb, req);
    return ZITI_OK;
}

int ziti_use_ext_jwt_signer(ziti_context ztx, const char *name) {
    if (ztx == NULL || name == NULL) {
        return ZITI_INVALID_STATE;
    }

    const ziti_jwt_signer *signer = model_map_get(&ztx->ext_signers, name);
    if (signer == NULL) {
        return ZITI_NOT_FOUND;
    }

    if (signer->provider_url == NULL) {
        ZTX_LOG(WARN, "OIDC provider[%s] configuration is missing auth URL", name);
        return ZITI_INVALID_CONFIG;
    }

    if (signer->client_id == NULL) {
        ZTX_LOG(WARN, "OIDC provider[%s] configuration is missing client ID", name);
        return ZITI_INVALID_CONFIG;
    }

    if (ztx->ext_auth) {
        ZTX_LOG(INFO, "clearing up previous OIDC provider");
        oidc_client_close(ztx->ext_auth, (oidc_close_cb) free);
        ztx->ext_auth = NULL;
    }

    return ztx_init_external_auth(ztx, signer);
}

void *ziti_app_ctx(ziti_context ztx) {
    return ztx->opts.app_ctx;
}

const char *ziti_get_controller(ziti_context ztx) {
    return ztx_get_controller(ztx)->url;
}

const ziti_version *ziti_get_controller_version(ziti_context ztx) {
    return &ztx_get_controller(ztx)->version;
}

const ziti_identity *ziti_get_identity(ziti_context ztx) {
    if (ztx->identity_data) {
        return (const ziti_identity *) ztx->identity_data;
    }

    return NULL;
}

int ziti_get_transfer_rates(ziti_context ztx, double *up, double *down) {
    if (!ztx->enabled) return ZITI_DISABLED;

    return metrics_rate_get(&ztx->up_rate, up) || metrics_rate_get(&ztx->down_rate, down);
}

static void free_ztx(uv_handle_t *h) {
    ziti_context ztx = h->data;

    model_map_clear(&ztx->ext_signers, (_free_f)free_ziti_jwt_signer_ptr);
    model_map_clear(&ztx->ctrl_details, (_free_f) free_ziti_controller_detail_ptr);
    ziti_auth_query_free(ztx->auth_queries);
    ziti_posture_checks_free(ztx->posture_checks);
    model_map_clear(&ztx->services, (_free_f) free_ziti_service_ptr);
    model_map_clear(&ztx->sessions, (_free_f) free_ziti_session_ptr);
    ziti_set_unauthenticated(ztx, NULL);
    free_ziti_identity_data(ztx->identity_data);
    FREE(ztx->identity_data);
    FREE(ztx->last_update);
    FREE(ztx->session_token);

    ziti_ctrl_close(ztx_get_controller(ztx));
    if (ztx->tlsCtx) ztx->tlsCtx->free_ctx(ztx->tlsCtx);
    if (ztx->id_creds.cert) {
        ztx->id_creds.cert->free(ztx->id_creds.cert);
    }
    if (ztx->id_creds.key) {
        ztx->id_creds.key->free(ztx->id_creds.key);
    }

    free_ziti_config(&ztx->config);

    ziti_event_t ev = {0};
    ev.type = ZitiContextEvent;
    ev.ctx.ctrl_status = ZITI_DISABLED;
    ev.ctx.err = ziti_errorstr(ZITI_DISABLED);

    ziti_send_event(ztx, &ev);


    ZTX_LOG(INFO, "shutdown is complete\n");
    free(ztx);
}

static void shutdown_and_free(ziti_context ztx) {
    if (model_map_size(&ztx->channels) > 0) {
        ZTX_LOG(INFO, "waiting for %zd channels to disconnect", model_map_size(&ztx->channels));
        return;
    }

    grim_reaper(ztx);

    if (ztx->tlsCtx) {
        ztx->tlsCtx->free_ctx(ztx->tlsCtx);
        ztx->tlsCtx = NULL;
    }

    // N.B.: libuv processes close callbacks in reverse order
    // so we put the free on the first uv_close()
    uv_close((uv_handle_t *) &ztx->w_async, free_ztx);
    uv_close((uv_handle_t *)&ztx->deadline_timer, NULL);
    uv_close((uv_handle_t *)&ztx->prepper, NULL);
}

int ziti_shutdown(ziti_context ztx) {
    ZTX_LOG(INFO, "Ziti is shutting down");
    ztx->closing = true;

    ziti_queue_work(ztx, ziti_stop_internal, NULL);

    return ZITI_OK;
}

const char *ziti_get_appdata_raw(ziti_context ztx, const char *key) {
    if (ztx->identity_data == NULL) return NULL;

    return model_map_get(&ztx->identity_data->app_data, key);
}

int ziti_get_appdata(ziti_context ztx, const char *key, void *data,
                     int (*parse_func)(void *, const char *, size_t)) {
    const char *app_data_json = ziti_get_appdata_raw(ztx, key);

    if (app_data_json == NULL) return ZITI_NOT_FOUND;

    if (parse_func(data, app_data_json, strlen(app_data_json)) < 0) {
        return ZITI_INVALID_CONFIG;
    }

    return ZITI_OK;
}


void ziti_dump(ziti_context ztx, int (*printer)(void *arg, const char *fmt, ...), void *ctx) {
    uint64_t now = uv_now(ztx->loop);
    printer(ctx, "\n======= Application Info ==========\n");
    printer(ctx, "Application:\t%s@%s\n", APP_ID ? APP_ID : "<unset>", APP_VERSION ? APP_VERSION : "<unknown>");
    const ziti_version *sdk_ver = ziti_get_version();
    printer(ctx, "ziti-sdk: %s(%s) %s\n", sdk_ver->version, sdk_ver->revision, sdk_ver->build_date);
    printer(ctx, "tlsuv:    %s (%s)\n", tlsuv_version(), ztx->tlsCtx ? ztx->tlsCtx->version() : "<unknown>");
    printer(ctx, "sodium:   %s\n", sodium_version_string());
    printer(ctx, "libuv:    %s\n", uv_version_string());

    printer(ctx, "\n======= Env Info ==========\n");
    const ziti_env_info *info = get_env_info();
    printer(ctx, "OS/arch:  %s %s (%s/%s)\n", info->os, info->arch, info->os_release, info->os_version);
    printer(ctx, "Hostname: %s/%s\n", info->hostname, info->domain);

    printer(ctx, "\n=================\nZiti Context:\n");
    printer(ctx, "ID:\t%d\n", ztx->id);
    if (ziti_is_enabled(ztx)) {
        printer(ctx, "enabled[true] uptime[%" PRIu64 "s]\n", (now -  ztx->start)/1000);
    } else {
        printer(ctx, "enabled[false]");
    }
    printer(ctx, "Config Source:\t%s\n", ztx->config.cfg_source ? ztx->config.cfg_source : "(none)");

    printer(ctx, "Controller%s:\t[%s] %s\n", ztx->ctrl.is_ha ? "[HA]" : "", ztx->ctrl.version.version, ztx_controller(ztx));
    if (ztx->ctrl.is_ha) {
        const char *url;
        ziti_controller_detail *detail;
        MODEL_MAP_FOREACH(url, detail, &ztx->ctrl.endpoints) {
            printer(ctx, "\t%s: online[%c] %s\n", detail->id, detail->is_online ? 'Y' : 'N', url);
        }
    }
    printer(ctx, "Config types:\n");
    for (int i = 0; ztx->opts.config_types && ztx->opts.config_types[i]; i++) {
        printer(ctx, "\t%s\n", ztx->opts.config_types[i]);
    }
    printer(ctx, "Identity:\t");
    if (ztx->identity_data) {
        printer(ctx, "%s[%s]\n", ztx->identity_data->name, ztx->identity_data->id);
    } else {
        printer(ctx, "unknown - never logged in\n");
    }

    printer(ctx, "\n=================\nAPI Session:\n");

    if (ztx->auth_method) {
        printer(ctx, "Session Info: \nauth_method[%s]\napi_session_state[%d]\n",
                ztx->auth_method->kind == HA ? "HA" : "Legacy",
                ztx->auth_state);
    } else {
        printer(ctx, "No Session found\n");
    }

    printer(ctx, "\n=================\nServices:\n");
    ziti_service *zs;
    const char *name;
    const char *cfg;
    const char *cfg_json;

    const char *pq_set_id;
    const ziti_posture_query_set *pq_set;
    const ziti_posture_query *pq;

    MODEL_MAP_FOREACH(name, zs, &ztx->services) {

        printer(ctx, "%s: id[%s] perm(dial=%s,bind=%s)\n", zs->name, zs->id,
                (zs->perm_flags & ZITI_CAN_DIAL ? "true" : "false"),
                (zs->perm_flags & ZITI_CAN_BIND ? "true" : "false")
        );

        MODEL_MAP_FOREACH(cfg, cfg_json, &zs->config) {
            printer(ctx, "\tconfig[%s]=%s\n", cfg, cfg_json);
        }

        printer(ctx, "\tposture queries[%d]:", model_map_size(&zs->posture_query_map));
        MODEL_MAP_FOREACH(pq_set_id, pq_set, &zs->posture_query_map) {
            printer(ctx, "\t\tposture query set[%s]\n", pq_set_id);

            for (int idx = 0; pq_set->posture_queries[idx] != NULL; idx++) {
                pq = pq_set->posture_queries[idx];
                printer(ctx, "\t\t\tquery_id[%s] type[%s] is_passing[%s] timeout[%d] timeoutRemaining[%d]\n",
                        pq->id, ziti_posture_query_types.name(pq->query_type),
                        pq->is_passing ? "true" : "false", pq->timeout, *pq->timeoutRemaining);
            }
        }
    }

    printer(ctx, "\n==================\nSessions:\n");
    ziti_session *sess;
    MODEL_MAP_FOREACH(name, sess, &ztx->sessions) {
        printer(ctx, "%s: service_id[%s]\n", sess->id, name);
    }

    printer(ctx, "\n==================\nChannels:\n");
    ziti_channel_t *ch;
    const char *er_id;
    MODEL_MAP_FOREACH(er_id, ch, &ztx->channels) {
        printer(ctx, "ch[%d] %s\n", ch->id, ch->name);
        printer(ctx, "\tconnected[%c] version[%s] address[%s]",
                ziti_channel_is_connected(ch) ? 'Y' : 'N', ch->version, ch->url);
        if (ziti_channel_is_connected(ch)) {
            printer(ctx, " latency[%" PRIu64 "]\n", ziti_channel_latency(ch));
        } else {
            printer(ctx, "\n");
        }
    }

    printer(ctx, "\n==================\n"
                 "Connections:\n");
    ziti_connection conn;
    const char *id;
    char bridge_info[128];
    MODEL_MAP_FOREACH(id, conn, &ztx->connections) {

        if (conn->type == Transport && conn->parent == NULL) {
            printer(ctx, "conn[%d/%s]: state[%s] service[%s] using ch[%d/%s]\n",
                    conn->conn_id, conn->marker, ziti_conn_state(conn), conn->service,
                    FIELD_OR_ELSE(conn->channel, id, -1),
                    FIELD_OR_ELSE(conn->channel, name, "(none)")
            );
            printer(ctx, "\tconnect_time[%" PRIu64 "] idle_time[%" PRIu64 "] "
                         "sent[%" PRIu64 "] recv[%" PRIu64 "] recv_buff[%" PRIu64 "]\n",
                    conn->connect_time, now - conn->last_activity, conn->sent, conn->received,
                    buffer_available(conn->inbound));

            if (conn_bridge_info(conn, bridge_info, sizeof(bridge_info)) == ZITI_OK) {
                printer(ctx, "\tbridge: %s\n", bridge_info);
            }
        }

        if (conn->type == Server) {
            printer(ctx, "conn[%d]: server service[%s] terminators[%ld]\n",
                    conn->conn_id, conn->service, model_map_size(&conn->server.bindings));
            const char *n;
            void *b;
            MODEL_MAP_FOREACH(n, b, &conn->server.bindings) {
                printer(ctx, "\t binding[%s]\n", n);
            }

            model_map_iter it = model_map_iterator(&conn->server.children);
            while (it != NULL) {
                uint32_t child_id = model_map_it_lkey(it);
                ziti_connection child = model_map_it_value(it);
                printer(ctx, "\tchild[%d/%s]: state[%s] caller_id[%s] ch[%d/%s]\n",
                        child_id, child->marker, ziti_conn_state(child), ziti_conn_source_identity(child),
                        FIELD_OR_ELSE(child->channel, id, -1),
                        FIELD_OR_ELSE(child->channel, name, "(none)")
                );
                printer(ctx, "\t\taccept_time[%" PRIu64 "] idle_time[%" PRIu64 "] "
                             "sent[%" PRIu64 "] recv[%" PRIu64 "] recv_buff[%" PRIu64 "]\n",
                        child->connect_time, now - child->last_activity, child->sent, child->received,
                        buffer_available(child->inbound));
                if (conn_bridge_info(child, bridge_info, sizeof(bridge_info)) == ZITI_OK) {
                    printer(ctx, "\t\tbridge: %s\n", bridge_info);
                }
                it = model_map_it_next(it);
            }
        }
    }
    printer(ctx, "\n==================\n\n");
}

int ziti_conn_init(ziti_context ztx, ziti_connection *conn, void *data) {
    struct ziti_ctx *ctx = ztx;
    NEWP(c, struct ziti_conn);
    c->ziti_ctx = ztx;
    c->data = data;
    c->conn_id = ztx->conn_seq++;
    c->rt_conn_id = c->conn_id;

    *conn = c;
    model_map_setl(&ctx->connections, (long) c->conn_id, c);
    return ZITI_OK;
}

void *ziti_conn_data(ziti_connection conn) {
    return conn != NULL ? conn->data : NULL;
}

void ziti_conn_set_data(ziti_connection conn, void *data) {
    if (conn != NULL) {
        conn->data = data;
    }
}

const char *ziti_conn_source_identity(ziti_connection conn) {
    return conn != NULL ? conn->source_identity : NULL;
}


void ziti_send_event(ziti_context ztx, const ziti_event_t *e) {
    if (ztx->opts.events & e->type) {
        CALL_CB(ztx->opts.event_cb, ztx, e);
    }
}

void ztx_config_update(ziti_context ztx) {
    ziti_send_event(ztx, &(ziti_event_t){
            .type = ZitiConfigEvent,
            .cfg = {
                    .config = &ztx->config,
            }
    });
}

static void set_service_flags(ziti_service *s) {
    for (int i = 0; s->permissions[i] != NULL; i++) {
        if (*s->permissions[i] == ziti_session_types.Dial) {
            s->perm_flags |= ZITI_CAN_DIAL;
        }
        if (*s->permissions[i] == ziti_session_types.Bind) {
            s->perm_flags |= ZITI_CAN_BIND;
        }
    }
}

static void service_cb(ziti_service *s, const ziti_error *err, void *ctx) {
    struct ztx_req_s *req = ctx;
    int rc = ZITI_SERVICE_UNAVAILABLE;

    if (s != NULL) {
        set_service_flags(s);
        ziti_service *old = model_map_set(&req->ztx->services, s->name, s);
        free_ziti_service_ptr(old);
        rc = ZITI_OK;
    } else {
        if (err) {
            rc = (int)err->err;
        }
    }

    CALL_CB((ziti_service_cb)req->cb, req->ztx, s, rc, req->cb_ctx);
    free(req);
}

int ziti_service_available(ziti_context ztx, const char *service, ziti_service_cb cb, void *ctx) {
    if (!ztx->enabled) return ZITI_DISABLED;

    ziti_service *s = model_map_get(&ztx->services, service);
    if (s != NULL) {
        cb(ztx, s, ZITI_OK, ctx);
        return ZITI_OK;
    }

    NEWP(req, struct ztx_req_s);
    req->ztx = ztx;
    req->cb = cb;
    req->cb_ctx = ctx;

    ziti_ctrl_get_service(ztx_get_controller(ztx), service, service_cb, req);
    return ZITI_OK;
}

static void term_cb(ziti_terminator_array terminators, const ziti_error *err, void *ctx) {
    struct ztx_req_s *r = ctx;
    CALL_CB((ziti_terminator_cb)r->cb, r->ztx, (const ziti_terminator * const *) terminators,
            err ? err->err : ZITI_OK, r->cb_ctx);
    free_ziti_terminator_array(&terminators);
    free(r);
}

static void term_srv_cb(ziti_context ztx, const ziti_service *s, int err, void *ctx) {
    struct ztx_req_s *req = ctx;
    if (err || s == NULL) {
        CALL_CB((ziti_terminator_cb)req->cb, req->ztx, NULL,
                err ? err : ZITI_SERVICE_UNAVAILABLE , req->cb_ctx);
        free(req);
        return;
    }

    ziti_ctrl_list_terminators(ztx_get_controller(req->ztx), s->id, term_cb, req);
}

int ziti_list_terminators(ziti_context ztx, const char *service, ziti_terminator_cb cb, void *ctx) {
    NEWP(req, struct ztx_req_s);
    req->ztx = ztx;
    req->cb = cb;
    req->cb_ctx = ctx;

    return ziti_service_available(ztx, service, term_srv_cb, req);
}

const ziti_service *ziti_service_for_addr_str(ziti_context ztx, ziti_protocol proto, const char *addr, int port) {
    ziti_address a;
    if (parse_ziti_address_str(&a, addr) != -1) {
        return ziti_service_for_addr(ztx, proto, &a, port);
    }
    ZITI_LOG(WARN, "invalid address host[%s]", addr);
    return NULL;
}

const ziti_service *ziti_service_for_addr(ziti_context ztx, ziti_protocol proto, const ziti_address *addr, int port) {
    int best_score = -1;
    ziti_service *best = NULL;

    ziti_service *srv;
    const char *name;
    MODEL_MAP_FOREACH(name, srv, &ztx->services) {
        ziti_intercept_cfg_v1 intercept = {0};
        ziti_client_cfg_v1 clt_cfg = {0};
        if (ziti_service_get_config(srv, ZITI_INTERCEPT_CFG_V1, &intercept, (parse_service_cfg_f) parse_ziti_intercept_cfg_v1) == ZITI_OK ||
                (ziti_service_get_config(srv, ZITI_CLIENT_CFG_V1, &clt_cfg, (parse_service_cfg_f) parse_ziti_client_cfg_v1) == ZITI_OK &&
                 ziti_intercept_from_client_cfg(&intercept, &clt_cfg) == ZITI_OK
                )
        ) {
            int match = ziti_intercept_match2(&intercept, proto, addr, port);

            if (match == -1) { continue; }

            // best possible match
            if (match == 0) { return srv; }

            if (best_score == -1 || best_score > match) {
                best_score = match;
                best = srv;
            }
        }
        free_ziti_intercept_cfg_v1(&intercept);
        free_ziti_client_cfg_v1(&clt_cfg);
    }
    return best;
}


int ziti_listen(ziti_connection serv_conn, const char *service, ziti_listen_cb lcb, ziti_client_cb cb) {
    return ziti_bind(serv_conn, service, NULL, lcb, cb);
}

int ziti_listen_with_options(ziti_connection serv_conn, const char *service, ziti_listen_opts *listen_opts,
                             ziti_listen_cb lcb, ziti_client_cb cb) {
    return ziti_bind(serv_conn, service, listen_opts, lcb, cb);
}

/**
 * `ziti_re_auth` attempts to re-authenticate with the controller.
 * First, is makes sure we get the right authentication method.
 *
 * @param ztx
 */
static void ziti_re_auth(ziti_context ztx) {
    if (ztx->ext_auth) {
        oidc_client_refresh(ztx->ext_auth);
    }

    // always get controller version to get the right auth method
    ziti_ctrl_get_version(ztx_get_controller(ztx), version_pre_auth_cb, ztx);

    // load external signers in case they are needed for auth
    ziti_get_ext_jwt_signers(ztx, NULL, NULL);
}

static void set_posture_query_defaults(ziti_service *service) {
    int posture_set_idx;
    for (posture_set_idx = 0; service->posture_query_set[posture_set_idx] != 0; posture_set_idx++) {
        int posture_query_idx;
        for (posture_query_idx = 0; service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]; posture_query_idx++) {

            //if the controller doesn't support
            if (service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]->timeoutRemaining == NULL) {
                //free done by model_free
                model_number *timeoutRemaining = calloc(1, sizeof(*timeoutRemaining));
                *timeoutRemaining = -1;
                service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]->timeoutRemaining = timeoutRemaining;
            }
        }
    }
}

static bool service_posture_check_timeouts_changed(ziti_context ztx, const ziti_posture_query_set *new_set, const ziti_posture_query_set *old_set) {
    for (int new_idx = 0; new_set->posture_queries[new_idx] != NULL; new_idx++) {
        for (int old_idx = 0; old_set->posture_queries[old_idx] != NULL; old_idx++) {
            if (strncmp(old_set->posture_queries[old_idx]->id, new_set->posture_queries[new_idx]->id, strlen(old_set->posture_queries[old_idx]->id)) == 0) {
                if (old_set->posture_queries[old_idx]->timeout != new_set->posture_queries[new_idx]->timeout) {
                    return true;
                }

                if (strcmp(old_set->posture_queries[old_idx]->updated_at, new_set->posture_queries[new_idx]->updated_at) != 0) {
                    return true;
                }
            }
        }
    }

    return false;
}

void ziti_force_service_update(ziti_context ztx, const char* service_id) {
    ZTX_LOG(DEBUG, "forcing service[%s] to be reported as updated", service_id);
    model_map_set(&ztx->service_forced_updates, service_id, (void *) (uintptr_t) true);
}

// is_service_updated returns 0 if the direct service properties
// and configurations have not been altered. Will return non-0
// values if they have. This ignores posture query alterations.
static int is_service_updated(ziti_context ztx, ziti_service *new, ziti_service *old) {
    //compare updated at, if changed, signal update
    if (strcmp(old->updated_at, new->updated_at) != 0) {
        ZTX_LOG(VERBOSE, "service [%s] is updated, update_at property changes", new->name);
        return 1;
    }

    //check for forced updates
    if (model_map_remove(&ztx->service_forced_updates, new->id) != NULL) {
        return 1;
    }

    // config is a map of raw json
    if (model_map_compare(&old->config, &new->config, get_json_meta()) != 0) {
        ZTX_LOG(VERBOSE, "service [%s] is updated, config changed", new->name);
        return 1;
    }

    const char *policy_id;
    const ziti_posture_query_set *new_set;
    MODEL_MAP_FOREACH(policy_id, new_set, &new->posture_query_map) {
        ziti_posture_query_set *old_set = model_map_get(&old->posture_query_map, policy_id);

        if (old_set == NULL) {
            ZTX_LOG(VERBOSE, "service [%s] is updated, new service gained a policy [%s]", new->name, policy_id);
            return 1;
        }

        //is_passing states differ
        if (old_set->is_passing != new_set->is_passing) {
            ZTX_LOG(VERBOSE, "service [%s] is updated, new service is_passing state differs for policy [%s], old[%s] new[%s]",
                    new->name, policy_id, old_set->is_passing ? "TRUE" : "FALSE", new_set->is_passing ? "TRUE" : "FALSE");
            return 1;
        }

        //if timeouts changed
        if (service_posture_check_timeouts_changed(ztx, new_set, old_set)) {
            return 1;
        }
    }

    //ensure that new didn't lose policies
    const ziti_posture_query_set *old_set;
    MODEL_MAP_FOREACH(policy_id, old_set, &old->posture_query_map) {
        ziti_posture_query_set *new_set_by_old_id = model_map_get(&new->posture_query_map, policy_id);

        if (new_set_by_old_id == NULL) {
            ZTX_LOG(VERBOSE, "service [%s] is updated, new service lost a policy [%s]", new->name, policy_id);
            return 1;
        }
    }

    ZTX_LOG(VERBOSE, "service [%s] is not updated, default case", new->name);
    //no change
    return 0;
}

static void update_services(ziti_service_array services, const ziti_error *error, void *ctx) {
    ziti_context ztx = ctx;

    // schedule next refresh
    ziti_services_refresh(ztx, false);

    if (error) {
        ZTX_LOG(ERROR, "failed to get service updates err[%s/%s] from ctrl[%s]", error->code, error->message,
                ztx_controller(ztx));
        if (error->err == ZITI_AUTHENTICATION_FAILED) {
            ZTX_LOG(WARN, "api session is no longer valid. Trying to re-auth");
            ziti_re_auth(ztx);
        } else if (error->err == ZITI_PARTIALLY_AUTHENTICATED) {
            ZTX_LOG(VERBOSE, "api session partially authenticated, waiting for api session state change");
            return;
        } else {
            FREE(ztx->last_update);
            update_ctrl_status(ztx, ZITI_CONTROLLER_UNAVAILABLE, error->message);
        }
        return;
    }
    update_ctrl_status(ztx, ZITI_OK, NULL);


    ZTX_LOG(VERBOSE, "processing service updates");

    model_map updates = {0};

    int idx;
    for (idx = 0; services[idx] != NULL; idx++) {
        set_service_flags(services[idx]);
        set_posture_query_defaults(services[idx]);
        set_service_posture_policy_map(services[idx]);
        model_map_set(&updates, services[idx]->name, services[idx]);
    }
    free(services);

    size_t current_size = model_map_size(&ztx->services);
    size_t chIdx = 0, addIdx = 0, remIdx = 0;
    ziti_event_t ev = {
            .type = ZitiServiceEvent,
            .service = {
                    .removed = calloc(current_size + 1, sizeof(ziti_service *)),
                    .changed = calloc(current_size + 1, sizeof(ziti_service *)),
                    .added = calloc(idx + 1, sizeof(ziti_service *)),
            }
    };

    ziti_service *s;
    model_map_iter it = model_map_iterator(&ztx->services);
    while (it != NULL) {
        ziti_service *updt = model_map_remove(&updates, model_map_it_key(it));

        if (updt != NULL) {
            if (is_service_updated(ztx, updt, model_map_it_value(it)) != 0) {
                ev.service.changed[chIdx++] = updt;
            } else {
                // no changes detected, just discard it
                free_ziti_service(updt);
                free(updt);
            }

            it = model_map_it_next(it);
        } else {
            // service was removed
            ZTX_LOG(DEBUG, "service[%s] is not longer available", model_map_it_key(it));
            s = model_map_it_value(it);
            ev.service.removed[remIdx++] = s;

            ziti_session *session = model_map_remove(&ztx->sessions, s->id);
            if (session) {
                free_ziti_session(session);
                free(session);
            }
            it = model_map_it_remove(it);
        }
    }

    // what's left are new services
    it = model_map_iterator(&updates);
    while (it != NULL) {
        s = model_map_it_value(it);
        ev.service.added[addIdx++] = s;
        it = model_map_it_remove(it);
    }

    // process updates
    for (idx = 0; ev.service.changed[idx] != NULL; idx++) {
        s = ev.service.changed[idx];
        ziti_service *old = model_map_set(&ztx->services, s->name, s);
        free_ziti_service(old);
        FREE(old);
    }

    // process additions
    for (idx = 0; ev.service.added[idx] != NULL; idx++) {
        s = ev.service.added[idx];
        model_map_set(&ztx->services, s->name, s);
    }

    if (!ztx->services_loaded || (addIdx + remIdx + chIdx) > 0) {
        ZTX_LOG(DEBUG, "sending service event initial[%s] %zd added, %zd removed, %zd changed",
                ztx->services_loaded ? "false" : "true", addIdx, remIdx, chIdx);
        ziti_send_event(ztx, &ev);
        ztx->services_loaded = true;
    } else {
        ZTX_LOG(VERBOSE, "no services added, changed, or removed");
    }

    // cleanup
    for (idx = 0; ev.service.removed[idx] != NULL; idx++) {
        s = ev.service.removed[idx];
        free_ziti_service(s);
        free(s);
    }

    free(ev.service.removed);
    free(ev.service.added);
    free(ev.service.changed);

    model_map_clear(&updates, NULL);
    model_map_clear(&ztx->service_forced_updates, NULL);
}

// set_service_posture_policy_map checks to see if the controller
// provided posture queries via a map instead of an array. If not,
// it will convert the old array values into a map. All downstream
// processing of posture queries assumes the map will be set.
// The original array, will be NULL.
static void set_service_posture_policy_map(ziti_service *service) {
    // no work to do
    if (service->posture_query_set != NULL && model_map_size(&service->posture_query_map) != 0) {
        return;
    }

    for (int idx = 0; service->posture_query_set[idx] != NULL; idx++) {
        model_map_set(&service->posture_query_map, service->posture_query_set[idx]->policy_id, service->posture_query_set[idx]);
    }

    //free the array so that subsequent ziti_service_free() calls do not double free on the map and array
    FREE(service->posture_query_set);
}

static void check_service_update(ziti_service_update *update, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    if (err) {
        ZTX_LOG(WARN, "failed to poll service updates: code[%d] err[%d/%s]",
                (int)err->http_code, (int)err->err, err->message);
        // if controller is unavailable just reschedule for later time
        if (err->err != ZITI_DISABLED) {
            ziti_services_refresh(ztx, false);
        }
    } else if (ztx->last_update == NULL || strcmp(ztx->last_update, update->last_change) != 0) {
        ZTX_LOG(VERBOSE, "ztx last_update = %s", update->last_change);
        FREE(ztx->last_update);
        ztx->last_update = (char*)update->last_change;
        ziti_ctrl_get_services(ztx_get_controller(ztx), update_services, ztx);

    } else {
        ZTX_LOG(VERBOSE, "not updating: last_update is same previous (%s == %s)", update->last_change,
                ztx->last_update);
        free_ziti_service_update(update);
        ziti_services_refresh(ztx, false);
    }
    FREE(update);
}

static void refresh_cb(void *data) {
    ziti_context ztx = data;

    if (!ztx->enabled) {
        ZTX_LOG(DEBUG, "service refresh stopped, ztx is disabled");
        return;
    }

    ziti_ctrl_current_identity(ztx_get_controller(ztx), update_identity_data, ztx);
    ziti_ctrl_current_edge_routers(ztx_get_controller(ztx), edge_routers_cb, ztx);
    ziti_ctrl_get_services_update(ztx_get_controller(ztx), check_service_update, ztx);
}

void ziti_services_refresh(ziti_context ztx, bool now) {
    if (now || ztx->opts.refresh_interval > 0) {
        if (now) {
            ZTX_LOG(VERBOSE, "forcing service refresh");
        } else {
            ZTX_LOG(VERBOSE, "scheduling service refresh %ld seconds from now", ztx->opts.refresh_interval);
        }
        uint64_t timeout = now ? 0 : (ztx->opts.refresh_interval * 1000);
        ztx_set_deadline(ztx, timeout, &ztx->refresh_deadline, refresh_cb, ztx);
    }
}

static void edge_routers_cb(ziti_edge_router_array ers, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    bool ers_changed = false;

    if (err) {
        if (err->err != ZITI_DISABLED) {
            ZTX_LOG(ERROR, "failed to get current edge routers: code[%d] %s/%s",
                    (int)err->http_code, err->code, err->message);
        }
        return;
    }

    if (ers == NULL) {
        ZTX_LOG(INFO, "no edge routers found");
        return;
    }

    if (ztx->closing) {
        free_ziti_edge_router_array(&ers);
        return;
    }

    model_map curr_routers = {0};
    const char *er_name;
    ziti_channel_t *ch;
    MODEL_MAP_FOREACH(er_name, ch, &ztx->channels) {
        model_map_set(&curr_routers, er_name, (void *) er_name);
    }

    ziti_edge_router **erp = ers;
    while (*erp) {
        ziti_edge_router *er = *erp;

        // check if it is already in the list
        if (model_map_remove(&curr_routers, er->name) == NULL) {
            if (ziti_channel_connect(ztx, er) == ZITI_OK) {
                ers_changed = true;
                ZTX_LOG(TRACE, "connecting to %s(%s)", er->name, er->protocols.tls);
            }
        } else if(er->protocols.tls != NULL) {
            // N.B.: if protocols.tls is NULL,
            //     controller may not have refreshed the ER model leave the channel as is
            // otherwise update the url
            ch = model_map_get(&ztx->channels, er->name);
            ziti_channel_set_url(ch, er->protocols.tls);
        }

        free_ziti_edge_router(er);
        free(er);
        erp++;
    }
    free(ers);

    model_map_iter it = model_map_iterator(&curr_routers);
    while (it != NULL) {
        er_name = model_map_it_key(it);
        ch = model_map_remove(&ztx->channels, er_name);
        ZTX_LOG(INFO, "removing channel[%s@%s]: no longer available", ch->name, ch->url);
        ziti_channel_close(ch, ZITI_GATEWAY_UNAVAILABLE);
        it = model_map_it_remove(it);
        ers_changed = true;
    }

    // if the list of ERs changed, we want to opportunistically
    // refresh sessions to clear out references to old ERs,
    // and pull new ERs (which could be better for dialing)

    // we don't want to evict/refresh session right away
    // because it may have a serviceable ER
    // just refresh it on demand (next dial)
    if (ers_changed) {
        const char *serv;
        ziti_session *session;
        MODEL_MAP_FOREACH(serv, session, &ztx->sessions) {
            session->refresh = true;
        }
    }
}

static void update_identity_data(ziti_identity_data *data, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    if (err) {
        ZTX_LOG(ERROR, "failed to get identity_data: %s[%s]", err->message, err->code);
        if (err->err == ZITI_AUTHENTICATION_FAILED) {
            ZTX_LOG(WARN, "api session is no longer valid. Trying to re-auth");
            ziti_set_unauthenticated(ztx, err);
            ziti_force_api_session_refresh(ztx);
        }
    } else {
        free_ziti_identity_data(ztx->identity_data);
        FREE(ztx->identity_data);
        ztx->identity_data = data;
    }

    update_ctrl_status(ztx,
                       FIELD_OR_ELSE(err, err, ZITI_OK),
                       FIELD_OR_ELSE(err, message, ziti_errorstr(ZITI_OK)));
}

static void on_create_cert(ziti_create_api_cert_resp *resp, const ziti_error *e, void *ctx) {
    ziti_context ztx = ctx;
    if (e) {
        ZTX_LOG(ERROR, "failed to create session cert: %d/%s", (int)e->err, e->message);
    } else {
        ZTX_LOG(DEBUG, "received API session certificate");
        ZTX_LOG(VERBOSE, "cert => %s", resp->client_cert_pem);

        if (ztx->session_creds.cert) {
            ztx->session_creds.cert->free(ztx->session_creds.cert);
            ztx->session_creds.cert = NULL;
        }

        if (ztx->tlsCtx->load_cert(&ztx->session_creds.cert, resp->client_cert_pem, strlen(resp->client_cert_pem)) != 0) {
            ZTX_LOG(ERROR, "failed to parse supplied session cert");
        }

        tlsuv_private_key_t pk = ztx->session_creds.key ? ztx->session_creds.key : ztx->id_creds.key;
        int rc = ztx->tlsCtx->set_own_cert(ztx->tlsCtx, pk, ztx->session_creds.cert);
        if (rc != 0) {
            ZTX_LOG(ERROR, "failed to set session cert: %d", rc);
        }

        free_ziti_create_api_cert_resp_ptr(resp);
    }
    FREE(ztx->sessionCsr);
}

static void ca_bundle_cb(char *pkcs7, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    tlsuv_certificate_t new_bundle = NULL;
    char *new_pem = NULL;
    if (err == NULL) {
        size_t pem_size;

        if (ztx->tlsCtx->parse_pkcs7_certs(&new_bundle, pkcs7, strlen((pkcs7)))) {
            ZITI_LOG(ERROR, "failed to parse updated CA bundle");
            goto error;
        }
        if (new_bundle->to_pem(new_bundle, 1, &new_pem, &pem_size)) {
            ZITI_LOG(ERROR, "failed to format new CA bundle");
            goto error;
        }

        if (ztx->config.id.ca == NULL || strcmp(new_pem, ztx->config.id.ca) != 0) {
            ztx->tlsCtx->set_ca_bundle(ztx->tlsCtx, new_pem, strlen(new_pem));
            char *old_ca = (char*)ztx->config.id.ca;
            free(old_ca);

            ztx->config.id.ca = new_pem;
            new_pem = NULL;

            ztx_config_update(ztx);
        }
    } else {
        ZITI_LOG(ERROR, "failed to get CA bundle from controller: %s", err->message);
    }

    error:
    free(pkcs7);
    free(new_pem);
    if (new_bundle) {
        new_bundle->free(new_bundle);
    }
}


static void update_ctrl_status(ziti_context ztx, int errCode, const char *errMsg) {
    if (ztx->ctrl_status != errCode && ztx->enabled) {
        ziti_event_t ev = {
                .type = ZitiContextEvent,
                .ctx = {
                        .ctrl_status = errCode,
                        .err = errMsg,
                }};
        ziti_send_event(ztx, &ev);
    }
    ztx->ctrl_status = errCode;
}

void ziti_invalidate_session(ziti_context ztx, const char *service_id, ziti_session_type type) {
    if (type == ziti_session_types.Dial) {
        ziti_session *s = model_map_remove(&ztx->sessions, service_id);
        free_ziti_session_ptr(s);
    }
}

static const ziti_version sdk_version = {
        .version = to_str(ZITI_VERSION),
        .revision = to_str(ZITI_COMMIT),
        .build_date = __DATE__ " " __TIME__,
};

const ziti_version *ziti_get_version() {
    return &sdk_version;
}

static void grim_reaper(ziti_context ztx) {

    size_t total = model_map_size(&ztx->connections);
    size_t count = 0;

    if (total == 0 && !ztx->enabled) {
        // context disabled and no connections
        return;
    }

    model_map_iter it = model_map_iterator(&ztx->connections);
    while (it != NULL) {
        ziti_connection conn = model_map_it_value(it);
        int closed = conn->close ? conn->disposer(conn) : 0;
        it = closed ? model_map_it_remove(it) : model_map_it_next(it);
        count += closed;
    }
    if (count > 0) {
        ZTX_LOG(DEBUG, "reaped %zd closed (out of %zd total) connections", count, total);
    }
}

void ztx_set_deadline(ziti_context ztx, uint64_t timeout, deadline_t *d, void (*cb)(void *), void *ctx) {
    assert(cb != NULL);
    clear_deadline(d);

    uint64_t now = uv_now(ztx->loop);
    d->expiration = now + timeout;
    d->ctx = ctx;
    d->expire_cb = cb;

    if (LIST_EMPTY(&ztx->deadlines)) {
        LIST_INSERT_HEAD(&ztx->deadlines, d, _next);
        return;
    }

    deadline_t *dp = LIST_FIRST(&ztx->deadlines);
    deadline_t *dn = LIST_NEXT(dp, _next);
    while(1) {
        if (d->expiration < dp->expiration) {
            LIST_INSERT_BEFORE(dp, d, _next);
            break;
        }

        if (dn == NULL) {
            LIST_INSERT_AFTER(dp, d, _next);
            break;
        }

        dp = dn;
        dn = LIST_NEXT(dp, _next);
    }
}

static void ztx_process_deadlines(uv_timer_t *t) {
    ziti_context ztx = t->data;
    uint64_t now = uv_now(ztx->loop);
    deadline_t *d ;
    while ((d = LIST_FIRST(&ztx->deadlines)) && now > d->expiration) {
        LIST_REMOVE(d, _next);

        void *ctx = d->ctx;
        void (*cb)(void *) = d->expire_cb;
        d->expire_cb = NULL;
        cb(d->ctx);
    }
}

static void ztx_prep_deadlines(ziti_context ztx) {
    if (LIST_EMPTY(&ztx->deadlines)) {
        uv_timer_stop(&ztx->deadline_timer);
        return;
    }

    deadline_t *next = LIST_FIRST(&ztx->deadlines);
    uint64_t now = uv_now(ztx->loop);
    uint64_t wait_time = next->expiration > now ? next->expiration - now : 0;
    uv_timer_start(&ztx->deadline_timer, ztx_process_deadlines, wait_time, 0);
}

void ztx_prepare(uv_prepare_t *prep) {
    ziti_context ztx = prep->data;

    grim_reaper(ztx);
    ztx_prep_deadlines(ztx);

    // prepare channels for IO
    // NOTE: stalled ziti connections are flushed with idle handlers,
    // which run before prepare, which means that message
    // buffers could be returned to their corresponding channels
    // therefore enabling channel read if it was blocked
    const char *id;
    ziti_channel_t *ch;
    MODEL_MAP_FOREACH(id, ch, &ztx->channels) {
        ziti_channel_prepare(ch);
    }

    if (!ztx->enabled || ztx->closing) {
        uv_timer_stop(&ztx->deadline_timer);
        uv_prepare_stop(&ztx->prepper);
    }
}

void ziti_on_channel_event(ziti_channel_t *ch, ziti_router_status status, int err, ziti_context ztx) {
    ziti_event_t ev = {
            .type = ZitiRouterEvent,
            .router = {
                    .name = ch->name,
                    .address = ch->host,
                    .version = ch->version,
                    .status = status,
            }
    };

    ziti_send_event(ztx, &ev);

    if (status == EdgeRouterRemoved) {
        model_map_remove(&ztx->channels, ch->name);
        if (ztx->closing) {
            shutdown_and_free(ztx);
        }
    }

    if (status == EdgeRouterDisconnected && err == ZITI_CONNABORT) {
        ZTX_LOG(VERBOSE, "edge router closed connection, trying to refresh api session");
        ziti_force_api_session_refresh(ch->ztx);
    }

    if (status == EdgeRouterConnected) {
        uint32_t conn_id;
        ziti_connection conn;
        // move all ids to a list
        model_list ids = {0};
        MODEL_MAP_FOR(it, ztx->waiting_connections) {
            model_list_append(&ids, model_map_it_value(it));
        }

        model_map_clear(&ztx->waiting_connections, NULL);

        model_list_iter id_it = model_list_iterator(&ids);
        while(id_it != NULL) {
            conn_id = (uint32_t)(uintptr_t)model_list_it_element(id_it);
            conn = model_map_getl(&ztx->connections, (long)conn_id);
            if (conn != NULL) {
                process_connect(conn, NULL);
            }
            id_it = model_list_it_remove(id_it);
        }

        MODEL_MAP_FOREACH(conn_id, conn, &ztx->connections) {
            if (conn->type == Server) {
                update_bindings(conn);
            }
        }
    }
}

static void ztx_work_async(uv_async_t *ar) {
    ziti_context ztx = ar->data;
    ztx_work_q work;
    STAILQ_INIT(&work);

    struct ztx_work_s *w;
    uv_mutex_lock(&ztx->w_lock);
    work = ztx->w_queue;
    STAILQ_INIT(&ztx->w_queue);
    uv_mutex_unlock(&ztx->w_lock);

    while (!STAILQ_EMPTY(&work)) {
        w = STAILQ_FIRST(&work);
        STAILQ_REMOVE_HEAD(&work, _next);

        w->w(ztx, w->w_data);

        free(w);
    }
}

void ziti_queue_work(ziti_context ztx, ztx_work_f w, void *data) {
    NEWP(wrk, struct ztx_work_s);
    wrk->w = w;
    wrk->w_data = data;

    uv_mutex_trylock(&ztx->w_lock);
    STAILQ_INSERT_TAIL(&ztx->w_queue, wrk, _next);
    uv_mutex_unlock(&ztx->w_lock);

    uv_async_send(&ztx->w_async);
}

static void copy_oidc(ziti_context ztx, const ziti_jwt_signer *oidc) {
    if (oidc == NULL) return;
    if (oidc->provider_url == NULL) {
        ZITI_LOG(ERROR, "invalid OIDC config `externalAuthUrl` is missing");
        return;
    }
    if (oidc->client_id == NULL) {
        ZITI_LOG(ERROR, "invalid OIDC config `clientId` is missing");
        return;
    }

    ztx->config.id.oidc = calloc(1, sizeof(*oidc));
    ztx->config.id.oidc->client_id = strdup(oidc->client_id);
    ztx->config.id.oidc->provider_url = strdup(oidc->provider_url);
    if (oidc->audience) {
        ztx->config.id.oidc->audience = strdup(oidc->audience);
    }
    const char *scope;
    MODEL_LIST_FOREACH(scope, oidc->scopes) {
        model_list_append(&ztx->config.id.oidc->scopes, strdup(scope));
    }
}

int ziti_context_init(ziti_context *ztx, const ziti_config *config) {
    if (config == NULL ||
            (config->controller_url == NULL &&
             model_list_size(&config->controllers) == 0)
            ) {
        ZITI_LOG(ERROR, "config or controller/tls has to be set");
        return ZITI_INVALID_CONFIG;
    }

    ziti_context ctx = calloc(1, sizeof(*ctx));

    const char *cfg_ca = config->id.ca;
    if (cfg_ca == NULL) {
        ZITI_LOG(WARN, "config is missing CA bundle");
        cfg_ca = "";
    }

    if (strncmp(cfg_ca, "file://", strlen("file://")) == 0) {
        struct tlsuv_url_s url;
        if (tlsuv_parse_url(&url, cfg_ca) != 0) {
            ZITI_LOG(ERROR, "invalid CA bundle reference[]");
            return ZITI_INVALID_CONFIG;
        }

        char *ca = NULL;
        size_t ca_len;
        int rc = load_file(url.path, url.path_len, &ca, &ca_len);
        if (rc == 0) {
            FREE(ctx->config.id.ca);
            ctx->config.id.ca = ca;
        }
    } else {
        ctx->config.id.ca = strdup(cfg_ca);
    }

    if (config->cfg_source) {
        ctx->config.cfg_source = strdup(config->cfg_source);
    }
    const char *url;
    if (config->controller_url) {
        ctx->config.controller_url = strdup(config->controller_url);
    }

    bool found = ctx->config.controller_url == NULL;
    MODEL_LIST_FOREACH(url, (config->controllers)) {
        model_list_append(&ctx->config.controllers, strdup(url));
        found = found || strcmp(ctx->config.controller_url, url) == 0;
    }
    if (!found) {
        model_list_append(&ctx->config.controllers, strdup(ctx->config.controller_url));
    }

    if (config->id.key) ctx->config.id.key = strdup(config->id.key);
    if (config->id.cert) ctx->config.id.cert = strdup(config->id.cert);
    copy_oidc(ctx, config->id.oidc);

    ctx->opts = default_options;

    *ztx = ctx;
    return ZITI_OK;
}

int ziti_context_set_options(ziti_context ztx, const ziti_options *options) {
    if (options == NULL) {
        ztx->opts = default_options;
    } else {
#define copy_opt(f) if (options->f != 0) ztx->opts.f = options->f

        copy_opt(disabled);
        copy_opt(config_types);
        copy_opt(refresh_interval);
        copy_opt(metrics_type);
        copy_opt(api_page_size);
        copy_opt(event_cb);
        copy_opt(events);
        copy_opt(app_ctx);
        copy_opt(pq_domain_cb);
        copy_opt(pq_mac_cb);
        copy_opt(pq_os_cb);
        copy_opt(pq_process_cb);
        copy_opt(cert_extension_window);

#undef copy_opt
    }
    return ZITI_OK;
}

int ziti_context_run(ziti_context ztx, uv_loop_t *loop) {
    if (ztx->loop) {
        return ZITI_INVALID_STATE;
    }

    ztx->loop = loop;
    ztx->ctrl_status = ZITI_WTF;

    uv_timer_init(loop, &ztx->deadline_timer);
    ztx->deadline_timer.data = ztx;

    STAILQ_INIT(&ztx->w_queue);
    uv_async_init(loop, &ztx->w_async, ztx_work_async);
    ztx->w_async.data = ztx;
    uv_mutex_init(&ztx->w_lock);

    ziti_queue_work(ztx, ziti_init_async, NULL);

    return ZITI_OK;
}

int ziti_refresh(ziti_context ztx) {
    if (!ztx->enabled) return ZITI_DISABLED;

    ZTX_LOG(DEBUG, "application requested service refresh");
    ziti_services_refresh(ztx, true);
    return ZITI_OK;
}


static void pre_auth_retry(void *data) {
    ziti_context ztx = data;
    if (ztx->enabled) {
        ziti_re_auth(ztx);
    }
}

static void jwt_signers_cb(ziti_jwt_signer_array arr, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    const ziti_jwt_signer *js = NULL;

    if (err) {
        ZTX_LOG(ERROR, "failed to get external signers: %d/%s", (int)err->err, err->message);
    }
    FOR(js, arr) {
        ZTX_LOG(INFO, "ext jwt: %s", js->provider_url);
    }
}

static void version_pre_auth_cb(const ziti_version *version, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    if (err) {
        ZTX_LOG(WARN, "failed to get controller version: %s/%s", err->code, err->message);
        ztx_set_deadline(ztx, 5000, &ztx->refresh_deadline, pre_auth_retry, ztx);
    } else {
        bool ha = ziti_has_capability(version, ziti_ctrl_caps.HA_CONTROLLER);
        ZTX_LOG(INFO, "connected to %s controller %s version %s(%s %s)",
                ha ? "HA" : "Legacy",
                ztx_controller(ztx), version->version, version->revision, version->build_date);

        enum AuthenticationMethod m = ha ? HA : LEGACY;

        if (ztx->auth_method && ztx->auth_method->kind != m) {
            ZITI_LOG(INFO, "current auth method does not match controller, switching to %s method",
                     ha ? "HA" : "LEGACY");
            ztx->auth_method->stop(ztx->auth_method);
            ztx->auth_method->free(ztx->auth_method);
            ztx->auth_method = NULL;
        }

        bool start = false;
        if (!ztx->auth_method) {
            start = true;
            if (ha) {
                ztx->auth_method = new_ha_auth(ztx->loop, ztx->ctrl.url, ztx->tlsCtx);
            } else {
                ztx->auth_method = new_legacy_auth(ztx_get_controller(ztx));
            }
        } else if (ztx->auth_method->set_endpoint){
            ztx->auth_method->set_endpoint(ztx->auth_method, ztx->ctrl.url);
        }

        if (ztx->ext_auth == NULL && ztx->id_creds.key == NULL) {
            ztx_init_external_auth(ztx, ztx->config.id.oidc);
            return;
        }

        if (start) {
            ztx->auth_method->start(ztx->auth_method, ztx_auth_state_cb, ztx);
        } else if (ztx->auth_state  == ZitiAuthStateUnauthenticated) {
            ziti_force_api_session_refresh(ztx);
        }
    }
}

void ztx_auth_state_cb(void *ctx, ziti_auth_state state, const void *data) {
    ziti_context ztx = ctx;
    switch (state) {
        case ZitiAuthStateUnauthenticated:
            ziti_set_unauthenticated(ztx, (const ziti_error *) data);
            break;
        case ZitiAuthStateAuthStarted:
            ziti_set_auth_started(ztx);
            break;
        case ZitiAuthStatePartiallyAuthenticated: {
            ziti_set_partially_authenticated(ztx, data);
            break;
        }
        case ZitiAuthStateFullyAuthenticated:
            ziti_set_fully_authenticated(ztx, data);
            break;
        case ZitiAuthImpossibleToAuthenticate:
            ziti_set_impossible_to_authenticate(ztx, (const ziti_error*)data);
            break;
    }
    ztx->auth_state = state;
}

ziti_channel_t * ztx_get_channel(ziti_context ztx, const ziti_edge_router *er) {
    assert(ztx);
    assert(er);

    ziti_channel_t *ch = (ziti_channel_t *) model_map_get(&ztx->channels, er->name);
    if (ch == NULL) {
        ziti_channel_connect(ztx, er);
    }
    return ch;
}

struct cert_ext_req {
    ziti_api_session *session;
    ziti_context ztx;
    ziti_extend_cert_authenticator_resp *cert_resp;
    tlsuv_certificate_t new_cert;
};

static void cert_verify_cb(void *r, const ziti_error *err, void *ctx) {
    struct cert_ext_req *req = ctx;
    ziti_context ztx = req->ztx;
    if (err) {
        ZTX_LOG(ERROR, "failed to verify extended identity certificate: %s", err->message);
        goto done;
    }

    if (ztx->tlsCtx->set_own_cert(ztx->tlsCtx, ztx->id_creds.key, req->new_cert) != 0) {
        ZTX_LOG(ERROR, "extended certificate did not match key");
        goto done;
    }


    struct tm exp;
    req->new_cert->get_expiration(req->new_cert, &exp);

    ZTX_LOG(INFO, "successfully verified extended cert. good until %04d-%02d-%02d %02d:%02d",
            1900 + exp.tm_year, exp.tm_mon + 1, exp.tm_mday, exp.tm_hour, exp.tm_min);
    ztx->id_creds.cert = req->new_cert;
    req->new_cert = NULL;

    FREE(ztx->config.id.ca);
    FREE(ztx->config.id.cert);
    ztx->config.id.ca = req->cert_resp->cas_pem;
    ztx->config.id.cert = req->cert_resp->client_cert_pem;
    req->cert_resp->cas_pem = NULL;
    req->cert_resp->client_cert_pem = NULL;

    ztx_config_update(ztx);

    done:
    if (req->new_cert) req->new_cert->free(req->new_cert);
    free_ziti_api_session_ptr(req->session);
    free_ziti_extend_cert_authenticator_resp_ptr(req->cert_resp);
    free(req);
}

static void cert_extend_cb(ziti_extend_cert_authenticator_resp *resp, const ziti_error *err, void *ctx) {
    struct cert_ext_req *req = ctx;
    ziti_context ztx = req->ztx;
    if (err) {
        ZTX_LOG(ERROR, "failed to extend identity certificate: %s", err->message);
        free_ziti_api_session_ptr(req->session);
        free(req);
        return;
    }

    assert(resp);
    if (ztx->tlsCtx->load_cert(&req->new_cert, resp->client_cert_pem, strlen(resp->client_cert_pem)) != 0) {
        ZTX_LOG(ERROR, "failed to parse new certificate");
        free_ziti_extend_cert_authenticator_resp_ptr(resp);
        free_ziti_api_session_ptr(req->session);
        free(req);
        return;
    }

    ZTX_LOG(INFO, "successfully generated extended cert");
    req->cert_resp = resp;
    ziti_ctrl_verify_extend_cert_authenticator(
            ztx_get_controller(ztx), req->session->authenticator_id,
            resp->client_cert_pem, cert_verify_cb, req);

}

static void api_session_cb(ziti_api_session *api_sess, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    char *csr = NULL;
    size_t len = 0;
    if (api_sess) {
        model_map_iter it = model_map_iterator(&ztx->sessions);
        while(it) {
            ziti_session *s = model_map_it_value(it);
            if (strcmp(s->api_session_id, api_sess->id) != 0) {
                ZTX_LOG(DEBUG, "evicted stale session for service_id[%s]", s->service_id);
                it = model_map_it_remove(it);
                free_ziti_session_ptr(s);
            } else {
                it = model_map_it_next(it);
            }
        }

        if (ztx->id_creds.cert == NULL) {
            goto done;
        }

        // it is a 3rd party cert, no need for the rest of checks
        if (!api_sess->is_cert_extendable) {
            ZTX_LOG(DEBUG, "identity certificate is not renewable");
            goto done;
        }

        if (api_sess->cert_extend_requested || api_sess->key_roll_requested) {
            ZTX_LOG(INFO, "controller requested certificate renewal (%s key roll)",
                    api_sess->key_roll_requested ? "with" : "without");
            goto extend;
        }

        if (api_sess->is_cert_improper) {
            ZTX_LOG(INFO, "controller reported certificate chain as incomplete");
            goto extend;
        }

        // check if identity cert is expiring or expired
        if (ztx->opts.cert_extension_window > 0) {
            struct tm exp;
            ztx->id_creds.cert->get_expiration(ztx->id_creds.cert, &exp);
            time_t now = time(0);
            time_t exptime = mktime(&exp);

            bool renew = exptime - now < ztx->opts.cert_extension_window * ONE_DAY;
            if (!renew) {
                goto done;
            }
            ZTX_LOG(INFO, "renewing identity certificate exp[%04d-%02d-%02d %02d:%02d]",
                    1900 + exp.tm_year, exp.tm_mon + 1, exp.tm_mday, exp.tm_hour, exp.tm_min);
        } else {
            ZTX_LOG(DEBUG, "app is not requiring expiration check");
            goto done;
        }

        extend:

        if ((ztx->opts.events & ZitiConfigEvent) == 0) {
            ZTX_LOG(WARN, "identity certificate needs to be renewed "
                          "but application is not handling ZitiConfigEvent");
            goto done;
        }

        if (api_sess->key_roll_requested) {
            ZTX_LOG(WARN, "key roll requested, but not yet supported");
        }

        if (ztx->tlsCtx->generate_csr_to_pem(ztx->id_creds.key, &csr, &len, "O", "OpenZiti",
                                         "DC", ztx->config.controller_url,
                                         "CN", api_sess->identity_id,
                                         NULL) != 0) {
            ZTX_LOG(WARN, "failed to generate certificate request");
            goto done;
        }

        NEWP(ext_req, struct cert_ext_req);
        ext_req->session = api_sess;
        ext_req->ztx = ztx;

        api_sess = NULL;
        ziti_ctrl_extend_cert_authenticator(ztx_get_controller(ztx),
                                            ext_req->session->authenticator_id, csr,
                                            cert_extend_cb, ext_req);
    }

    done:
    free_ziti_api_session_ptr(api_sess);
    free(csr);
}
