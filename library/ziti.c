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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "zt_internal.h"
#include <auth_queries.h>
#include <uv.h>

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

#define ztx_controller(ztx) \
((ztx)->ctrl.url ? (ztx)->ctrl.url : (ztx)->config.controller_url)

static const char *ALL_CONFIG_TYPES[] = {
        "all",
        NULL
};

struct ziti_init_req {
    ziti_context ztx;
    bool start;
};

int code_to_error(const char *code);

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

static void ztx_auth_state_cb(void *, ziti_auth_state , const void *);

static void ca_bundle_cb(char *pkcs7, const ziti_error *err, void *ctx);

static void update_identity_data(ziti_identity_data *data, const ziti_error *err, void *ctx);

static uint32_t ztx_seq;

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
            *res = val + strlen("file://");
            len = strlen(*res) + 1;
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

static int init_tls_from_config(tls_context *tls, ziti_config *cfg) {
    PREP(ziti);

    tlsuv_private_key_t pk;

    TRY(ziti, cfg->id.key == NULL ? ZITI_INVALID_CONFIG : ZITI_OK);

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
    return ZITI_OK;
}

int load_tls(ziti_config *cfg, tls_context **ctx) {

    // load ca from ziti config if present
    const char *ca;
    size_t ca_len = parse_ref(cfg->id.ca, &ca);
    tls_context *tls = default_tls_context(ca, ca_len);

    int rc = init_tls_from_config(tls, cfg);

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

void ziti_set_unauthenticated(ziti_context ztx) {
    ZTX_LOG(DEBUG, "setting auth_state[%d] to %d", ztx->auth_state, ZitiAuthStateUnauthenticated);

    FREE(ztx->session_token);

    if (ztx->sessionKey) {
        init_tls_from_config(ztx->tlsCtx, &ztx->config);
        if (ztx->sessionCert) {
            ztx->sessionCert->free(ztx->sessionCert);
            ztx->sessionCert = NULL;
        }

        ztx->sessionKey->free(ztx->sessionKey);
        ztx->sessionKey = NULL;
    }

    model_map_clear(&ztx->sessions, (void (*)(void *)) free_ziti_session_ptr);

    ziti_ctrl_clear_api_session(ztx_get_controller(ztx));
}

void ziti_set_impossible_to_authenticate(ziti_context ztx) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->auth_state, ZitiAuthImpossibleToAuthenticate);
    FREE(ztx->session_token);
    ziti_ctrl_clear_api_session(ztx_get_controller(ztx));
}

void ziti_set_partially_authenticated(ziti_context ztx, const ziti_auth_query_mfa *mfa_q) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->auth_state, ZitiAuthStatePartiallyAuthenticated);
    update_ctrl_status(ztx, ZITI_PARTIALLY_AUTHENTICATED, NULL);

    ziti_event_t ev = {
            .type = ZitiAuthEvent,
            .auth = {
                    .action = ziti_auth_prompt_totp,
                    .type = mfa_q->type_id,
                    .detail = mfa_q->provider,
            }
    };

    ziti_send_event(ztx, &ev);
}

static void ctrl_list_cb(ziti_controller_detail_array ctrls, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    if (err) {
        ZTX_LOG(WARN, "failed to list HA controllers %s/%s", err->code, err->message);
        return;
    }

    model_map_clear(&ztx->ctrl_details, (_free_f)free_ziti_controller_detail_ptr);
    for (int i = 0; ctrls[i] != NULL; i++) {
        ziti_controller_detail *detail = ctrls[i];
        api_address *api = model_list_head(&detail->apis.edge);
        ZTX_LOG(INFO, "controller[%s/%s] url[%s]", detail->name, detail->id, FIELD_OR_ELSE(api, url, "<unset>"));

        model_map_set(&ztx->ctrl_details, detail->id, detail);
    }
    free(ctrls);
}

void ziti_set_fully_authenticated(ziti_context ztx, const char *session_token) {
    ZTX_LOG(DEBUG, "setting auth_state[%d] to %d",
            ztx->auth_state, ZitiAuthStateFullyAuthenticated);

    if (ztx->session_token == NULL || strcmp(ztx->session_token, session_token) != 0) {
        free(ztx->session_token);
        ztx->session_token = strdup(session_token);
    }
    ziti_controller *ctrl = ztx_get_controller(ztx);
    if (ztx->auth_method->kind == HA) {
        ziti_ctrl_set_token(ztx_get_controller(ztx), session_token);
        ziti_ctrl_list_controllers(ctrl, ctrl_list_cb, ztx);

        const char* url;
        ziti_channel_t *ch;
        MODEL_MAP_FOREACH(url, ch, &ztx->channels) {
            ziti_channel_update_token(ch);
        }
    }
    ziti_ctrl_get_well_known_certs(ctrl, ca_bundle_cb, ztx);
    ziti_ctrl_current_identity(ctrl, update_identity_data, ztx);

    // disable this until we figure out expiration and rolling requirements
#if ENABLE_SESSION_CERTIFICATES
    if (ztx->sessionKey == NULL) {
            char common_name[128];
            snprintf(common_name, sizeof(common_name), "%s-%u-%" PRIu64,
                     APP_ID ? APP_ID : "ziti-sdk-c",
                     ztx->id, uv_now(ztx->loop));

            ztx->tlsCtx->generate_key(&ztx->sessionKey);

            size_t csr_len;
            ztx->tlsCtx->generate_csr_to_pem(ztx->sessionKey, &ztx->sessionCsr, &csr_len,
                                             "O", "OpenZiti",
                                             "OU", "ziti-sdk",
                                             "CN", common_name,
                                             NULL);

            ziti_ctrl_create_api_certificate(&ztx->controller, ztx->sessionCsr, on_create_cert, ztx);
        }
#endif


    ziti_services_refresh(ztx, true);
    ziti_posture_init(ztx, 20);
}

static void logout_cb(void *resp, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    ziti_set_unauthenticated(ztx);

    ziti_close_channels(ztx, ZITI_DISABLED);

    model_map_clear(&ztx->sessions, (_free_f) free_ziti_session_ptr);
    model_map_clear(&ztx->services, (_free_f) free_ziti_service_ptr);

    if (ztx->closing) {
        ztx->logout = true;
        shutdown_and_free(ztx);
    } else {
        update_ctrl_status(ztx, ZITI_DISABLED, ziti_errorstr(ZITI_DISABLED));
    }
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
        ztx->enabled = false;

        metrics_rate_close(&ztx->up_rate);
        metrics_rate_close(&ztx->down_rate);

        ztx->auth_method->stop(ztx->auth_method);

        // stop updates
        uv_timer_stop(ztx->service_refresh_timer);

        if (ztx->posture_checks) {
            ziti_posture_checks_free(ztx->posture_checks);
            ztx->posture_checks = NULL;
        }

        model_map_clear(&ztx->sessions, (void (*)(void *)) free_ziti_session_ptr);

        // close all channels
        ziti_close_channels(ztx, ZITI_DISABLED);

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

        ztx->auth_method->stop(ztx->auth_method);
        ziti_send_event(ztx, &ev);
        free_ziti_service_array(&ev.service.removed);

        ziti_ctrl_cancel(ztx_get_controller(ztx));
        // logout
        ziti_ctrl_logout(ztx_get_controller(ztx), logout_cb, ztx);
    }
}

uv_timer_t* new_ztx_timer(ziti_context ztx) {
    uv_timer_t *timer = calloc(1, sizeof(uv_timer_t));
    uv_timer_init(ztx->loop, timer);
    timer->data = ztx;
    return timer;
}

static void ziti_start_internal(ziti_context ztx, void *init_req) {
    if (!ztx->enabled) {
        ztx->enabled = true;
        ztx->logout = false;
        uv_prepare_start(ztx->prepper, ztx_prepare);
        ztx->start = uv_now(ztx->loop);
        ziti_set_unauthenticated(ztx);

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

    ziti_event_t ev = {
            .type = ZitiAPIEvent,
            .api.new_ctrl_address = new_addr,
    };
    ziti_send_event(ztx, &ev);
}

static void ziti_init_async(ziti_context ztx, void *data) {
    ztx->id = ztx_seq++;
    uv_loop_t *loop = ztx->w_async.loop;
    struct ziti_init_req *init_req = data;
    ziti_event_t ev = {
	     .type = ZitiContextEvent,
    };

    ZTX_LOG(INFO, "using tlsuv[%s], tls[%s]", tlsuv_version(),
            ztx->tlsCtx->version ? ztx->tlsCtx->version() : "unspecified");
    ZTX_LOG(INFO, "Loading ziti context with controller[%s]", ztx_controller(ztx));

    const char *url;
    int rc = ziti_ctrl_init(loop, &ztx->ctrl, &ztx->config.controllers, ztx->tlsCtx);
    if (rc != 0) {
        ZITI_LOG(ERROR, "no valid controllers found");
        ev.ctx.ctrl_status = rc;
        ziti_send_event(ztx, &ev);
        return;
    }

    ziti_ctrl_set_callbacks(ztx_get_controller(ztx), ztx, on_ctrl_redirect,
                            (ziti_ctrl_change_cb) on_ctrl_list_change);
    if (ztx->opts.api_page_size != 0) {
        ziti_ctrl_set_page_size(ztx_get_controller(ztx), ztx->opts.api_page_size);
    }

    ztx->service_refresh_timer = new_ztx_timer(ztx);

    ztx->prepper = calloc(1, sizeof(uv_prepare_t));
    uv_prepare_init(loop, ztx->prepper);
    ztx->prepper->data = ztx;
    uv_unref((uv_handle_t *) ztx->prepper);

    ZTX_LOG(DEBUG, "using metrics interval: %d", (int) ztx->opts.metrics_type);
    metrics_rate_init(&ztx->up_rate, ztx->opts.metrics_type);
    metrics_rate_init(&ztx->down_rate, ztx->opts.metrics_type);
    metrics_init(loop, 5);

    if (init_req->start) {
        ziti_start_internal(ztx, NULL);
    } else {
        ev.ctx.ctrl_status = ZITI_DISABLED;
        ziti_send_event(ztx, &ev);
    }
    free(init_req);
}

extern void *ziti_app_ctx(ziti_context ztx) {
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

void ziti_get_transfer_rates(ziti_context ztx, double *up, double *down) {
    *up = metrics_rate_get(&ztx->up_rate);
    *down = metrics_rate_get(&ztx->down_rate);
}

static void free_ztx(uv_handle_t *h) {
    ziti_context ztx = h->data;

    model_map_clear(&ztx->ctrl_details, (_free_f) free_ziti_controller_detail_ptr);
    ziti_auth_query_free(ztx->auth_queries);
    ziti_posture_checks_free(ztx->posture_checks);
    model_map_clear(&ztx->services, (_free_f) free_ziti_service_ptr);
    model_map_clear(&ztx->sessions, (_free_f) free_ziti_session_ptr);
    ziti_set_unauthenticated(ztx);
    free_ziti_identity_data(ztx->identity_data);
    FREE(ztx->identity_data);
    FREE(ztx->last_update);
    FREE(ztx->session_token);

    ziti_ctrl_close(ztx_get_controller(ztx));
    ztx->tlsCtx->free_ctx(ztx->tlsCtx);
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

    if (!ztx->logout) {
        ZTX_LOG(INFO, "waiting for logout");
        return;
    }

    grim_reaper(ztx);
    CLOSE_AND_NULL(ztx->prepper);
    CLOSE_AND_NULL(ztx->service_refresh_timer);

    uv_close((uv_handle_t *) &ztx->w_async, free_ztx);
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
    printer(ctx, "\n=================\nZiti Context:\n");
    printer(ctx, "ID:\t%d\n", ztx->id);
    if (ziti_is_enabled(ztx)) {
        printer(ctx, "enabled[true] uptime[%" PRIu64 "s]\n", (now -  ztx->start)/1000);
    } else {
        printer(ctx, "enabled[false]");
    }
    printer(ctx, "Config Source:\t%s\n", ztx->config.cfg_source ? ztx->config.cfg_source : "(none)");
    printer(ctx, "Controller:\t%s\n", ztx_controller(ztx));
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
                printer(ctx, "\t\t\tquery_id[%s] type[%s] is_passing[%s] timeout[%d] timeoutRemaining[%d]\n", pq->id, pq->query_type, pq->is_passing ? "true" : "false", pq->timeout, *pq->timeoutRemaining);
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
    const char *url;
    MODEL_MAP_FOREACH(url, ch, &ztx->channels) {
        printer(ctx, "ch[%d](%s@%s) ", ch->id, ch->name, url);
        if (ziti_channel_is_connected(ch)) {
            printer(ctx, "connected [latency=%" PRIu64 "]\n", ziti_channel_latency(ch));
        }
        else {
            printer(ctx, "Disconnected\n");
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

void ziti_conn_set_data_cb(ziti_connection conn, ziti_data_cb cb) {
    if (conn) {
        conn->data_cb = cb;
    }
}

const char *ziti_conn_source_identity(ziti_connection conn) {
    return conn != NULL ? conn->source_identity : NULL;
}


void ziti_send_event(ziti_context ztx, const ziti_event_t *e) {
    if ((ztx->opts.events & e->type) && ztx->opts.event_cb) {
        ztx->opts.event_cb(ztx, e);
    }
}

struct service_req_s {
    struct ziti_ctx *ztx;
    char *service;
    ziti_service_cb cb;
    void *cb_ctx;
};

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
    struct service_req_s *req = ctx;
    int rc = ZITI_SERVICE_UNAVAILABLE;

    if (s != NULL) {
        set_service_flags(s);
        ziti_service *old = model_map_set(&req->ztx->services, s->name, s);
        free_ziti_service_ptr(old);
        rc = ZITI_OK;
    } else {
        if (err) {
            rc = err->err;
        }
    }

    req->cb(req->ztx, s, rc, req->cb_ctx);
    FREE(req->service);
    free(req);
}

int ziti_service_available(ziti_context ztx, const char *service, ziti_service_cb cb, void *ctx) {
    if (!ztx->enabled) return ZITI_DISABLED;

    ziti_service *s = model_map_get(&ztx->services, service);
    if (s != NULL) {
        cb(ztx, s, ZITI_OK, ctx);
        return ZITI_OK;
    }

    NEWP(req, struct service_req_s);
    req->ztx = ztx;
    req->service = strdup(service);
    req->cb = cb;
    req->cb_ctx = ctx;

    ziti_ctrl_get_service(ztx_get_controller(ztx), service, service_cb, req);
    return ZITI_OK;
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
 * `ziti_re_auth` attempts to re-authenticate with the controller. However
 * this will be ignored if the current `ziti_context` believes it is in a
 * partially authenticated state. If desired, called `ziti_set_unauthenticated`
 * to bypass this state.
 * @param ztx
 * @param force
 */

static void version_pre_auth_cb(const ziti_version *version, const ziti_error *err, void *ctx);

static void ziti_re_auth(ziti_context ztx) {
    // always get controller version to get the right auth method
    ziti_ctrl_get_version(ztx_get_controller(ztx), version_pre_auth_cb, ztx);
}

static void set_posture_query_defaults(ziti_service *service) {
    int posture_set_idx;
    for (posture_set_idx = 0; service->posture_query_set[posture_set_idx] != 0; posture_set_idx++) {
        int posture_query_idx;
        for (posture_query_idx = 0; service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]; posture_query_idx++) {

            //if the controller doesn't support
            if (service->posture_query_set[posture_set_idx]->posture_queries[posture_query_idx]->timeoutRemaining == NULL) {
                //free done by model_free
                int *timeoutRemaining = calloc(1, sizeof(int));
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
                err->http_code, err->err, err->message);
        // if controller is unavailable just reschedule for later time
        if (err->err != ZITI_DISABLED) {
            ziti_services_refresh(ztx, false);
        }
    } else if (ztx->last_update == NULL || strcmp(ztx->last_update, update->last_change) != 0) {
        ZTX_LOG(VERBOSE, "ztx last_update = %s", update->last_change);
        FREE(ztx->last_update);
        ztx->last_update = update->last_change;
        ziti_ctrl_get_services(ztx_get_controller(ztx), update_services, ztx);

    } else {
        ZTX_LOG(VERBOSE, "not updating: last_update is same previous (%s == %s)", update->last_change,
                ztx->last_update);
        free_ziti_service_update(update);
        ziti_services_refresh(ztx, false);
    }
    FREE(update);
}

static void refresh_cb(uv_timer_t *t) {
    ziti_context ztx = t->data;

//151637
    if (!ztx->enabled) {
        ZTX_LOG(DEBUG, "service refresh stopped, ztx is disabled");
        return;
    }

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
        uv_timer_start(ztx->service_refresh_timer, refresh_cb, timeout, 0);
    }
}

static void edge_routers_cb(ziti_edge_router_array ers, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    bool ers_changed = false;

    if (err) {
        if (err->err != ZITI_DISABLED) {
            ZTX_LOG(ERROR, "failed to get current edge routers: code[%d] %s/%s",
                    err->http_code, err->code, err->message);
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
    const char *er_url;
    ziti_channel_t *ch;
    MODEL_MAP_FOREACH(er_url, ch, &ztx->channels) {
        model_map_set(&curr_routers, er_url, (void *) er_url);
    }

    ziti_edge_router **erp = ers;
    while (*erp) {
        ziti_edge_router *er = *erp;
        const char *tls = er->protocols.tls;

        if (tls) {
            // check if it is already in the list
            if (model_map_remove(&curr_routers, tls) == NULL) {
                ZTX_LOG(TRACE, "connecting to %s(%s)", er->name, tls);
                ziti_channel_connect(ztx, er->name, tls);
                ers_changed = true;
            }
        } else {
            ZTX_LOG(DEBUG, "edge router %s does not have TLS edge listener", er->name);
        }

        free_ziti_edge_router(er);
        free(er);
        erp++;
    }
    free(ers);

    model_map_iter it = model_map_iterator(&curr_routers);
    while (it != NULL) {
        er_url = model_map_it_key(it);
        ch = model_map_remove(&ztx->channels, er_url);
        ZTX_LOG(INFO, "removing channel[%s@%s]: no longer available", ch->name, er_url);
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
    } else {
        free_ziti_identity_data(ztx->identity_data);
        FREE(ztx->identity_data);
        ztx->identity_data = data;
    }

    update_ctrl_status(ztx, FIELD_OR_ELSE(err, err, ZITI_OK), FIELD_OR_ELSE(err, message, NULL));
}

static void on_create_cert(ziti_create_api_cert_resp *resp, const ziti_error *e, void *ctx) {
    ziti_context ztx = ctx;
    if (e) {
        ZTX_LOG(ERROR, "failed to create session cert: %d/%s", e->err, e->message);
    } else {
        ZTX_LOG(DEBUG, "received API session certificate");
        ZTX_LOG(VERBOSE, "cert => %s", resp->client_cert_pem);

        if (ztx->sessionCert) {
            ztx->sessionCert->free(ztx->sessionCert);
            ztx->sessionCert = NULL;
        }

        if (ztx->tlsCtx->load_cert(&ztx->sessionCert, resp->client_cert_pem, strlen(resp->client_cert_pem)) != 0) {
            ZTX_LOG(ERROR, "failed to parse supplied session cert");
        }

        int rc = ztx->tlsCtx->set_own_cert(ztx->tlsCtx, ztx->sessionKey, ztx->sessionCert);
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

        if (ztx->config.id.ca && strcmp(new_pem, ztx->config.id.ca) != 0) {
            char *old_ca = ztx->config.id.ca;
            ztx->config.id.ca = new_pem;

            tls_context *new_tls = NULL;
            if (load_tls(&ztx->config, &new_tls) == 0) {
                ziti_send_event(ztx, &(ziti_event_t){
                        .type = ZitiAPIEvent,
                        .api = {
                                .new_ca_bundle = new_pem,
                        }
                });
                free(old_ca);
                ztx->tlsCtx = new_tls;
                ztx_get_controller(ztx)->client->tls = ztx->tlsCtx;
                new_pem = NULL; // owned by ztx->config
            } else {
                ztx->config.id.ca = old_ca;
                ZITI_LOG(ERROR, "failed to create TLS context with updated CA bundle");
            }
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
        ztx->ctrl_status = errCode;
        ziti_send_event(ztx, &ev);
    }
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

void ztx_prepare(uv_prepare_t *prep) {
    ziti_context ztx = prep->data;

    grim_reaper(ztx);

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

    if (!ztx->enabled) {
        uv_prepare_stop(ztx->prepper);
    }
}

void ziti_on_channel_event(ziti_channel_t *ch, ziti_router_status status, ziti_context ztx) {
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
        model_map_remove(&ztx->channels, ch->url);
        if (ztx->closing) {
            shutdown_and_free(ztx);
        }
    }

    if (status == EdgeRouterConnected) {
        // move all ids to a list
        model_list ids = {0};
        MODEL_MAP_FOR(it, ztx->waiting_connections) {
            model_list_append(&ids, model_map_it_value(it));
        }

        model_map_clear(&ztx->waiting_connections, NULL);

        model_list_iter id_it = model_list_iterator(&ids);
        while(id_it != NULL) {
            uint32_t conn_id = (uint32_t)(uintptr_t)model_list_it_element(id_it);
            ziti_connection conn = model_map_getl(&ztx->connections, (long)conn_id);
            if (conn != NULL) {
                process_connect(conn, NULL);
            }
            id_it = model_list_it_remove(id_it);
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

int ziti_context_init(ziti_context *ztx, const ziti_config *config) {
    if (config == NULL ||
            (config->controller_url == NULL &&
             model_list_size(&config->controllers) == 0)
            ) {
        ZITI_LOG(ERROR, "config or controller/tls has to be set");
        return ZITI_INVALID_CONFIG;
    }

    ziti_context ctx = calloc(1, sizeof(*ctx));

    char *cfg_ca = config->id.ca;
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
    if (model_list_size(&config->controllers) > 0) {
        MODEL_LIST_FOREACH(url, (config->controllers)) {
            model_list_append(&ctx->config.controllers, strdup(url));
        }
    } else {
        model_list_append(&ctx->config.controllers, strdup(config->controller_url));
    }
    if (config->id.key) ctx->config.id.key = strdup(config->id.key);
    if (config->id.cert) ctx->config.id.cert = strdup(config->id.cert);

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

#undef copy_opt
    }
    return ZITI_OK;
}

int ziti_context_run(ziti_context ztx, uv_loop_t *loop) {
    if (ztx->loop) {
        return ZITI_INVALID_STATE;
    }
    PREPF(ziti, ziti_errorstr);

    tls_context *tls = NULL;
    TRY(ziti, load_tls(&ztx->config, &tls));

    ztx->tlsCtx = tls;
    ztx->loop = loop;
    ztx->ctrl_status = ZITI_WTF;

    STAILQ_INIT(&ztx->w_queue);
    uv_async_init(loop, &ztx->w_async, ztx_work_async);
    ztx->w_async.data = ztx;
    uv_mutex_init(&ztx->w_lock);

    NEWP(init_req, struct ziti_init_req);
    init_req->start = !ztx->opts.disabled;
    ziti_queue_work(ztx, ziti_init_async, init_req);

    CATCH(ziti) {
        return ERR(ziti);
    }

    return ZITI_OK;
}

static void pre_auth_retry(uv_timer_t *t) {
    ziti_context ztx = t->data;
    ziti_re_auth(ztx);
    uv_close((uv_handle_t *) t, (uv_close_cb) free);
}

static void version_pre_auth_cb(const ziti_version *version, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    if (err) {
        ZTX_LOG(WARN, "failed to get controller version: %s/%s", err->code, err->message);
        uv_timer_t *t = calloc(1, sizeof(*t));
        uv_timer_init(ztx->loop, t);
        t->data = ztx;
        uv_timer_start(t, pre_auth_retry, 5 * 1000, 0);
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

        if (!ztx->auth_method) {
            if (ha) {
                ztx->auth_method = new_ha_auth(ztx->loop, &ztx->config.controllers, ztx->tlsCtx);
            } else {
                ztx->auth_method = new_legacy_auth(ztx_get_controller(ztx));
            }
            ztx->auth_method->start(ztx->auth_method, ztx_auth_state_cb, ztx);
        } else if (ztx->auth_state  == ZitiAuthStateUnauthenticated) {
            ztx->auth_method->force_refresh(ztx->auth_method);
        }
    }
}

static void ztx_auth_state_cb(void *ctx, ziti_auth_state state, const void *data) {
    ziti_context ztx = ctx;
    ztx->auth_state = state;
    switch (state) {
        case ZitiAuthStateUnauthenticated:
            ziti_set_unauthenticated(ztx);
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
            ziti_set_impossible_to_authenticate(ztx);
            break;
    }
}
