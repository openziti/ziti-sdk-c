// Copyright (c) 2022.  NetFoundry, Inc.
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


#include <stdlib.h>
#include <string.h>

#include <ziti/ziti.h>
#include <uv.h>
#include "utils.h"
#include "zt_internal.h"
#include <http_parser.h>
#include <posture.h>
#include <auth_queries.h>

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

#define ztx_controller(ztx) ((ztx)->controller.url ? (ztx)->controller.url : (ztx)->opts->controller)

static const char *ALL_CONFIG_TYPES[] = {
        "all",
        NULL
};

struct ziti_init_req {
    ziti_context ztx;
    bool start;
    int init_status;
};

const int API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS = 60;
const int API_SESSION_DELAY_WINDOW_SECONDS = 60;
const int API_SESSION_EXPIRATION_TOO_SMALL_SECONDS = 120;

int code_to_error(const char *code);

static void update_ctrl_status(ziti_context ztx, int code, const char *msg);

static void version_cb(ziti_version *v, const ziti_error *err, void *ctx);

static void api_session_cb(ziti_api_session *session, const ziti_error *err, void *ctx);

static void ziti_init_async(ziti_context ztx, void *data);

static void ziti_re_auth(ziti_context ztx);

static void grim_reaper(uv_prepare_t *p);

static void ztx_work_async(uv_async_t *ar);

static void ziti_stop_internal(ziti_context ztx, void *data);

static void ziti_start_internal(ziti_context ztx, void *init_req);

static void set_service_posture_policy_map(ziti_service *service);

static void api_session_refresh(uv_timer_t *t);

static void shutdown_and_free(ziti_context ztx);

static uint32_t ztx_seq;

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

static int parse_getopt(const char *q, const char *opt, char *out, size_t maxout) {
    size_t optlen = strlen(opt);
    do {
        // found it
        if (strncasecmp(q, opt, optlen) == 0 && (q[optlen] == '=' || q[optlen] == 0)) {
            const char *val = q + optlen + 1;
            char *end = strchr(val, '&');
            int vlen = (int) (end == NULL ? strlen(val) : end - val);
            snprintf(out, maxout, "%*.*s", vlen, vlen, val);
            return ZITI_OK;

        } else { // skip to next '&'
            q = strchr(q, '&');
            if (q == NULL) {
                break;
            }
            q += 1;
        }
    } while (q != NULL);
    out[0] = '\0';
    return ZITI_INVALID_CONFIG;
}

int load_tls(ziti_config *cfg, tls_context **ctx) {
    PREP(ziti);

    // load ca from ziti config if present
    const char *ca, *cert;
    size_t ca_len = parse_ref(cfg->id.ca, &ca);
    size_t cert_len = parse_ref(cfg->id.cert, &cert);
    tls_context *tls = default_tls_context(ca, ca_len);

    if (strncmp(cfg->id.key, "pkcs11://", strlen("pkcs11://")) == 0) {
        char path[MAXPATHLEN] = {0};
        char pin[32] = {0};
        char slot[32] = {0};
        char id[32] = {0};

        char *p = cfg->id.key + strlen("pkcs11://");
        char *endp = strchr(p, '?');
        char *q = endp + 1;
        if (endp == NULL) {
            TRY(ziti, ("invalid pkcs11 key specification", ZITI_INVALID_CONFIG));
        }
        sprintf(path, "%*.*s", (int) (endp - p), (int) (endp - p), p);

        TRY(ziti, parse_getopt(q, "pin", pin, sizeof(pin)));
        TRY(ziti, parse_getopt(q, "slot", slot, sizeof(slot)));
        TRY(ziti, parse_getopt(q, "id", id, sizeof(id)));

        tls->api->set_own_cert_pkcs11(tls->ctx, cert, cert_len, path, pin, slot, id);
    } else {
        const char *key;
        size_t key_len = parse_ref(cfg->id.key, &key);
        tls->api->set_own_cert(tls->ctx, cert, cert_len, key, key_len);
    }

    CATCH(ziti) {
        return ERR(ziti);
    }

    *ctx = tls;
    return ZITI_OK;
}

int ziti_init_opts(ziti_options *options, uv_loop_t *loop) {
    ziti_log_init(loop, ZITI_LOG_DEFAULT_LEVEL, NULL);
    metrics_init(loop, 5);

    PREPF(ziti, ziti_errorstr);

    if (options->config == NULL && (options->controller == NULL || options->tls == NULL)) {
        ZITI_LOG(ERROR, "config or controller/tls has to be set");
        return ZITI_INVALID_CONFIG;
    }

    ziti_config *cfg = NULL;
    if (options->config != NULL) {
        TRY(ziti, load_config(options->config, &cfg));
    }
    if (options->controller == NULL) {
        options->controller = strdup(cfg->controller_url);
    }

    tls_context *tls = options->tls;
    if (tls == NULL) {
        TRY(ziti, load_tls(cfg, &tls));
    }

    free_ziti_config(cfg);
    free(cfg);

    NEWP(ctx, struct ziti_ctx);
    ctx->opts = options;
    ctx->tlsCtx = tls;
    ctx->loop = loop;
    ctx->ziti_timeout = ZITI_DEFAULT_TIMEOUT;
    ctx->ctrl_status = ZITI_WTF;

    STAILQ_INIT(&ctx->w_queue);
    uv_async_init(loop, &ctx->w_async, ztx_work_async);
    ctx->w_async.data = ctx;
    uv_mutex_init(&ctx->w_lock);

    NEWP(init_req, struct ziti_init_req);
    init_req->start = !options->disabled;
    ziti_queue_work(ctx, ziti_init_async, init_req);

    CATCH(ziti) {
        return ERR(ziti);
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
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->api_session_state, ZitiApiSessionStateAuthStarted);
    free_ziti_api_session(ztx->api_session);
    FREE(ztx->api_session);
    ztx->api_session_state = ZitiApiSessionStateAuthStarted;
}

void ziti_set_unauthenticated(ziti_context ztx) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->api_session_state, ZitiApiSessionStateUnauthenticated);

    free_ziti_api_session(ztx->api_session);
    FREE(ztx->api_session);
    ztx->api_session_state = ZitiApiSessionStateUnauthenticated;

    ziti_ctrl_clear_api_session(&ztx->controller);
}

void ziti_set_impossible_to_authenticate(ziti_context ztx) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->api_session_state, ZitiApiSessionImpossibleToAuthenticate);

    free_ziti_api_session(ztx->api_session);
    FREE(ztx->api_session);
    ztx->api_session_state = ZitiApiSessionImpossibleToAuthenticate;

    ziti_ctrl_clear_api_session(&ztx->controller);
}

void ziti_set_partially_authenticated(ziti_context ztx) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->api_session_state, ZitiApiSessionStatePartiallyAuthenticated);
    ztx->api_session_state = ZitiApiSessionStatePartiallyAuthenticated;
}

void ziti_set_fully_authenticated(ziti_context ztx) {
    ZTX_LOG(DEBUG, "setting api_session_state[%d] to %d", ztx->api_session_state, ZitiApiSessionStateFullyAuthenticated);
    ztx->api_session_state = ZitiApiSessionStateFullyAuthenticated;
}

static bool is_api_session_expired(ziti_context ztx) {
    if (ztx->api_session == NULL) {
        ZTX_LOG(DEBUG, "is_api_session_expired[TRUE] - api_session is null");
        return true;
    }

    uv_timeval64_t now;
    uv_gettimeofday(&now);

    if (ztx->api_session_expires_at.tv_sec < now.tv_sec) {
        ZTX_LOG(DEBUG, "is_api_session_expired[TRUE] - expires->tv_sec[%ld] < now->tv_sec[%ld]", ztx->api_session->expires->tv_sec, now.tv_sec);
        return true;
    }

    ZTX_LOG(DEBUG, "is_api_session_expired[FALSE] - default case");
    return false;
}

static void logout_cb(void *resp, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    ziti_set_unauthenticated(ztx);

    model_map_clear(&ztx->sessions, (_free_f) free_ziti_net_session);
    model_map_clear(&ztx->services, (_free_f) free_ziti_service);

    if (ztx->closing) {
        shutdown_and_free(ztx);
    }
}

void ziti_stop_api_session_refresh(ziti_context ztx) {
    ZTX_LOG(DEBUG, "ziti_stop_api_session_refresh: stopping api session refresh");
    uv_timer_stop(ztx->api_session_timer);
}

void ziti_schedule_api_session_refresh(ziti_context ztx, uint64_t timeout_ms) {
    ZTX_LOG(DEBUG, "ziti_schedule_api_session_refresh: scheduling api session refresh: %ldms", timeout_ms);
    uv_timer_start(ztx->api_session_timer, api_session_refresh, timeout_ms, 0);
}

void ziti_force_api_session_refresh(ziti_context ztx) {
    ZTX_LOG(DEBUG, "forcing session refresh");
    ziti_schedule_api_session_refresh(ztx, 0);
}

static void ziti_stop_internal(ziti_context ztx, void *data) {
    if (ztx->enabled) {
        ztx->enabled = false;

        metrics_rate_close(&ztx->up_rate);
        metrics_rate_close(&ztx->down_rate);

        // stop updates
        uv_close((uv_handle_t *) ztx->service_refresh_timer, (uv_close_cb) free);
        ztx->service_refresh_timer = NULL;
        ziti_stop_api_session_refresh(ztx);
        uv_close((uv_handle_t *) ztx->api_session_timer, (uv_close_cb) free);
        ztx->api_session_timer = NULL;

        if (ztx->posture_checks && ztx->posture_checks->timer) {
            uv_timer_stop(ztx->posture_checks->timer);
        }

        // close all channels
        ziti_close_channels(ztx, ZITI_DISABLED);

        const char *svc_name;
        ziti_service *svc;
        ziti_event_t ev = {0};
        ev.type = ZitiServiceEvent;
        ev.event.service.removed = calloc(model_map_size(&ztx->services) + 1, sizeof(ziti_service *));
        int idx = 0;
        MODEL_MAP_FOREACH(svc_name, svc, &ztx->services) {
            ev.event.service.removed[idx++] = svc;
        }

        ziti_send_event(ztx, &ev);
        FREE(ev.event.service.removed);

        // logout
        ziti_ctrl_logout(&ztx->controller, logout_cb, ztx);

        ev.type = ZitiContextEvent;
        ev.event.ctx.ctrl_status = ZITI_DISABLED;

        ziti_send_event(ztx, &ev);
    }
}

static void ziti_start_internal(ziti_context ztx, void *init_req) {
    if (!ztx->enabled) {
        ztx->enabled = true;
        uv_prepare_start(ztx->reaper, grim_reaper);
        ziti_ctrl_get_version(&ztx->controller, version_cb, ztx);
        ziti_set_unauthenticated(ztx);
        ziti_re_auth(ztx);
    }
}

static void on_ctrl_change(const char *new_addr, void *ctx) {
    ziti_context ztx = ctx;

    ziti_event_t ev = {
            .type = ZitiAPIEvent,
            .event.api.new_ctrl_address = new_addr,
    };
    ziti_send_event(ztx, &ev);
}

static void ziti_init_async(ziti_context ztx, void *data) {
    ztx->id = ztx_seq++;
    uv_loop_t *loop = ztx->w_async.loop;
    struct ziti_init_req *init_req = data;

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    char time_str[32];
    ziti_fmt_time(time_str, sizeof(time_str), &start_time);

    ZTX_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting at (%s.%03d)",
            ziti_get_build_version(false), ziti_git_commit(), ziti_git_branch(),
            time_str, start_time.tv_usec / 1000);
    ZTX_LOG(INFO, "using uv_mbed[%s], tls[%s]", uv_mbed_version(), ztx->tlsCtx->api->version ? ztx->tlsCtx->api->version() : "unspecified");
    ZTX_LOG(INFO, "Loading from config[%s] controller[%s]", ztx->opts->config, ztx_controller(ztx));

    ziti_ctrl_init(loop, &ztx->controller, ztx_controller(ztx), ztx->tlsCtx);
    ziti_ctrl_set_redirect_cb(&ztx->controller, on_ctrl_change, ztx);
    if (ztx->opts->api_page_size != 0) {
        ziti_ctrl_set_page_size(&ztx->controller, ztx->opts->api_page_size);
    }

    ztx->api_session_timer = calloc(1, sizeof(uv_timer_t));
    uv_timer_init(loop, ztx->api_session_timer);
    ztx->api_session_timer->data = ztx;

    ztx->service_refresh_timer = calloc(1, sizeof(uv_timer_t));
    uv_timer_init(loop, ztx->service_refresh_timer);
    if (ztx->opts->refresh_interval == 0) {
        uv_unref((uv_handle_t *) ztx->service_refresh_timer);
    }
    ztx->service_refresh_timer->data = ztx;

    ztx->reaper = calloc(1, sizeof(uv_prepare_t));
    uv_prepare_init(loop, ztx->reaper);
    ztx->reaper->data = ztx;
    uv_unref((uv_handle_t *) ztx->reaper);

    ZTX_LOG(DEBUG, "using metrics interval: %d", (int) ztx->opts->metrics_type);
    metrics_rate_init(&ztx->up_rate, ztx->opts->metrics_type);
    metrics_rate_init(&ztx->down_rate, ztx->opts->metrics_type);

    if (init_req->start) {
        ziti_start_internal(ztx, NULL);
    }
    free(init_req);
}

int ziti_init(const char *config, uv_loop_t *loop, ziti_event_cb event_cb, int events, void *app_ctx) {

    NEWP(opts, ziti_options);
    opts->config = config;
    opts->events = events;
    opts->event_cb = event_cb;
    opts->app_ctx = app_ctx;
    opts->config_types = ALL_CONFIG_TYPES;

    return ziti_init_opts(opts, loop);
}

extern void *ziti_app_ctx(ziti_context ztx) {
    return ztx->opts->app_ctx;
}

const char *ziti_get_controller(ziti_context ztx) {
    return ztx_controller(ztx);
}

const ziti_version *ziti_get_controller_version(ziti_context ztx) {
    return &ztx->controller.version;
}

const ziti_identity *ziti_get_identity(ziti_context ztx) {
    if (ztx->identity_data) {
        return (const ziti_identity *) ztx->identity_data;
    }

    if (ztx->api_session) {
        return ztx->api_session->identity;
    }

    return NULL;
}

void ziti_get_transfer_rates(ziti_context ztx, double *up, double *down) {
    *up = metrics_rate_get(&ztx->up_rate);
    *down = metrics_rate_get(&ztx->down_rate);
}

int ziti_set_timeout(ziti_context ztx, int timeout) {
    if (timeout > 0) {
        ztx->ziti_timeout = timeout;
    } else {
        ztx->ziti_timeout = ZITI_DEFAULT_TIMEOUT;
    }
    return ZITI_OK;
}

static void free_ztx(uv_handle_t *h) {
    ziti_context ztx = h->data;

    ziti_ctrl_close(&ztx->controller);

    if (ztx->tlsCtx != ztx->opts->tls) {
        ztx->tlsCtx->api->free_ctx(ztx->tlsCtx);
    }
    ziti_auth_query_free(ztx->auth_queries);
    ziti_posture_checks_free(ztx->posture_checks);
    model_map_clear(&ztx->services, (_free_f) free_ziti_service);
    model_map_clear(&ztx->sessions, (_free_f) free_ziti_net_session);
    ziti_set_unauthenticated(ztx);
    free_ziti_identity_data(ztx->identity_data);
    FREE(ztx->identity_data);
    FREE(ztx->last_update);

    ZTX_LOG(INFO, "shutdown is complete\n");
    free(ztx);
}

static void shutdown_and_free(ziti_context ztx) {
    if (model_map_size(&ztx->channels) > 0) {
        ZTX_LOG(INFO, "waiting for %zd channels to disconnect", model_map_size(&ztx->channels));
        return;
    }

    if (ztx->api_session) {
        ZTX_LOG(INFO, "waiting for logout");
        return;
    }

    grim_reaper(ztx->reaper);
    uv_close((uv_handle_t *) ztx->reaper, (uv_close_cb) free);
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
    printer(ctx, "\n=================\nZiti Context:\n");
    printer(ctx, "ID:\t%d\n", ztx->id);
    printer(ctx, "Enabled:\t%s\n", ziti_is_enabled(ztx) ? "true" : "false");
    printer(ctx, "Config:\t%s\n", ztx->opts->config);
    printer(ctx, "Controller:\t%s\n", ztx_controller(ztx));
    printer(ctx, "Config types:\n");
    for (int i = 0; ztx->opts->config_types && ztx->opts->config_types[i]; i++) {
        printer(ctx, "\t%s\n", ztx->opts->config_types[i]);
    }
    printer(ctx, "Identity:\t");
    if (ztx->identity_data) {
        printer(ctx, "%s[%s]\n", ztx->identity_data->name, ztx->identity_data->id);
    } else {
        printer(ctx, "unknown - never logged in\n");
    }

    printer(ctx, "\n=================\nAPI Session:\n");

    if (ztx->api_session) {
        printer(ctx, "Session Info: \napi_session[%s]\napi_session_state[%d]\n", ztx->api_session->id, ztx->api_session_state);
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
    ziti_net_session *sess;
    MODEL_MAP_FOREACH(name, sess, &ztx->sessions) {
        printer(ctx, "%s: service_id[%s]\n", sess->id, name);
    }

    printer(ctx, "\n==================\nChannels:\n");
    ziti_channel_t *ch;
    const char *url;
    MODEL_MAP_FOREACH(url, ch, &ztx->channels) {
        printer(ctx, "ch[%d](%s) ", ch->id, url);
        if (ziti_channel_is_connected(ch)) {
            printer(ctx, "connected [latency=%ld]\n", (long) ch->latency);
        } else {
            printer(ctx, "Disconnected\n", (long) ch->latency);
        }
    }

    printer(ctx, "\n==================\nConnections:\n");
    ziti_connection conn;
    LIST_FOREACH(conn, &ztx->connections, next) {
        if (conn->parent == NULL) {
            printer(ctx, "conn[%d]: state[%s] service[%s] using ch[%d] %s\n",
                    conn->conn_id, ziti_conn_state(conn), conn->service,
                    conn->channel ? conn->channel->id : -1,
                    conn->channel ? conn->channel->name : "(none)");

            model_map_iter it = model_map_iterator(&conn->children);
            while (it != NULL) {
                uint32_t child_id = model_map_it_lkey(it);
                ziti_connection child = model_map_it_value(it);
                printer(ctx, "\tchild[%d]: state[%s] caller_id[%s]\n",
                        child_id, ziti_conn_state(child), ziti_conn_source_identity(child)
                );
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
    c->channel = NULL;
    c->timeout = ctx->ziti_timeout;
    c->edge_msg_seq = 1;
    c->conn_id = ztx->conn_seq++;
    c->inbound = new_buffer();
    TAILQ_INIT(&c->in_q);
    TAILQ_INIT(&c->wreqs);

    *conn = c;
    LIST_INSERT_HEAD(&ctx->connections, c, next);
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
    if (ztx->enabled || e->type == ZitiContextEvent) {
        if ((ztx->opts->events & e->type) && ztx->opts->event_cb) {
            ztx->opts->event_cb(ztx, e);
        }
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
        model_map_set(&req->ztx->services, s->name, s);
        rc = ZITI_OK;
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

    ziti_ctrl_get_service(&ztx->controller, service, service_cb, req);
    return ZITI_OK;
}

int ziti_listen(ziti_connection serv_conn, const char *service, ziti_listen_cb lcb, ziti_client_cb cb) {
    return ziti_bind(serv_conn, service, NULL, lcb, cb);
}

int ziti_listen_with_options(ziti_connection serv_conn, const char *service, ziti_listen_opts *listen_opts,
                             ziti_listen_cb lcb, ziti_client_cb cb) {
    return ziti_bind(serv_conn, service, listen_opts, lcb, cb);
}

static void api_session_refresh(uv_timer_t *t) {
    ziti_context ztx = t->data;

    ZTX_LOG(DEBUG, "api_session_refresh running");

    bool no_session = ztx->api_session == NULL;
    bool is_expired = is_api_session_expired(ztx);

    if (no_session || is_expired) {
        ZTX_LOG(DEBUG, "api_session_refresh re-auth due to no active api session[%s] or session expiration[%s]",
                no_session ? "TRUE" : "FALSE", is_expired ? "TRUE" : "FALSE");
        ziti_re_auth(ztx);
    } else {
        // to attempt a refresh the api session needs to be partially or fully authenticated
        // api_session_cb will handle transitions to unauthenticated and subsequent re-auths.
        if (ztx->api_session_state == ZitiApiSessionStatePartiallyAuthenticated || ztx->api_session_state == ZitiApiSessionStateFullyAuthenticated) {
            struct ziti_init_req *req = calloc(1, sizeof(struct ziti_init_req));
            req->ztx = ztx;
            ZTX_LOG(DEBUG, "api_session_refresh refreshing api session by querying controller");
            ziti_ctrl_current_api_session(&ztx->controller, api_session_cb, req);
        } else {
            ZTX_LOG(DEBUG, "api_session_refresh refreshing api session skipped, waiting for api session state change");
        }
    }
}

void ziti_re_auth_with_cb(ziti_context ztx, void(*cb)(ziti_api_session *, const ziti_error *, void *), void *ctx) {
    bool is_expired = is_api_session_expired(ztx);

    ZTX_LOG(INFO, "starting to re-auth with ctlr[%s] api_session_status[%d] api_session_expired[%s]",
            ztx_controller(ztx), ztx->api_session_state, is_expired ? "TRUE" : "FALSE");

    bool is_auth_started = ztx->api_session_state == ZitiApiSessionStateAuthStarted;
    bool authed_and_not_expired = (ztx->api_session_state == ZitiApiSessionStatePartiallyAuthenticated ||
                                   ztx->api_session_state == ZitiApiSessionStateFullyAuthenticated)
                                  && !is_expired;

    if (is_auth_started || authed_and_not_expired) {
        ZTX_LOG(VERBOSE, "re-auth aborted, api session state is currently authenticating/authenticated and not expired: "
                         "api_session_status[%d] api_session_expired[%s]",
                ztx->api_session_state, is_expired ? "TRUE" : "FALSE");

        ziti_error err = {
                .err = ZITI_PARTIALLY_AUTHENTICATED
        };
        cb(NULL, &err, ctx);

        return;
    }

    ziti_set_auth_started(ztx);

    uv_timer_stop(ztx->service_refresh_timer);
    ziti_stop_api_session_refresh(ztx);
    if (ztx->posture_checks) {
        uv_timer_stop(ztx->posture_checks->timer);
    }

    model_map_clear(&ztx->sessions, (_free_f) free_ziti_net_session);
    FREE(ztx->last_update);

    ziti_ctrl_login(&ztx->controller, ztx->opts->config_types, cb, ctx);
}

/**
 * `ziti_re_auth` attempts to re-authenticate with the controller. However
 * this will be ignored if the current `ziti_context` believes it is in a
 * partially authenticated state. If desired, called `ziti_set_unauthenticated`
 * to by pass this state.
 * @param ztx
 * @param force
 */
static void ziti_re_auth(ziti_context ztx) {
    if (ztx->api_session_state != ZitiApiSessionStateAuthStarted) {
        ZTX_LOG(DEBUG, "re-auth executing, transitioning to unauthenticated");
        ziti_set_unauthenticated(ztx);

        NEWP(init_req, struct ziti_init_req);
        init_req->ztx = ztx;
        init_req->start = true;

        ziti_re_auth_with_cb(ztx, api_session_cb, init_req);
    } else {
        ZTX_LOG(DEBUG, "re-auth aborted, re-auth already started");
    }
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
    NEWP(val, bool);
    *val = true;
    void* old = model_map_set(&ztx->service_forced_updates, service_id, val);
    FREE(old);
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
    if (model_map_get(&ztx->service_forced_updates, new->id) != NULL) {
        model_map_remove(&ztx->service_forced_updates, new->id);
        return 1;
    }

    //check for config change, find meta
    type_meta *ziti_service_meta = get_ziti_service_meta();
    int i = 0;
    bool is_config_found = false;
    for (i = 0; i < ziti_service_meta->field_count; i++) {
        if (strcmp(ziti_service_meta->fields[i].name, "config") == 0) {
            is_config_found = true;
            break;
        }
    }

    if (is_config_found) {
        type_meta *config_field_meta = ziti_service_meta->fields[i].meta();
        if (model_map_compare(&old->config, &new->config, config_field_meta) != 0) {
            ZTX_LOG(VERBOSE, "service [%s] is updated, config changed", new->name);
            return 1;
        }
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
    if (ztx->opts->refresh_interval > 0) {
        ZTX_LOG(VERBOSE, "scheduling service refresh %ld seconds from now", ztx->opts->refresh_interval);
        uv_timer_start(ztx->service_refresh_timer, ziti_services_refresh, ztx->opts->refresh_interval * 1000, 0);
    }

    if (error) {
        ZTX_LOG(ERROR, "failed to get service updates err[%s/%s] from ctrl[%s]", error->code, error->message,
                ztx_controller(ztx));
        if (error->err == ZITI_NOT_AUTHORIZED) {
            ZTX_LOG(WARN, "api session is no longer valid. Trying to re-auth");
            ziti_re_auth(ztx);
        } else if (error->err == ZITI_PARTIALLY_AUTHENTICATED) {
            ZTX_LOG(VERBOSE, "api session partially authenticated, waiting for api session state change");
            return;
        } else {
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
            .event.service = {
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
                ev.event.service.changed[chIdx++] = updt;
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
            ev.event.service.removed[remIdx++] = s;

            ziti_net_session *session = model_map_remove(&ztx->sessions, s->id);
            if (session) {
                free_ziti_net_session(session);
                free(session);
            }
            it = model_map_it_remove(it);
        }
    }

    // what's left are new services
    it = model_map_iterator(&updates);
    while (it != NULL) {
        s = model_map_it_value(it);
        ev.event.service.added[addIdx++] = s;
        it = model_map_it_remove(it);
    }

    // process updates
    for (idx = 0; ev.event.service.changed[idx] != NULL; idx++) {
        s = ev.event.service.changed[idx];
        ziti_service *old = model_map_set(&ztx->services, s->name, s);
        free_ziti_service(old);
        FREE(old);
    }

    // process additions
    for (idx = 0; ev.event.service.added[idx] != NULL; idx++) {
        s = ev.event.service.added[idx];
        model_map_set(&ztx->services, s->name, s);
    }

    if (addIdx > 0 || remIdx > 0 || chIdx > 0) {
        ZTX_LOG(DEBUG, "sending service event %zd added, %zd removed, %zd changed", addIdx, remIdx, chIdx);
        ziti_send_event(ztx, &ev);
    } else {
        ZTX_LOG(VERBOSE, "no services added, changed, or removed");
    }

    // cleanup
    for (idx = 0; ev.event.service.removed[idx] != NULL; idx++) {
        s = ev.event.service.removed[idx];
        free_ziti_service(s);
        free(s);
    }

    free(ev.event.service.removed);
    free(ev.event.service.added);
    free(ev.event.service.changed);

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
    bool need_update = true;

    if (err) { // API not supported - do refresh
        if (err->http_code == 404) {
            ZTX_LOG(INFO, "Controller does not support /current-api-session/service-updates API");
            ztx->no_service_updates_api = true;
        }
    } else if (ztx->last_update == NULL || strcmp(ztx->last_update, update->last_change) != 0) {
        ZTX_LOG(VERBOSE, "ztx last_update = %s", update->last_change);
        FREE(ztx->last_update);
        ztx->last_update = update->last_change;
    } else {
        ZTX_LOG(VERBOSE, "not updating: last_update is same previous (%s == %s)", update->last_change,
                ztx->last_update);
        free_ziti_service_update(update);
        need_update = false;

        uv_timer_start(ztx->service_refresh_timer, ziti_services_refresh, ztx->opts->refresh_interval * 1000, 0);
    }

    if (need_update) {
        ziti_ctrl_get_services(&ztx->controller, update_services, ztx);
    }
    FREE(update);
}

void ziti_services_refresh(uv_timer_t *t) {
    ziti_context ztx = t->data;

    if (ztx->auth_queries->outstanding_auth_query_ctx) {
        ZTX_LOG(DEBUG, "service refresh stopped, outstanding auth queries");
        return;
    }

    if (ztx->no_service_updates_api) {
        ziti_ctrl_get_services(&ztx->controller, update_services, ztx);
    } else {
        ziti_ctrl_get_services_update(&ztx->controller, check_service_update, ztx);
    }
}

static void edge_routers_cb(ziti_edge_router_array ers, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    if (err) {
        if (err->http_code == 404) {
            ztx->no_current_edge_routers = true;
        } else {
            ZTX_LOG(ERROR, "failed to get current edge routers: %s/%s", err->code, err->message);
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
        const char *tls = model_map_get(&er->protocols, "tls");

        if (tls) {
            size_t ch_name_len = strlen(er->name) + strlen(tls) + 2;
            char *ch_name = malloc(ch_name_len);
            snprintf(ch_name, ch_name_len, "%s@%s", er->name, tls);
            ZTX_LOG(TRACE, "connecting to %s(%s)", er->name, tls);
            ziti_channel_connect(ztx, ch_name, tls, NULL, NULL);
            model_map_remove(&curr_routers, ch_name);
            free(ch_name);
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
        er_name = model_map_it_value(it);
        ZTX_LOG(INFO, "removing channel[%s]: no longer available", er_name);
        ch = model_map_remove(&ztx->channels, er_name);
        ziti_channel_close(ch, ZITI_GATEWAY_UNAVAILABLE);
        it = model_map_it_remove(it);
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

    update_ctrl_status(ztx, FIELD_OR_ELSE(err, err, 0), FIELD_OR_NULL(err, message));
}

void update_session_data(ziti_api_session *session, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    if (err != NULL) {
        ZTX_LOG(ERROR, "error refreshing current api session immediately after auth query processing: err[%s]", ziti_errorstr(err->err));
    }

    if (session) {
        ziti_set_api_session(ztx, session);
        ZTX_LOG(DEBUG, "api session after authentication query processing complete");
    }
}

static void session_post_auth_query_cb(ziti_context ztx, int status, void *ctx) {
    ZTX_LOG(VERBOSE, "post auth query callback starting with status[%s]", ziti_errorstr(status));
    if (status == ZITI_OK) {
        ZTX_LOG(VERBOSE, "transitioning to fully authenticated");
        ziti_api_session *session = ztx->api_session;

        ziti_set_fully_authenticated(ztx);

        update_ctrl_status(ztx, ZITI_OK, NULL);

        ziti_ctrl_current_identity(&ztx->controller, update_identity_data, ztx);

        //if we had auth queries, refresh state to zero out
        if (session->auth_queries != NULL && *session->auth_queries != NULL) {
            ziti_ctrl_current_api_session(&ztx->controller, update_session_data, ztx);
        }

        if (ztx->opts->refresh_interval > 0 && !uv_is_active((const uv_handle_t *) &ztx->service_refresh_timer)) {
            ZTX_LOG(DEBUG, "refresh_interval set to %ld seconds", ztx->opts->refresh_interval);
            ziti_services_refresh(ztx->service_refresh_timer);
        } else if (ztx->opts->refresh_interval == 0) {
            ZTX_LOG(DEBUG, "refresh_interval not specified");
            uv_timer_stop(ztx->service_refresh_timer);
        }

        ziti_posture_init(ztx, 20);

        if (!ztx->no_current_edge_routers) {
            ziti_ctrl_current_edge_routers(&ztx->controller, edge_routers_cb, ztx);
        }
    } else {
        ZTX_LOG(VERBOSE, "transitioning to unauthenticated, unhandled status[%s]", ziti_errorstr(status));
        ziti_set_unauthenticated(ztx); //disable?
        update_ctrl_status(ztx, ZITI_NOT_AUTHORIZED, NULL);
    }
}

void ziti_set_api_session(ziti_context ztx, ziti_api_session *session) {
    if (ztx->api_session == session) {
        ZTX_LOG(WARN, "api session attempted to be set with the same value");
        return;
    }

    ziti_api_session *old_session = ztx->api_session;
    ztx->api_session = session;

    uv_gettimeofday(&ztx->session_received_at);

    if (session->expires) {
        int time_diff;
        if (session->cached_last_activity_at) {
            ZTX_LOG(TRACE, "API supports cached_last_activity_at");
            time_diff = (int) (ztx->session_received_at.tv_sec - session->cached_last_activity_at->tv_sec);
        } else {
            ZTX_LOG(TRACE, "API doesn't support cached_last_activity_at - using updated");
            time_diff = (int) (ztx->session_received_at.tv_sec - session->updated->tv_sec);
        }
        if (abs(time_diff) > 10) {
            ZTX_LOG(ERROR, "local clock is %d seconds %s UTC (as reported by controller)", abs(time_diff),
                    time_diff > 0 ? "ahead" : "behind");
        }

        ZTX_LOG(DEBUG, "ziti api session expires in %ld seconds", (long) (session->expires->tv_sec - ztx->session_received_at.tv_sec));

        long delay_seconds = 0;

        if (session->expireSeconds != NULL) {
            delay_seconds = *session->expireSeconds;
        } else {
            // adjust expiration to local time if needed
            session->expires->tv_sec += time_diff;
            delay_seconds = (session->expires->tv_sec - ztx->session_received_at.tv_sec);
        }

        uv_gettimeofday(&ztx->api_session_expires_at);
        ztx->api_session_expires_at.tv_sec = ztx->api_session_expires_at.tv_sec + delay_seconds;

        delay_seconds = delay_seconds - API_SESSION_DELAY_WINDOW_SECONDS; //renew a little early

        if (delay_seconds < API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS) {
            delay_seconds = API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS;
            ZTX_LOG(WARN, "api session expiration window is set too small (<%d) and may cause issues with "
                          "connectivity and api session maintenance, defaulting api session refresh delay [%ds]",
                    API_SESSION_EXPIRATION_TOO_SMALL_SECONDS, API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS);
        }

        ZTX_LOG(INFO, "api session set, setting api_session_timer to %lds", delay_seconds);
        ziti_schedule_api_session_refresh(ztx, delay_seconds * 1000);
    }


    if (session->auth_queries != NULL && *session->auth_queries != NULL) {
        ziti_set_partially_authenticated(ztx);
        update_ctrl_status(ztx, ZITI_PARTIALLY_AUTHENTICATED, NULL);
    } else {
        ziti_set_fully_authenticated(ztx);
        ziti_ctrl_current_identity(&ztx->controller, update_identity_data, ztx);
    }

    free_ziti_api_session(old_session);
    FREE(old_session);
}

static void api_session_cb(ziti_api_session *session, const ziti_error *err, void *ctx) {
    struct ziti_init_req *init_req = ctx;
    ziti_context ztx = init_req->ztx;
    ztx->loop_thread = uv_thread_self();

    int errCode = err ? err->err : ZITI_OK;

    if (session) {

        ZTX_LOG(DEBUG, "%s successfully => api_session[%s]", ztx->api_session ? "refreshed" : "logged in", session->id);

        ziti_set_api_session(ztx, session);

        ziti_auth_query_init(ztx);

        //check for additional authentication requirements, pickup in session_post_auth_query_cb
        ziti_auth_query_process(ztx, session_post_auth_query_cb);
    } else if (err) {
        ZTX_LOG(WARN, "failed to get api session from ctrl[%s] api_session_state[%d] %s[%d] %s",
                ztx_controller(ztx), ztx->api_session_state, err->code, errCode, err->message);

        if (errCode == ZITI_NOT_AUTHORIZED) {
            if (ztx->api_session || !init_req->start) {
                ZTX_LOG(DEBUG, "received NOT_AUTHORIZED attempting re-auth");
                ziti_set_unauthenticated(ztx);
                ziti_re_auth(ztx);
                errCode = ztx->ctrl_status; // do not trigger event yet
            } else {
                // cannot login or re-auth -- identity no longer valid
                // notify service removal, and state
                ziti_set_impossible_to_authenticate(ztx);

                ZTX_LOG(ERROR, "identity[%s] cannot authenticate with ctrl[%s]", ztx->opts->config,
                        ztx_controller(ztx));
                ziti_event_t service_event = {
                        .type = ZitiServiceEvent,
                        .event.service = {
                                .removed = calloc(model_map_size(&ztx->services) + 1, sizeof(ziti_service *)),
                                .added = NULL,
                                .changed = NULL,
                        }
                };

                const char *name;
                ziti_service *srv;
                size_t idx = 0;
                MODEL_MAP_FOREACH(name, srv, &ztx->services) {
                    service_event.event.service.removed[idx++] = srv;
                }

                ziti_send_event(ztx, &service_event);
                model_map_clear(&ztx->services, (_free_f) free_ziti_service);

                ziti_stop_api_session_refresh(ztx);
                uv_timer_stop(ztx->service_refresh_timer);
                if (ztx->posture_checks != NULL) {
                    uv_timer_stop(ztx->posture_checks->timer);
                }
            }
        } else {
            ZTX_LOG(DEBUG, "unhandled error, setting api_session_timer to 5s");
            ziti_set_unauthenticated(ztx);
            ziti_schedule_api_session_refresh(ztx, 5 * 1000);
        }

        update_ctrl_status(ztx, errCode, err ? err->message : NULL);
    } else {
        ZTX_LOG(ERROR, "%s: no api session or error received", ziti_errorstr(ZITI_WTF));
    }

    FREE(init_req);
}

static void update_ctrl_status(ziti_context ztx, int errCode, const char *errMsg) {
    if (ztx->ctrl_status != errCode) {
        ziti_event_t ev = {
                .type = ZitiContextEvent,
                .event.ctx = {
                        .ctrl_status = errCode,
                        .err = errMsg,
                }};
        ztx->ctrl_status = errCode;
        ziti_send_event(ztx, &ev);
    }
}

static void version_cb(ziti_version *v, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    if (err != NULL) {
        ZTX_LOG(ERROR, "failed to get controller version from %s %s(%s)",
                ztx_controller(ztx), err->code, err->message);
    } else {
        ZTX_LOG(INFO, "connected to controller %s version %s(%s %s)",
                ztx_controller(ztx), v->version, v->revision, v->build_date);
        free_ziti_version(v);
        FREE(v);
    }
}

void ziti_invalidate_session(ziti_context ztx, ziti_net_session *session, const char *service_id, ziti_session_type type) {
    if (session == NULL) {
        return;
    }

    if (type == ziti_session_types.Dial) {
        ziti_net_session *s = model_map_get(&ztx->sessions, service_id);
        if (s != session) {
            // already removed or different one
            // passed reference is no longer valid
            session = NULL;
        } else if (s == session) {
            model_map_remove(&ztx->sessions, session->service_id);
        }
    }

    free_ziti_net_session(session);
    FREE(session);
}

static const ziti_version sdk_version = {
        .version = to_str(ZITI_VERSION),
        .revision = to_str(ZITI_COMMIT),
        .build_date = to_str(BUILD_DATE)
};

const ziti_version *ziti_get_version() {
    return &sdk_version;
}

static void grim_reaper(uv_prepare_t *p) {
    ziti_context ztx = p->data;

    int total = 0;
    int count = 0;

    ziti_connection conn = LIST_FIRST(&ztx->connections);
    if (conn == NULL && !ztx->enabled) {
        // context disabled and no connections
        uv_prepare_stop(p);
        return;
    }

    while (conn != NULL) {
        ziti_connection try_close = conn;
        total++;
        conn = LIST_NEXT(conn, next);
        count += close_conn_internal(try_close);
    }
    if (count > 0) {
        ZTX_LOG(DEBUG, "reaped %d closed (out of %d total) connections", count, total);
    }
}

void ziti_on_channel_event(ziti_channel_t *ch, ziti_router_status status, ziti_context ztx) {
    ziti_event_t ev = {
            .type = ZitiRouterEvent,
            .event.router = {
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
