/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


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

#define ZTX_LOG(lvl,fmt, ...) ZITI_LOG(lvl, "ztx[%d] " fmt, ztx->id, ##__VA_ARGS__)

static const char *ALL_CONFIG_TYPES[] = {
        "all",
        NULL
};

struct ziti_init_req {
    ziti_context ztx;
    bool login;
    int init_status;
};

int code_to_error(const char *code);

static void update_ctrl_status(ziti_context ztx, int code, const char *msg);

static void services_refresh(uv_timer_t *t);

static void version_cb(ziti_version *v, const ziti_error *err, void *ctx);

static void session_cb(ziti_session *session, const ziti_error *err, void *ctx);

static void ziti_init_async(uv_async_t *ar);

static void ziti_re_auth(ziti_context ztx);

static void grim_reaper(uv_prepare_t *p);

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
    if (options->tls == NULL) {
        TRY(ziti, load_tls(cfg, &options->tls));
    }

    free_ziti_config(cfg);
    free(cfg);

    NEWP(ctx, struct ziti_ctx);
    ctx->opts = options;
    ctx->tlsCtx = options->tls;
    ctx->loop = loop;
    ctx->ziti_timeout = ZITI_DEFAULT_TIMEOUT;
    ctx->ctrl_status = ZITI_WTF;

    NEWP(init_req, struct ziti_init_req);
    init_req->ztx = ctx;

    NEWP(async_init_req, uv_async_t);
    uv_async_init(loop, async_init_req, ziti_init_async);
    async_init_req->data = init_req;

    uv_async_send(async_init_req);

    CATCH(ziti) {
        return ERR(ziti);
    }

    return ZITI_OK;
}

static void ziti_init_async(uv_async_t *ar) {
    struct ziti_init_req *init_req = ar->data;

    ziti_context ztx = init_req->ztx;
    uv_loop_t *loop = ar->loop;
    ztx->id = ztx_seq++;

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    char time_str[32];
    ziti_fmt_time(time_str, sizeof(time_str), &start_time);

    ZTX_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting at (%s.%03d)",
             ziti_get_build_version(false), ziti_git_commit(), ziti_git_branch(),
             time_str, start_time.tv_usec / 1000);
    ZTX_LOG(INFO, "Loading from config[%s] controller[%s]", ztx->opts->config, ztx->opts->controller);

    init_req->login = true;
    ziti_ctrl_init(loop, &ztx->controller, ztx->opts->controller, ztx->tlsCtx);
    ziti_ctrl_get_version(&ztx->controller, version_cb, ztx);

    uv_timer_init(loop, &ztx->session_timer);
    ztx->session_timer.data = ztx;

    uv_timer_init(loop, &ztx->refresh_timer);
    if (ztx->opts->refresh_interval == 0) {
        uv_unref((uv_handle_t *) &ztx->refresh_timer);
    }
    ztx->refresh_timer.data = ztx;

    uv_prepare_init(loop, &ztx->reaper);
    ztx->reaper.data = ztx;
    uv_unref((uv_handle_t *) &ztx->reaper);
    uv_prepare_start(&ztx->reaper, grim_reaper);

    ZTX_LOG(DEBUG, "using metrics interval: %d", (int) ztx->opts->metrics_type);
    metrics_rate_init(&ztx->up_rate, ztx->opts->metrics_type);
    metrics_rate_init(&ztx->down_rate, ztx->opts->metrics_type);

    init_req->login = true;
    ziti_ctrl_login(&ztx->controller, ztx->opts->config_types, session_cb, init_req);
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
    return ztx->opts->controller;
}

const ziti_version *ziti_get_controller_version(ziti_context ztx) {
    return &ztx->controller.version;
}

const ziti_identity *ziti_get_identity(ziti_context ztx) {
    return ztx->session ? ztx->session->identity : NULL;
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

static void on_logout(void *msg, const ziti_error *err, void *arg) {
    ziti_context ztx = arg;
    ZTX_LOG(DEBUG, "identity[%s] logout %s",
            ztx->session->identity->name, err ? "failed" : "success");

    free_ziti_identity_data(ztx->identity_data);
    FREE(ztx->identity_data);
    free_ziti_session(ztx->session);
    free(ztx->session);
    ztx->session = NULL;

    ziti_ctrl_close(&ztx->controller);
}

int ziti_shutdown(ziti_context ztx) {
    ZTX_LOG(INFO, "Ziti is shutting down");

    uv_timer_stop(&ztx->refresh_timer);
    uv_timer_stop(&ztx->session_timer);
    uv_timer_stop(ztx->posture_checks->timer);

    ziti_close_channels(ztx);

    ziti_ctrl_logout(&ztx->controller, on_logout, ztx);
    metrics_rate_close(&ztx->up_rate);
    metrics_rate_close(&ztx->down_rate);

    return ZITI_OK;
}

int ziti_ctx_free(ziti_context *ctxp) {
    if (ctxp == NULL || *ctxp == NULL) { return ZITI_OK; }

    ziti_context ztx = *ctxp;
    if ((*ctxp)->tlsCtx != NULL) {
        (*ctxp)->tlsCtx->api->free_ctx((*ctxp)->tlsCtx);
    }
    ziti_auth_query_free((*ctxp)->auth_queries);
    ziti_posture_checks_free((*ctxp)->posture_checks);
    model_map_clear(&(*ctxp)->services, (_free_f) free_ziti_service);
    model_map_clear(&(*ctxp)->sessions, (_free_f) free_ziti_net_session);
    free_ziti_session((*ctxp)->session);
    FREE((*ctxp)->session);

    ZTX_LOG(INFO, "shutdown is complete\n");
    free(*ctxp);
    *ctxp = NULL;

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

    if(parse_func(data, app_data_json, strlen(app_data_json)) != 0) {
        return ZITI_INVALID_CONFIG;
    }

    return ZITI_OK;
}


void ziti_dump(ziti_context ztx, int (*printer)(void *arg, const char *fmt, ...), void *ctx) {
    printer(ctx, "\n=================\nZiti Context:\n");
    printer(ctx, "ID:\t%d\n", ztx->id);
    printer(ctx, "Config:\t%s\n", ztx->opts->config);
    printer(ctx, "Controller:\t%s\n", ztx->opts->controller);
    printer(ctx, "Config types:\n");
    for (int i = 0; ztx->opts->config_types && ztx->opts->config_types[i]; i++) {
        printer(ctx, "\t%s\n", ztx->opts->config_types[i]);
    }

    printer(ctx, "\n=================\nSession:\n");

    if (ztx->session) {
        printer(ctx, "Session Info: id[%s] name[%s] api_session[%s]\n",
                ztx->session->identity->id, ztx->session->identity->name, ztx->session->id);
    } else {
        printer(ctx, "No Session found\n");
    }

    printer(ctx, "\n=================\nServices:\n");
    ziti_service *zs;
    const char *name;
    const char *cfg;
    const char *cfg_json;
    MODEL_MAP_FOREACH(name, zs, &ztx->services) {

        printer(ctx, "%s: id[%s] perm(dial=%s,bind=%s)\n", zs->name, zs->id,
                (zs->perm_flags & ZITI_CAN_DIAL ? "true" : "false"),
                (zs->perm_flags & ZITI_CAN_BIND ? "true" : "false")
        );

        MODEL_MAP_FOREACH(cfg, cfg_json, &zs->config) {
            printer(ctx, "\tconfig[%s]=%s\n", cfg, cfg_json);
        }
    }

    printer(ctx, "\n==================\nNet Sessions:\n");
    ziti_net_session *it;
    MODEL_MAP_FOREACH(name, it, &ztx->sessions) {
        printer(ctx, "%s: service_id[%s]\n", it->id, name);
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
        printer(ctx, "conn[%d]: state[%s] service[%s] using ch[%d] %s\n",
                conn->conn_id, ziti_conn_state(conn), conn->service,
                conn->channel ? conn->channel->id : -1,
                conn->channel ? conn->channel->name : "(none)");
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

const char *ziti_conn_source_identity(ziti_connection conn) {
    return conn != NULL ? conn->source_identity : NULL;
}


void ziti_send_event(ziti_context ztx, const ziti_event_t *e) {
    if ((ztx->opts->events & e->type) && ztx->opts->event_cb) {
        ztx->opts->event_cb(ztx, e);
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
        if (strcmp(s->permissions[i], "Dial") == 0) {
            s->perm_flags |= ZITI_CAN_DIAL;
        }
        if (strcmp(s->permissions[i], "Bind") == 0) {
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

static void session_refresh(uv_timer_t *t) {
    ziti_context ztx = t->data;

    bool login = ztx->session == NULL;

    if (ztx->session) {
        uv_timeval64_t now;
        uv_gettimeofday(&now);

        if (ztx->session->expires->tv_sec < now.tv_sec) {
            ZTX_LOG(DEBUG, "session expired");
            free_ziti_session(ztx->session);
            FREE(ztx->session);
            login = true;
        }
    }

    if (login) {
        ziti_re_auth(ztx);
    } else {
        struct ziti_init_req *req = calloc(1, sizeof(struct ziti_init_req));
        req->ztx = ztx;
        ZTX_LOG(DEBUG, "refreshing API session");
        ziti_ctrl_current_api_session(&ztx->controller, session_cb, req);
    }
}

void ziti_force_session_refresh(ziti_context ztx) {
    uv_timer_start(&ztx->session_timer, session_refresh, 0, 0);
}

void ziti_re_auth_with_cb(ziti_context ztx, void(*cb)(ziti_session *, const ziti_error *, void *), void *ctx) {
    ZTX_LOG(WARN, "starting to re-auth with ctlr[%s]", ztx->opts->controller);
    uv_timer_stop(&ztx->refresh_timer);
    uv_timer_stop(&ztx->session_timer);
    if (ztx->posture_checks) {
        uv_timer_stop(ztx->posture_checks->timer);
    }
    free_ziti_session(ztx->session);
    FREE(ztx->session);
    model_map_clear(&ztx->sessions, (_free_f) free_ziti_net_session);
    FREE(ztx->last_update);

    ziti_ctrl_login(&ztx->controller, ztx->opts->config_types, cb, ctx);
}

static void ziti_re_auth(ziti_context ztx) {
    NEWP(init_req, struct ziti_init_req);
    init_req->ztx = ztx;
    init_req->login = true;

    ziti_re_auth_with_cb(ztx, session_cb, init_req);
}

static void update_services(ziti_service_array services, const ziti_error *error, void *ctx) {
    ziti_context ztx = ctx;

    // schedule next refresh
    if (ztx->opts->refresh_interval > 0) {
        ZTX_LOG(VERBOSE, "scheduling service refresh %ld seconds from now", ztx->opts->refresh_interval);
        uv_timer_start(&ztx->refresh_timer, services_refresh, ztx->opts->refresh_interval * 1000, 0);
    }

    if (error) {
        ZTX_LOG(ERROR, "failed to get service updates err[%s/%s] from ctrl[%s]", error->code, error->message,
                 ztx->opts->controller);
        if (error->err == ZITI_NOT_AUTHORIZED) {
            ZTX_LOG(WARN, "API session is no longer valid. Trying to re-auth");
            ziti_re_auth(ztx);
        }
        else {
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
            if (cmp_ziti_service(updt, model_map_it_value(it)) != 0 || ziti_service_has_query_with_timeout(updt)) {
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
        ZTX_LOG(DEBUG, "sending service event %d added, %d removed, %d changed", addIdx, remIdx, chIdx);
        ziti_send_event(ztx, &ev);
    }
    else {
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

        uv_timer_start(&ztx->refresh_timer, services_refresh, ztx->opts->refresh_interval * 1000, 0);
    }

    if (need_update) {
        ziti_ctrl_get_services(&ztx->controller, update_services, ztx);
    }
    FREE(update);
}

static void services_refresh(uv_timer_t *t) {
    ziti_context ztx = t->data;
    
    if (ztx->auth_queries->outstanding_auth_query_ctx) {
        ZITI_LOG(DEBUG, "service refresh stopped, outstanding auth queries");
        return;
    }
    
    if (ztx->no_service_updates_api) {
        ziti_ctrl_get_services(&ztx->controller, update_services, ztx);
    }
    else {
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
            free(ch_name);
        } else {
            ZTX_LOG(DEBUG, "edge router %s does not have TLS edge listener", er->name);
        }

        free_ziti_edge_router(er);
        free(er);
        erp++;
    }
    free(ers);
}

static void session_post_auth_query_cb(ziti_context ztx){
    ziti_session *session = ztx->session;

    int time_diff;
    if (session->cached_last_activity_at) {
        ZITI_LOG(TRACE, "API supports cached_last_activity_at");
        time_diff = (int) (ztx->session_received_at.tv_sec - session->cached_last_activity_at->tv_sec);
    } else {
        ZITI_LOG(TRACE, "API doesn't support cached_last_activity_at - using updated");
        time_diff = (int) (ztx->session_received_at.tv_sec - session->updated->tv_sec);
    }
    if (abs(time_diff) > 10) {
        ZITI_LOG(ERROR, "local clock is %d seconds %s UTC (as reported by controller)", abs(time_diff),
                 time_diff > 0 ? "ahead" : "behind");
    }

    if (session->expires) {
        // adjust expiration to local time if needed
        session->expires->tv_sec += time_diff;
        ZTX_LOG(DEBUG, "ziti API session expires in %ld seconds", (long) (session->expires->tv_sec - ztx->session_received_at.tv_sec));
        long delay = (session->expires->tv_sec - ztx->session_received_at.tv_sec) - 10;
        uv_timer_start(&ztx->session_timer, session_refresh, delay * 1000, 0);
    }

    if (ztx->opts->refresh_interval > 0 && !uv_is_active((const uv_handle_t *) &ztx->refresh_timer)) {
        ZTX_LOG(DEBUG, "refresh_interval set to %ld seconds", ztx->opts->refresh_interval);
        services_refresh(&ztx->refresh_timer);
    } else if (ztx->opts->refresh_interval == 0) {
        ZTX_LOG(DEBUG, "refresh_interval not specified");
        uv_timer_stop(&ztx->refresh_timer);
    }

    ziti_posture_init(ztx, 20);

    if (!ztx->no_current_edge_routers) {
        ziti_ctrl_current_edge_routers(&ztx->controller, edge_routers_cb, ztx);
    }
}

static void update_identity_data(ziti_identity_data *data, const ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;

    if (err) {
        ZITI_LOG(ERROR, "failed to get identity_data: %s[%d]", err->message, err->code);
    } else {
        free_ziti_identity_data(ztx->identity_data);
        FREE(ztx->identity_data);
        ztx->identity_data = data;
    }
}

void set_session(ziti_context ztx, ziti_session *session) {
    ziti_session *old_session = ztx->session;
    ztx->session = session;
    uv_gettimeofday(&ztx->session_received_at);

    free_ziti_session(old_session);
    FREE(old_session);

    ziti_ctrl_current_identity(&ztx->controller, update_identity_data, ztx);
}

static void session_cb(ziti_session *session, const ziti_error *err, void *ctx) {
    struct ziti_init_req *init_req = ctx;
    ziti_context ztx = init_req->ztx;
    ztx->loop_thread = uv_thread_self();

    int errCode = err ? err->err : ZITI_OK;

    if (session) {
        ZTX_LOG(DEBUG, "%s successfully => api_session[%s]", ztx->session ? "refreshed" : "logged in", session->id);

        ziti_session *old_session = ztx->session;
        ztx->session = session;
        uv_gettimeofday(&ztx->session_received_at);

        free_ziti_session(old_session);
        FREE(old_session);

        ziti_ctrl_current_identity(&ztx->controller, update_identity_data, ztx);

        ziti_auth_query_init(ztx);

        //check for additional authentication requirements, pickup in session_post_auth_query_cb
        ziti_auth_query_process(ztx,session_post_auth_query_cb);
    } else if (err) {
        ZTX_LOG(WARN, "failed to get session from ctrl[%s] %s[%d] %s",
                 ztx->opts->controller, err->code, errCode, err->message);

        if (errCode == ZITI_NOT_AUTHORIZED) {
            if (ztx->session || !init_req->login) {
                // previously successfully logged in
                // maybe just session expired
                // just try to re-auth
                ziti_re_auth(ztx);
                errCode = ztx->ctrl_status; // do not trigger event yet
            } else {
                // cannot login or re-auth -- identity no longer valid
                // notify service removal, and state
                ZTX_LOG(ERROR, "identity[%s] cannot authenticate with ctrl[%s]", ztx->opts->config,
                         ztx->opts->controller);
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

                uv_timer_stop(&ztx->session_timer);
                uv_timer_stop(&ztx->refresh_timer);
                if (ztx->posture_checks != NULL) {
                    uv_timer_stop(ztx->posture_checks->timer);
                }
            }
        } else {
            uv_timer_start(&ztx->session_timer, session_refresh, 5 * 1000, 0);
        }

    } else {
        ZTX_LOG(ERROR, "%s: no session or error received", ziti_errorstr(ZITI_WTF));
    }

    update_ctrl_status(ztx, errCode, err ? err->message : NULL);

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
                ztx->opts->controller, err->code, err->message);
    } else {
        ZTX_LOG(INFO, "connected to controller %s version %s(%s %s)",
                ztx->opts->controller, v->version, v->revision, v->build_date);
        free_ziti_version(v);
        FREE(v);
    }
}

void ziti_invalidate_session(ziti_context ztx, ziti_net_session *session, const char *service_id, const char *type) {
    if (session == NULL) {
        return;
    }

    if (strcmp(TYPE_DIAL, type) == 0) {
        ziti_net_session *s = model_map_get(&ztx->sessions, service_id);
        if (s != session) {
            // already removed or different one
            // passed reference is no longer valid
            session = NULL;
        }
        else if (s == session) {
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
}
