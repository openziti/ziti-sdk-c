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

static const char *ALL_CONFIG_TYPES[] = {
        "all",
        NULL
};

struct ziti_init_req {
    ziti_context ztx;
    bool login;
    int init_status;
    ziti_init_cb init_cb;
    void *init_ctx;
};

int code_to_error(const char *code);

static void version_cb(ziti_version *v, ziti_error *err, void *ctx);

static void session_cb(ziti_session *session, ziti_error *err, void *ctx);

static void ziti_init_async(uv_async_t *ar);

static void grim_reaper(uv_prepare_t *p);

#define CONN_STATES(XX) \
XX(Initial)\
    XX(Connecting)\
    XX(Connected)\
    XX(Binding)\
    XX(Bound)\
    XX(Accepting) \
    XX(Closed)

static const char* strstate(enum conn_state st) {
#define state_case(s) case s: return #s;

    switch (st) {

        CONN_STATES(state_case)

        default: return "<unknown>";
    }
#undef state_case
}

static size_t parse_ref(const char *val, const char **res) {
    size_t len = 0;
    *res = NULL;
    if (val != NULL) {
        if (strncmp("file:", val, 5) == 0) {
            // load file
            *res = val + strlen("file://");
            len = strlen(*res) + 1;
        }
        else if (strncmp("pem:", val, 4) == 0) {
            // load inline PEM
            *res = val + 4;
            len = strlen(val + 4) + 1;
        }
        else {
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
            int vlen = (int)(end == NULL ? strlen(val) : end - val);
            snprintf(out, maxout, "%*.*s", vlen, vlen, val);
            return ZITI_OK;

        }
        else { // skip to next '&'
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

static void async_connects(uv_async_t *ar) {
    ziti_context ztx = ar->data;
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

int ziti_init_opts(ziti_options *options, uv_loop_t *loop, void *init_ctx) {
    ziti_log_init(loop, ZITI_LOG_DEFAULT_LEVEL, NULL);
    metrics_init(loop, 5);

    PREP(ziti);

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

    NEWP(init_req, struct ziti_init_req);
    init_req->init_cb = options->init_cb;
    init_req->init_ctx = init_ctx;
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

    ziti_context ctx = init_req->ztx;
    uv_loop_t *loop = ar->loop;

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    char time_str[32];
    ziti_fmt_time(time_str, sizeof(time_str), &start_time);

    ZITI_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting at (%s.%03d)",
             ziti_get_build_version(false), ziti_git_commit(), ziti_git_branch(),
             time_str, start_time.tv_usec / 1000);

    init_req->login = true;
    ziti_ctrl_init(loop, &ctx->controller, ctx->opts->controller, ctx->tlsCtx);
    ziti_ctrl_get_version(&ctx->controller, version_cb, ctx);

    uv_timer_init(loop, &ctx->session_timer);
    uv_unref((uv_handle_t *) &ctx->session_timer);
    ctx->session_timer.data = ctx;

    uv_timer_init(loop, &ctx->refresh_timer);
    if (ctx->opts->refresh_interval == 0) {
        uv_unref((uv_handle_t *) &ctx->refresh_timer);
    }
    ctx->refresh_timer.data = ctx;

    uv_prepare_init(loop, &ctx->reaper);
    ctx->reaper.data = ctx;
    uv_unref((uv_handle_t *) &ctx->reaper);
    uv_prepare_start(&ctx->reaper, grim_reaper);

    ziti_ctrl_login(&ctx->controller, ctx->opts->config_types, session_cb, init_req);
}

int ziti_init(const char *config, uv_loop_t *loop, ziti_init_cb init_cb, void *init_ctx) {

    NEWP(opts, ziti_options);
    opts->config = config;
    opts->init_cb = init_cb;
    opts->config_types = ALL_CONFIG_TYPES;

    return ziti_init_opts(opts, loop, init_ctx);
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

int ziti_shutdown(ziti_context ztx) {
    ZITI_LOG(INFO, "Ziti is shutting down");

    free_ziti_session(ztx->session);
    free(ztx->session);
    ztx->session = NULL;

    uv_timer_stop(&ztx->refresh_timer);
    uv_timer_stop(&ztx->session_timer);
    uv_timer_stop(&ztx->posture_checks->timer);

    ziti_ctrl_close(&ztx->controller);
    ziti_close_channels(ztx);

    ziti_ctrl_logout(&ztx->controller, NULL, NULL);
    metrics_rate_close(&ztx->up_rate);
    metrics_rate_close(&ztx->down_rate);

    return ZITI_OK;
}

int ziti_ctx_free(ziti_context *ctxp) {
    if ((*ctxp)->tlsCtx != NULL) {
        (*ctxp)->tlsCtx->api->free_ctx((*ctxp)->tlsCtx);
    }

    ziti_posture_checks_free((*ctxp)->posture_checks);

    free(*ctxp);
    *ctxp = NULL;

    ZITI_LOG(INFO, "shutdown is complete\n");
    return ZITI_OK;
}

void ziti_dump(ziti_context ztx) {
    printf("\n=================\nSession:\n");
    printf("Session Info: id[%s] name[%s] api_session[%s]\n",
           ztx->session->identity->id, ztx->session->identity->name, ztx->session->id);

    printf("\n=================\nServices:\n");
    ziti_service *zs;
    const char *name;
    MODEL_MAP_FOREACH(name, zs, &ztx->services) {

        printf("%s: id[%s] perm(dial=%s,bind=%s)\n", zs->name, zs->id,
               (zs->perm_flags & ZITI_CAN_DIAL ? "true" : "false"),
               (zs->perm_flags & ZITI_CAN_BIND ? "true" : "false")
        );
    }

    printf("\n==================\nNet Sessions:\n");
    ziti_net_session *it;
    MODEL_MAP_FOREACH(name, it, &ztx->sessions) {
        printf("%s: service_id[%s]\n", it->id, name);
    }

    printf("\n==================\nChannels:\n");
    ziti_channel_t *ch;
    const char *url;
    MODEL_MAP_FOREACH(url, ch, &ztx->channels) {
        printf("ch[%d](%s) %s\n", ch->id, url, ch->state == Disconnected ? "Disconnected" : "");
    }

    printf("\n==================\nConnections:\n");
    ziti_connection conn;
    LIST_FOREACH(conn, &ztx->connections, next) {
        printf("conn[%d]: state[%d] service[%s] using ch[%d] %s\n",
               conn->conn_id, conn->state, conn->service,
               conn->channel ? conn->channel->id : -1,
               conn->channel ? conn->channel->name : "(none)");
    }
}

int ziti_conn_init(ziti_context ztx, ziti_connection *conn, void *data) {
    struct ziti_ctx *ctx = ztx;
    NEWP(c, struct ziti_conn);
    c->ziti_ctx = ztx;
    c->data = data;
    c->channel = NULL;
    c->state = Initial;
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

int ziti_close(ziti_connection *conn) {
    struct ziti_conn *c = *conn;

    if (c != NULL) {
        ziti_disconnect(c);
    }

    *conn = NULL;

    return ZITI_OK;
}

int ziti_write(ziti_connection conn, uint8_t *data, size_t length, ziti_write_cb write_cb, void *write_ctx) {
    if (conn->state != Connected) {
        ZITI_LOG(ERROR, "attempted write on conn[%d] in invalid state[%d]", conn->conn_id, conn->state);
        write_cb(conn, ZITI_INVALID_STATE, write_ctx);
        return ZITI_INVALID_STATE;
    }

    NEWP(req, struct ziti_write_req_s);
    req->conn = conn;
    req->buf = data;
    req->len = length;
    req->cb = write_cb;
    req->ctx = write_ctx;

    metrics_rate_update(&conn->ziti_ctx->up_rate, length);

    return ziti_write_req(req);
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

static void service_cb(ziti_service *s, ziti_error *err, void *ctx) {
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
    struct ziti_init_req *req = calloc(1, sizeof(struct ziti_init_req));
    req->ztx = ztx;

    ZITI_LOG(DEBUG, "refreshing API session");
    ziti_ctrl_current_api_session(&ztx->controller, session_cb, req);
}

void ziti_force_session_refresh(ziti_context ztx) {
    uv_timer_start(&ztx->session_timer, session_refresh, 0, 0);
}

static void ziti_re_auth(ziti_context ztx) {
    ZITI_LOG(WARN, "starting to re-auth with ctlr[%s]", ztx->opts->controller);
    uv_timer_stop(&ztx->refresh_timer);
    uv_timer_stop(&ztx->session_timer);
    if (ztx->posture_checks) {
        uv_timer_stop(&ztx->posture_checks->timer);
    }
    free_ziti_session(ztx->session);
    FREE(ztx->session);
    model_map_clear(&ztx->sessions, (_free_f) free_ziti_net_session);

    NEWP(init_req, struct ziti_init_req);
    init_req->ztx = ztx;
    init_req->login = true;
    ziti_ctrl_login(&ztx->controller, ztx->opts->config_types, session_cb, init_req);
}

static void update_services(ziti_service_array services, ziti_error *error, ziti_context ztx) {
    if (error) {
        ZITI_LOG(ERROR, "failed to get service updates err[%s/%s] from ctrl[%s]", error->code, error->message,
                 ztx->opts->controller);
        if (strcmp(error->code, "UNAUTHORIZED") == 0) {
            ZITI_LOG(WARN, "API session is no longer valid. Trying to re-auth");
            ziti_re_auth(ztx);
        }
        return;
    }

    ZITI_LOG(VERBOSE, "processing service updates");

    model_map updates = {0};
    model_map changes = {0};

    for (int idx = 0; services[idx] != NULL; idx++) {
        set_service_flags(services[idx]);
        model_map_set(&updates, services[idx]->name, services[idx]);
    }
    free(services);

    const char *name;
    ziti_service *s;
    model_map_iter it = model_map_iterator(&ztx->services);
    while (it != NULL) {
        ziti_service *updt = model_map_remove(&updates, model_map_it_key(it));

        if (updt != NULL) {
            if (cmp_ziti_service(updt, model_map_it_value(it)) != 0) {
                model_map_set(&changes, model_map_it_key(it), updt);
            } else {
                // no changes detected, just discard it
                free_ziti_service(updt);
                free(updt);
            }

            it = model_map_it_next(it);
        } else {
            // service was removed
            ZITI_LOG(DEBUG, "service[%s] is not longer available", model_map_it_key(it));
            s = model_map_it_value(it);
            if (ztx->opts->service_cb != NULL) {
                ztx->opts->service_cb(ztx, s, ZITI_SERVICE_UNAVAILABLE, ztx->opts->ctx);
            }
            ziti_net_session *session = model_map_remove(&ztx->sessions, s->id);
            if (session) {
                free_ziti_net_session(session);
                free(session);
            }
            it = model_map_it_remove(it);
            free_ziti_service(s);
            free(s);
        }
    }

    // what's left are new services
    it = model_map_iterator(&updates);
    while (it != NULL) {
        s = model_map_it_value(it);
        name = model_map_it_key(it);
        model_map_set(&ztx->services, name, s);
        if (ztx->opts->service_cb != NULL) {
            ztx->opts->service_cb(ztx, s, ZITI_OK, ztx->opts->ctx);
        }
        it = model_map_it_remove(it);
    }

    // process updates
    it = model_map_iterator(&changes);
    while (it != NULL) {
        s = model_map_it_value(it);
        name = model_map_it_key(it);

        ziti_service *old = model_map_set(&ztx->services, name, s);
        if (ztx->opts->service_cb != NULL) {
            ztx->opts->service_cb(ztx, s, ZITI_OK, ztx->opts->ctx);
        }

        free_ziti_service(old);
        FREE(old);
        it = model_map_it_remove(it);
    }


    model_map_clear(&updates, NULL);
}

static void services_refresh(uv_timer_t *t) {
    ziti_context ztx = t->data;
    ziti_ctrl_get_services(&ztx->controller, update_services, ztx);
}

static void session_cb(ziti_session *session, ziti_error *err, void *ctx) {
    struct ziti_init_req *init_req = ctx;
    ziti_context ztx = init_req->ztx;
    ztx->loop_thread = uv_thread_self();

    int errCode = err ? code_to_error(err->code) : ZITI_OK;

    if (session) {
        ZITI_LOG(DEBUG, "%s successfully => api_session[%s]", ztx->session ? "refreshed" : "logged in", session->id);
        free_ziti_session(ztx->session);
        FREE(ztx->session);

        ztx->session = session;

        if (session->expires) {
            uv_timeval64_t now;
            uv_gettimeofday(&now);
            ZITI_LOG(DEBUG, "ziti API session expires in %ld seconds", (long) (session->expires->tv_sec - now.tv_sec));
            long delay = (session->expires->tv_sec - now.tv_sec) * 3 / 4;
            uv_timer_start(&ztx->session_timer, session_refresh, delay * 1000, 0);
        }

        if (ztx->opts->refresh_interval > 0 && !uv_is_active((const uv_handle_t *) &ztx->refresh_timer)) {
            ZITI_LOG(DEBUG, "refresh_interval set to %ld seconds", ztx->opts->refresh_interval);
            uv_timer_start(&ztx->refresh_timer, services_refresh, 0, ztx->opts->refresh_interval * 1000);
        }
        else if (ztx->opts->refresh_interval == 0) {
            ZITI_LOG(DEBUG, "refresh_interval not specified");
            uv_timer_stop(&ztx->refresh_timer);
        }

        posture_init(ztx, 20);

    } else if (err) {

        ZITI_LOG(WARN, "failed to get session from ctrl[%s] %s[%d] %s",
                 ztx->opts->controller, err->code, errCode, err->message);

        if (errCode == ZITI_NOT_AUTHORIZED) {
            if (ztx->session || !init_req->login) {
                // previously successfully logged in
                // maybe just session expired
                // just try to re-auth
                ziti_re_auth(ztx);
            }
            else {
                // cannot login or re-auth -- identity no longer valid
                // notify service removal, and state
                ZITI_LOG(ERROR, "identity[%s] cannot authenticate with ctrl[%s]", ztx->opts->config,
                         ztx->opts->controller);
                const char *name;
                ziti_service *srv;
                size_t idx = 0;
                if (ztx->opts->service_cb) {
                    MODEL_MAP_FOREACH(name, srv, &ztx->services) {
                        ztx->opts->service_cb(ztx, srv, ZITI_SERVICE_UNAVAILABLE, ztx->opts->ctx);
                    }
                }

                model_map_clear(&ztx->services, (_free_f) free_ziti_service);

                uv_timer_stop(&ztx->session_timer);
                uv_timer_stop(&ztx->refresh_timer);
                if (ztx->posture_checks != NULL) {
                    uv_timer_stop(&ztx->posture_checks->timer);
                }
            }
        } else {
            uv_timer_start(&ztx->session_timer, session_refresh, 5 * 1000, 0);
        }

    } else {
        ZITI_LOG(ERROR, "%s: no session or error received", ziti_errorstr(ZITI_WTF));
    }

    if (init_req->init_cb) {
        if (errCode == ZITI_OK) {
            rate_type rate = ztx->opts->metrics_type;

            ZITI_LOG(INFO, "using metrics interval: %d", (int) rate);

            metrics_rate_init(&ztx->up_rate, rate);
            metrics_rate_init(&ztx->down_rate, rate);
        }

        init_req->init_cb(ztx, errCode, init_req->init_ctx);
    }

    free_ziti_error(err);
    FREE(init_req);
}

static void version_cb(ziti_version *v, ziti_error *err, void *ctx) {
    ziti_context ztx = ctx;
    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to get controller version from %s %s(%s)",
                 ztx->opts->controller, err->code, err->message);
        free_ziti_error(err);
        FREE(err);
    } else {
        ZITI_LOG(INFO, "connected to controller %s version %s(%s %s)",
                 ztx->opts->controller, v->version, v->revision, v->build_date);
        free_ziti_version(v);
        FREE(v);
    }
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
        ZITI_LOG(INFO, "reaped %d closed (out of %d total) connections", count, total);
    }
}