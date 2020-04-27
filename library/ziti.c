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

#include <nf/ziti.h>
#include <uv.h>
#include "utils.h"
#include "zt_internal.h"
#include <http_parser.h>

#include <utils.h>

#define MJSON_API_ONLY
#include <mjson.h>

#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#elif _WIN32
#define MAXPATHLEN 260
#else
#define MAXPATHLEN 4096
#endif
#endif

#if _WIN32
#define strncasecmp _strnicmp
#endif

static const char *ALL_CONFIG_TYPES[] = {
        "all",
        NULL
};

struct nf_init_req {
    nf_context nf;
    int init_status;
    nf_init_cb init_cb;
    void* init_ctx;
};

int code_to_error(const char *code);

static void version_cb(ziti_version *v, ziti_error *err, void *ctx);

static void session_cb(ziti_session *session, ziti_error *err, void *ctx);

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
    nf_context nf = ar->data;
    ziti_process_connect_reqs(nf);
}

int load_tls(nf_config *cfg, tls_context **ctx) {
    PREP(ziti);

    // load ca from nf config if present
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
        sprintf(path, "%*.*s", (int)(endp - p), (int)(endp - p), p);

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

int NF_init_opts(nf_options *opts, uv_loop_t *loop, void *init_ctx) {
    init_debug();

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    struct tm *start_tm = gmtime(&start_time.tv_sec);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%FT%T", start_tm);

    ZITI_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting at (%s.%03d)",
            ziti_get_version(false), ziti_git_commit(), ziti_git_branch(),
            time_str, start_time.tv_usec/1000);

    PREP(ziti);

    if (opts->config == NULL && (opts->controller == NULL || opts->tls == NULL)) {
        ZITI_LOG(ERROR, "config or controller/tls has to be set");
        return ZITI_INVALID_CONFIG;
    }

    nf_config *cfg = NULL;
    if (opts->config != NULL) {
        TRY(ziti, load_config(opts->config, &cfg));
    }
    if (opts->controller == NULL) {
        opts->controller = strdup(cfg->controller_url);
    }
    if (opts->tls == NULL) {
        TRY(ziti, load_tls(cfg, &opts->tls));
    }

    free_nf_config(cfg);
    free(cfg);

    NEWP(ctx, struct nf_ctx);
    ctx->opts = opts;
    ctx->tlsCtx = opts->tls;
    ctx->loop = loop;
    ctx->ziti_timeout = NF_DEFAULT_TIMEOUT;

    uv_async_init(loop, &ctx->connect_async, async_connects);
    uv_unref((uv_handle_t *) &ctx->connect_async);

    ziti_ctrl_init(loop, &ctx->controller, opts->controller, ctx->tlsCtx);
    ziti_ctrl_get_version(&ctx->controller, version_cb, &ctx->controller);

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

    NEWP(init_req, struct nf_init_req);
    init_req->init_cb = opts->init_cb;
    init_req->init_ctx = init_ctx;
    init_req->nf = ctx;
    ziti_ctrl_login(&ctx->controller, ctx->opts->config_types, session_cb, init_req);

    CATCH(ziti) {
        return ERR(ziti);
    }

    return ZITI_OK;
}

int NF_init(const char *config, uv_loop_t *loop, nf_init_cb init_cb, void *init_ctx) {

    NEWP(opts, nf_options);
    opts->config = config;
    opts->init_cb = init_cb;
    opts->config_types = ALL_CONFIG_TYPES;

    return NF_init_opts(opts, loop, init_ctx);
}

const char *NF_get_controller(nf_context nf) {
    return nf->opts->controller;
}

const ziti_version *NF_get_controller_version(nf_context nf) {
    return &nf->controller.version;
}

const ziti_identity *NF_get_identity(nf_context nf) {
    return nf->session ? nf->session->identity : NULL;
}

int NF_set_timeout(nf_context ctx, int timeout) {
    if (timeout > 0) {
        ctx->ziti_timeout = timeout;
    }
    else {
        ctx->ziti_timeout = NF_DEFAULT_TIMEOUT;
    }
    return ZITI_OK;
}

int NF_shutdown(nf_context ctx) {
    ZITI_LOG(INFO, "Ziti is shutting down");

    free_ziti_session(ctx->session);
    ctx->session = NULL;

    uv_timer_stop(&ctx->session_timer);
    ziti_ctrl_close(&ctx->controller);
    ziti_close_channels(ctx);

    ziti_ctrl_logout(&ctx->controller, NULL, NULL);

    return ZITI_OK;
}

int NF_free(nf_context *ctxp) {
    if ((*ctxp)->tlsCtx != NULL) {
        (*ctxp)->tlsCtx->api->free_ctx((*ctxp)->tlsCtx);
    }
    free(*ctxp);
    *ctxp = NULL;

    ZITI_LOG(INFO, "shutdown is complete\n");
    return ZITI_OK;
}

void NF_dump(nf_context ctx) {
    printf("\n=================\nSession:\n");
    dump_ziti_session(ctx->session, 0);

    printf("\n=================\nServices:\n");
    ziti_service *zs;
    const char *name;
    MODEL_MAP_FOREACH(name, zs, ctx->services) {
        dump_ziti_service(zs, 0);
    }

    printf("\n==================\nNet Sessions:\n");
    ziti_net_session *it;
    MODEL_MAP_FOREACH(name, it, ctx->sessions) {
        dump_ziti_net_session(it, 0);
    }

    printf("\n==================\nChannels:\n");
    ziti_channel_t *ch;
    const char *url;
    MODEL_MAP_FOREACH(url, ch, ctx->channels) {
        printf("ch[%d](%s)\n", ch->id, url);
        nf_connection conn;
        LIST_FOREACH(conn, &ch->connections, next) {
            printf("\tconn[%d]: state[%s] service[%s] session[%s]\n", conn->conn_id, strstate(conn->state),
                   "TODO", "TODO"); // TODO
        }
    }
}

int NF_conn_init(nf_context nf_ctx, nf_connection *conn, void *data) {
    struct nf_ctx *ctx = nf_ctx;
    NEWP(c, struct nf_conn);
    c->nf_ctx = nf_ctx;
    c->data = data;
    c->channel = NULL;
    c->state = Initial;
    c->timeout = ctx->ziti_timeout;
    c->edge_msg_seq = 1;
    c->conn_id = nf_ctx->conn_seq++;
    c->inbound = new_buffer();

    *conn = c;
    return ZITI_OK;
}

void *NF_conn_data(nf_connection conn) {
    return conn != NULL ? conn->data : NULL;
}

int NF_dial(nf_connection conn, const char *service, nf_conn_cb conn_cb, nf_data_cb data_cb) {
    return ziti_dial(conn, service, conn_cb, data_cb);
}

int NF_close(nf_connection *conn) {
    struct nf_conn *c = *conn;

    if (c != NULL) {
        ziti_disconnect(c);
    }

    *conn = NULL;

    return ZITI_OK;
}

int NF_write(nf_connection conn, uint8_t* data, size_t length, nf_write_cb write_cb, void* write_ctx) {

    NEWP(req, struct nf_write_req);
    req->conn = conn;
    req->buf = data;
    req->len = length;
    req->cb = write_cb;
    req->ctx = write_ctx;

    return ziti_write(req);
}

struct service_req_s {
    struct nf_ctx *nf;
    char *service;
    nf_service_cb cb;
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
        model_map_set(&req->nf->services, s->name, s);
        rc = ZITI_OK;
    }

    req->cb(req->nf, s, rc, req->cb_ctx);
    FREE(req->service);
    free(req);
}

int NF_service_available(nf_context nf, const char *service, nf_service_cb cb, void *ctx) {
    ziti_service *s = model_map_get(&nf->services, service);
    if (s != NULL) {
        cb(nf, s, ZITI_OK, ctx);
        return ZITI_OK;
    }

    NEWP(req, struct service_req_s);
    req->nf = nf;
    req->service = strdup(service);
    req->cb = cb;
    req->cb_ctx = ctx;

    ziti_ctrl_get_service(&nf->controller, service, service_cb, req);
    return ZITI_OK;
}

extern int NF_listen(nf_connection serv_conn, const char *service, nf_listen_cb lcb, nf_client_cb cb) {
    return ziti_bind(serv_conn, service, lcb, cb);
}

extern int NF_accept(nf_connection clt, nf_conn_cb cb, nf_data_cb data_cb) {
    return ziti_accept(clt, cb, data_cb);
}

static void session_refresh(uv_timer_t *t) {
    nf_context nf = t->data;
    struct nf_init_req *req = calloc(1, sizeof(struct nf_init_req));
    req->nf = nf;

    ZITI_LOG(DEBUG, "refreshing API session");
    ziti_ctrl_current_api_session(&nf->controller, session_cb, req);
}

static void update_services(ziti_service_array services, ziti_error *error, nf_context nf) {
    if (error) {
        ZITI_LOG(ERROR, "failed to get service updates err[%s/%s]", error->code, error->message);
        return;
    }

    ZITI_LOG(VERBOSE, "processing service updates");

    model_map updates = {0};

    for (int idx = 0; services[idx] != NULL; idx++) {
        set_service_flags(services[idx]);
        model_map_set(&updates, services[idx]->name, services[idx]);
    }
    free(services);

    const char *name;
    ziti_service *s;
    model_map_iter it = model_map_iterator(&nf->services);
    while (it != NULL) {
        ziti_service *updt = model_map_remove(&updates, model_map_it_key(it));

        if (updt != NULL) {
            // do we want to process service updates possibly?
            free_ziti_service(updt);
            free(updt);

            it = model_map_it_next(it);
        }
        else {
            // service was removed
            ZITI_LOG(DEBUG, "service[%s] is not longer available", model_map_it_key(it));
            s = model_map_it_value(it);
            if (nf->opts->service_cb != NULL) {
                nf->opts->service_cb(nf, s, ZITI_SERVICE_UNAVAILABLE, nf->opts->ctx);
            }
            ziti_net_session *session = model_map_remove(&nf->sessions, s->id);
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
        model_map_set(&nf->services, name, s);
        if (nf->opts->service_cb != NULL) {
            nf->opts->service_cb(nf, s, ZITI_OK, nf->opts->ctx);
        }
        it = model_map_it_remove(it);
    }

    model_map_clear(&updates, NULL);
}

static void services_refresh(uv_timer_t *t) {
    nf_context nf = t->data;
    ziti_ctrl_get_services(&nf->controller, update_services, nf);
}

static void session_cb(ziti_session *session, ziti_error *err, void *ctx) {
    struct nf_init_req *init_req = ctx;
    nf_context nf = init_req->nf;

    int errCode = err ? code_to_error(err->code) : ZITI_OK;

    if (session) {
        ZITI_LOG(DEBUG, "%s successfully => api_session[%s]", nf->session ? "refreshed" : "logged in", session->id);
        free_ziti_session(nf->session);
        FREE(nf->session);

        nf->session = session;

        if (session->expires) {
            uv_timeval64_t now;
            uv_gettimeofday(&now);
            ZITI_LOG(DEBUG, "ziti API session expires in %ld seconds", (long) (session->expires->tv_sec - now.tv_sec));
            long delay = (session->expires->tv_sec - now.tv_sec) * 3 / 4;
            uv_timer_start(&nf->session_timer, session_refresh, delay * 1000, 0);
        }

        if (nf->opts->refresh_interval > 0) {
            uv_timer_start(&nf->refresh_timer, services_refresh, 0, nf->opts->refresh_interval * 1000);
        }

    } else {
        ZITI_LOG(ERROR, "failed to login: %s[%d](%s)", err->code, errCode, err->message);
    }

    if (init_req->init_cb) {
        init_req->init_cb(nf, errCode, init_req->init_ctx);
    }

    free_ziti_error(err);
    FREE(init_req);
}

static void version_cb(ziti_version *v, ziti_error *err, void *ctx) {
    ziti_controller *ctrl = ctx;
    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to get controller version from %s:%s %s(%s)",
                 ctrl->client.host, ctrl->client.port, err->code, err->message);
        free_ziti_error(err);
        FREE(err);
    }
    else {
        ZITI_LOG(INFO, "connected to controller %s:%s version %s(%s %s)",
                 ctrl->client.host, ctrl->client.port, v->version, v->revision, v->build_date);
        free_ziti_version(v);
        FREE(v);
    }
}

static const ziti_version sdk_version = {
        .version = to_str(ZITI_VERSION),
        .revision = to_str(ZITI_COMMIT),
        .build_date = to_str(BUILD_DATE)
};

const ziti_version *NF_get_version() {
    return &sdk_version;
}

static void grim_reaper(uv_prepare_t *p) {
    nf_context nf = p->data;

    int count = 0;
    const char *url;
    ziti_channel_t *ch;
    MODEL_MAP_FOREACH(url, ch, nf->channels) {
        nf_connection conn = LIST_FIRST(&ch->connections);
        while(conn != NULL) {
            nf_connection try_close = conn;
            conn = LIST_NEXT(conn, next);
            count += close_conn_internal(try_close);
        }
    }
    if (count > 0) {
        ZITI_LOG(INFO, "reaped %d closed connections", count);
    }
}