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
#define _GNU_SOURCE

#include <uv.h>
#include <tlsuv/http.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <utils.h>
#include <ziti/ziti.h>
#include "proxy.h"

#if(_WIN32)
#define strsignal(s) "_windows_unimplemented_"
#endif

#if !defined (SIGUSR1)
#define SIGUSR1 10
#endif


static int report_metrics = -1;
static uv_timer_t report_timer;
static uv_timer_t shutdown_timer;

static void signal_cb(uv_signal_t *s, int signum);

static void on_ziti_close(ziti_connection conn);

static struct sig_handlers {
    uv_signal_t sig;
    int signum;
    uv_signal_cb cb;
} signals[] = {
        {.signum = SIGINT, .cb = signal_cb},
        {.signum = SIGTERM, .cb = signal_cb},
        {.signum = SIGUSR1, .cb = signal_cb},
#ifndef _WIN32
        {.signum = SIGUSR2, .cb = signal_cb},
#endif
};

struct proxy_app_ctx {
    model_map listeners;
    model_map bindings;
    LIST_HEAD(clients, client) clients;
    ziti_context ziti;
    uv_loop_t *loop;
};

struct binding {
    char *service_name;
    ziti_connection conn;
    struct addrinfo *addr;
    int type;
};

struct listener {
    char *service_name;
    int port;
    uv_tcp_t server;
    struct proxy_app_ctx *app_ctx;
};



// typedef LIST_HEAD(listeners, listener) listener_l;

struct client {
    struct sockaddr_in addr;
    char addr_s[32];
    ziti_connection ziti_conn;
    int closed;

    LIST_ENTRY(client) next;
};

void mfa_auth_event_handler(ziti_context ztx);
void ext_auth_event_handler(ziti_context ztx, const char *name);

static void close_server_cb(uv_handle_t *h) {
    struct listener *l = h->data;
    ZITI_LOG(DEBUG, "listener closed for %s", l->service_name);
}

static void close_binding_cb(ziti_connection conn) {
    struct binding *b = ziti_conn_data(conn);
    ZITI_LOG(DEBUG, "binding closed for %s", b->service_name);
}

static void shutdown_timer_cb(uv_timer_t *t) {
    uv_loop_t *l = t->loop;

    ZITI_LOG(WARN, "shutdown timer expired");
    uv_print_active_handles(l, stderr);
}

static void free_listener(struct listener *l) {
    free(l->service_name);
    free(l);
}

static void process_stop(uv_loop_t *loop, struct proxy_app_ctx *app_ctx) {
    ZITI_LOG(INFO, "stopping");

    // shutdown listeners
    MODEL_MAP_FOR(it, app_ctx->listeners) {
        struct listener *l = model_map_it_value(it);
        if (uv_is_active((const uv_handle_t *) &l->server)) {
            uv_close((uv_handle_t *) &l->server, close_server_cb);
        }
    }

    MODEL_MAP_FOR(it, app_ctx->bindings) {
        struct binding *b = model_map_it_value(it);
        if (b->conn) {
            ziti_close(b->conn, close_binding_cb);
        }
    }

    if (uv_is_active((const uv_handle_t *) &report_timer)) {
        ZITI_LOG(INFO, "stopping report timer");
        uv_close((uv_handle_t *) &report_timer, NULL);
    }

    ZITI_LOG(INFO, "stopping signal handlers");
    for (int i = 0; i < sizeof(signals)/sizeof(signals[0]); i++) {
        uv_close((uv_handle_t *) &signals[i].sig, NULL);
    }

    // shutdown diagnostics
    uv_timer_init(loop, &shutdown_timer);
    uv_timer_start(&shutdown_timer, shutdown_timer_cb, 5000, 0);
    uv_unref((uv_handle_t *) &shutdown_timer);

    // try to clean up
    if (app_ctx->ziti)
        ziti_shutdown(app_ctx->ziti);

    ZITI_LOG(INFO, "exiting");
}

static int dump(void *out, const char *fmt, ...) {
    char line[1024];
    uv_udp_t *u = out;
    const struct sockaddr *addr = u->data;
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    uv_buf_t b = uv_buf_init(line, len);
    return uv_udp_try_send(u, &b, 1, addr);
}

static void debug_dump(struct proxy_app_ctx *app_ctx,
        int (*print_fn)(void *, const char *, ...), void *printer) {
    print_fn(printer, "==== listeners ====\n");
    MODEL_MAP_FOR(it, app_ctx->listeners) {
        struct listener *l = model_map_it_value(it);
        print_fn(printer, "listening for service[%s] on port[%d]\n", l->service_name, l->port);
    }

    print_fn(printer, "\n==== bindings ====\n");
    MODEL_MAP_FOR(it, app_ctx->bindings) {
        struct binding *b = model_map_it_value(it);
        uv_getnameinfo_t name;
        uv_getnameinfo(app_ctx->loop, &name, NULL, b->addr->ai_addr, NI_NUMERICHOST);
        print_fn(printer, "bound to service[%s] -> %s:%s\n", b->service_name, name.host, name.service);
    }
    ziti_dump(app_ctx->ziti, print_fn, printer);
}

static void reporter_cb(uv_timer_t *t) {
    double up, down;
    struct proxy_app_ctx *app_ctx = t->data;
    if (app_ctx->ziti != NULL) {
        ziti_get_transfer_rates(app_ctx->ziti, &up, &down);
        ZITI_LOG(INFO, "transfer rates: up=%lf down=%lf", up, down);
    }
}

static void signal_cb(uv_signal_t *s, int signum) {
    ZITI_LOG(INFO, "signal[%d/%s] received", signum, strsignal(signum));

    switch (signum) {
        case SIGINT:
        case SIGTERM:
            process_stop(s->loop, s->data);
            break;

        case SIGUSR1:
            debug_dump(s->data, (int (*)(void *, const char *, ...)) fprintf, stdout);
            break;
#ifndef _WIN32
        case SIGUSR2: {
            struct proxy_app_ctx *ctx = s->data;
            ziti_set_enabled(ctx->ziti, !ziti_is_enabled(ctx->ziti));
            break;
        }
#endif

        default:
            ZITI_LOG(INFO, "signal[%d/%s] received", signum, strsignal(signum));
            break;
    }
}

static void close_cb(uv_handle_t *h) {
    struct client *clt = h->data;
    ZITI_LOG(DEBUG, "client connection closed for %s", clt->addr_s);
    if (clt->ziti_conn) {
        ziti_conn_set_data(clt->ziti_conn, NULL);
        ziti_close(clt->ziti_conn, NULL);
    }
    LIST_REMOVE(clt, next);
    free(clt);
    free(h);
}

static void on_ziti_close(ziti_connection conn) {
    uv_stream_t *tcp = ziti_conn_data(conn);
    if (tcp) {
        struct client *clt = tcp->data;
        clt->ziti_conn = NULL;
        ZITI_LOG(DEBUG, "ziti connection closed for clt[%s]", clt->addr_s);
        clt->closed = true;
        if (!uv_is_closing((const uv_handle_t *) tcp)) {
            uv_close((uv_handle_t *) tcp, close_cb);
        }
    }
}

static void on_bridge_close(uv_handle_t *handle) {
    uv_close(handle, (uv_close_cb) free);
}

void on_ziti_connect(ziti_connection conn, int status) {
    uv_handle_t *clt = ziti_conn_data(conn);

    if (status == ZITI_OK) {
        ziti_conn_bridge(conn, clt, on_bridge_close);
    } else {
        ZITI_LOG(ERROR, "ziti connect failed: %s(%d)", ziti_errorstr(status), status);
        ziti_close(conn, on_ziti_close);
    }
}

static void on_client(uv_stream_t *server, int status) {
    PREPF(uv, uv_err_name);

    NEWP(c, uv_tcp_t);

    TRY(uv, uv_tcp_init(server->loop, c));
    TRY(uv, uv_accept(server, (uv_stream_t *) c));

    NEWP(clt, struct client);
    int len = sizeof(clt->addr);
    TRY(uv, uv_tcp_getpeername(c, (struct sockaddr *) &clt->addr, &len));
    sprintf(clt->addr_s, "%s:%hu", inet_ntoa(clt->addr.sin_addr), ntohs(clt->addr.sin_port));
    CATCH(uv) {
        return;
    }

    struct listener *l = server->data;
    ZITI_LOG(DEBUG, "client connection accepted from %s (%s:%d)",
             clt->addr_s, l->service_name, l->port);
    LIST_INSERT_HEAD(&l->app_ctx->clients, clt, next);

    PREPF(ziti, ziti_errorstr);
    TRY(ziti, ziti_conn_init(l->app_ctx->ziti, &clt->ziti_conn, c));
    ziti_dial_opts opts = {
            .stream = true,
    };
    TRY(ziti, ziti_dial_with_options(clt->ziti_conn, l->service_name, &opts, on_ziti_connect, NULL));
    c->data = clt;

    CATCH(ziti) {
        free(clt);
        ZITI_LOG(ERROR, "closing client [%s]", clt->addr_s);
        uv_close((uv_handle_t *) c, close_cb);
    }

}

static void on_listener_close(uv_handle_t *lh) {
    uv_tcp_t *l = (uv_tcp_t *) lh;
    uv_tcp_init(lh->loop, l);
}

static void update_listener(ziti_service *service, int status, struct listener *l) {
    PREPF(uv, uv_strerror);

    if (status == ZITI_OK && (service->perm_flags & ZITI_CAN_DIAL)) {
        if (uv_is_active((const uv_handle_t *) &l->server)) {
            ZITI_LOG(INFO, "listener for service[%s] is already active on port[%d]", l->service_name, l->port);
            return;
        }

        ZITI_LOG(INFO, "starting listener for service[%s] on port[%d]", l->service_name, l->port);

        NEWP(addr, struct sockaddr_in);
        TRY(uv, uv_ip4_addr("0.0.0.0", l->port, addr));
        TRY(uv, uv_tcp_bind(&l->server, (const struct sockaddr *) addr, 0));
        TRY(uv, uv_listen((uv_stream_t *) &l->server, 5, on_client));
        free(addr);
    } else {
        if (uv_is_active((const uv_handle_t *) &l->server)) {
            ZITI_LOG(WARN, "service %s is not available. stopping listener[%d]", l->service_name, l->port);
            uv_close((uv_handle_t *) &l->server, on_listener_close);
        }
    }

    CATCH(uv) {
        exit(2);
    }
}

static void binding_listen_cb(ziti_connection srv, int status) {
    struct binding *b = ziti_conn_data(srv);
    if (status != ZITI_OK) {
        ZITI_LOG(WARN, "failed to bind to service[%s]", b->service_name);
        ziti_close(b->conn, NULL);
        b->conn = NULL;
    }
}

static void on_ziti_accept(ziti_connection clt, int status) {
    uv_handle_t *s = ziti_conn_data(clt);
    if (status == ZITI_OK) {
        if (ziti_conn_bridge(clt, s, on_bridge_close) == 0) {
            if (s->type == UV_UDP) {
                ziti_conn_bridge_idle_timeout(clt, 10000);
            }
        } else {
            ZITI_LOG(WARN, "failed to bridge ziti connection and backend handle");
            ziti_close(clt, NULL);
            uv_close(s, (uv_close_cb) free);
        }
    } else {
        ziti_close(clt, NULL);
        uv_close(s, (uv_close_cb) free);
    }
}

static void on_tcp_connect(uv_connect_t *conn_req, int status) {
    ziti_connection clt = conn_req->data;

    if (status == 0) {
        ziti_conn_set_data(clt, conn_req->handle);
        ziti_accept(clt, on_ziti_accept, NULL);
    } else {
        struct binding *b = conn_req->handle->data;
        uv_getnameinfo_t name;
        uv_getnameinfo(conn_req->handle->loop, &name, NULL, b->addr->ai_addr, NI_NUMERICHOST);
        ZITI_LOG(WARN, "failed to establish connection to tcp:%s:%s", name.host, name.service);
        uv_close((uv_handle_t *) conn_req->handle, (uv_close_cb) free);
        ziti_close(clt, NULL);
    }
    free(conn_req);
}

static void binding_client_cb(ziti_connection srv, ziti_connection clt, int status, const ziti_client_ctx *clt_ctx) {
    struct binding *b = ziti_conn_data(srv);
    ziti_context ztx = ziti_conn_context(srv);
    struct proxy_app_ctx *pxy = ziti_app_ctx(ztx);

    if (status == ZITI_OK) {
        switch (b->addr->ai_protocol) {
            case IPPROTO_TCP: {
                NEWP(tcp, uv_tcp_t);
                uv_tcp_init(pxy->loop, tcp);
                tcp->data = b;

                NEWP(conn_req, uv_connect_t);
                conn_req->data = clt;
                if (uv_tcp_connect(conn_req, tcp, b->addr->ai_addr, on_tcp_connect) != 0) {
                    ziti_close(clt, NULL);
                    uv_close((uv_handle_t *) tcp, (uv_close_cb) free);
                    free(conn_req);
                }
                break;
            }
            case IPPROTO_UDP: {
                NEWP(udp, uv_udp_t);
                uv_udp_init(pxy->loop, udp);
                int rc = uv_udp_connect(udp, b->addr->ai_addr);
                if (rc != 0) {
                    ZITI_LOG(WARN, "failed to connect UDP handle: %d/%s", rc, uv_strerror(rc));
                    ziti_close(clt, NULL);
                } else {
                    ziti_conn_set_data(clt, udp);
                    ziti_accept(clt, on_ziti_accept, NULL);
                }
                break;
            }

            default:
                ziti_close(clt, NULL);
                ZITI_LOG(WARN, "unknown protocol for bound service[%s]", b->service_name);
                break;
        }
    } else {
        ZITI_LOG(WARN, "stopping serving[%s] due to %d/%s", b->service_name, status, ziti_errorstr(status));
        ziti_close(b->conn, NULL);
        b->conn = NULL;
    }
}

static void service_check_cb(ziti_context ztx, ziti_service *service, int status, void *ctx) {
    struct proxy_app_ctx *app_ctx = ctx;
    ZITI_LOG(DEBUG, "service[%s]: %s", service->name, ziti_errorstr(status));
    struct listener *l = model_map_get(&app_ctx->listeners, service->name);
    if (l) {
        update_listener(service, status, l);
    }

    struct binding *b = model_map_get(&app_ctx->bindings, service->name);
    if (b && status == ZITI_OK && (service->perm_flags & ZITI_CAN_BIND) != 0) {
        if (b->conn == NULL) {
            ziti_conn_init(ztx, &b->conn, b);
            ziti_listen(b->conn, b->service_name, binding_listen_cb, binding_client_cb);
        }
    }
}

static void on_ziti_event(ziti_context ztx, const ziti_event_t *event) {
    struct proxy_app_ctx *app_ctx = ziti_app_ctx(ztx);
    switch (event->type) {
        case ZitiConfigEvent: {
            char *cfg = ziti_config_to_json(event->cfg.config, 0, NULL);
            printf("new config:\n%s\n\n", cfg);
            free(cfg);
            break;
        }

        case ZitiContextEvent:
            if (event->ctx.ctrl_status == ZITI_OK) {
                const ziti_version *ctrl_ver = ziti_get_controller_version(ztx);
                const ziti_identity *proxy_id = ziti_get_identity(ztx);
                ZITI_LOG(INFO, "controller version = %s(%s)[%s]", ctrl_ver->version, ctrl_ver->revision,
                         ctrl_ver->build_date);
                if (proxy_id) {
                    ZITI_LOG(INFO, "proxy identity = <%s>[%s]", proxy_id->name, proxy_id->id);
                }
                app_ctx->ziti = ztx;

                for (int i = 0; i < event->ctx.ctrl_count; i++) {
                    ZITI_LOG(INFO, "ctrl[%s/%s]@%s",
                             event->ctx.ctrl_details[i].id,
                             event->ctx.ctrl_details[i].online ? "online" : "offline",
                             event->ctx.ctrl_details[i].url
                             );
                }
            } else if (event->ctx.ctrl_status == ZITI_DISABLED) {
                ZITI_LOG(INFO, "ziti is shutdown");
//                if (shutdown_timer.type == UV_TIMER && !uv_is_closing((const uv_handle_t *) &shutdown_timer))
//                    uv_close((uv_handle_t *) &shutdown_timer, NULL);
            } else {
                ZITI_LOG(ERROR, "controller is not available: %s/%s", ziti_errorstr(event->ctx.ctrl_status),
                         event->ctx.err);
            }
            break;

        case ZitiServiceEvent:
            if (event->service.removed != NULL) {
                for (ziti_service **sp = event->service.removed; *sp != NULL; sp++) {
                    service_check_cb(ztx, *sp, ZITI_SERVICE_UNAVAILABLE, app_ctx);
                }
            }

            if (event->service.added != NULL) {
                for (ziti_service **sp = event->service.added; *sp != NULL; sp++) {
                    service_check_cb(ztx, *sp, ZITI_OK, app_ctx);
                }
            }

            if (event->service.changed != NULL) {
                for (ziti_service **sp = event->service.changed; *sp != NULL; sp++) {
                    ziti_service *service = *sp;
                    service_check_cb(ztx, *sp, ZITI_OK, app_ctx);

                    MODEL_MAP_FOR(it, service->posture_query_map) {
                        ziti_posture_query_set *policy = model_map_it_value(it);
                        for (int idx = 0; policy->posture_queries[idx] != NULL; idx++) {
                            ziti_posture_query *query = policy->posture_queries[idx];

                            if (query->query_type == ziti_posture_query_type_PC_MFA &&
                                query->timeoutRemaining != NULL &&
                                *query->timeoutRemaining == 0) {
                                mfa_auth_event_handler(ztx);
                            }
                        }
                    }
                }
            }
            break;

        case ZitiRouterEvent:
            switch (event->router.status) {
                case EdgeRouterAdded:
                    ZITI_LOG(INFO, "ziti added edge router %s address=%s", event->router.name,
                             event->router.address);
                    break;
                case EdgeRouterConnected:
                    ZITI_LOG(INFO, "ziti connected to edge router %s, version = %s", event->router.name,
                             event->router.version);
                    break;
                case EdgeRouterDisconnected:
                    ZITI_LOG(INFO, "ziti disconnected from edge router %s", event->router.name);
                    break;
                case EdgeRouterRemoved:
                    ZITI_LOG(INFO, "ziti removed edge router %s", event->router.name);
                    break;
                case EdgeRouterUnavailable:
                    ZITI_LOG(INFO, "edge router %s is not available", event->router.name);
                    break;
            }
            break;
        case ZitiAuthEvent:
            if (event->auth.action == ziti_auth_prompt_totp) {
                ZITI_LOG(INFO, "ziti requires MFA %s/%s", event->auth.type, event->auth.detail);
                mfa_auth_event_handler(ztx);
            } else if (event->auth.action == ziti_auth_login_external) {
                ext_auth_event_handler(ztx, NULL);
            } else if (event->auth.action == ziti_auth_select_external) {
                const char *name = event->auth.providers[0]->name;
                ext_auth_event_handler(ztx, name);
            } else {
                ZITI_LOG(ERROR, "unhandled auth event %d/%s", event->auth.action, event->auth.type);
            }
            break;

        default:
            break;
    }
}

char *pxoxystrndup(const char *s, size_t n);

const char *my_configs[] = {
        "all", NULL
};

struct mfa_work {
    uv_work_t w;
    ziti_context ztx;
    char *code;
};

void mfa_response_cb(ziti_context ztx, int status, void *ctx);

void prompt_stdin(char *buffer, size_t buflen) {
    if (fgets(buffer, (int)buflen, stdin) != 0) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        } else {
            int ch;
            while ((ch = getc(stdin)) != EOF && ch != '\n');
        }
    }
}

void mfa_prompt(struct mfa_work *mfa_wr) {
    uv_sleep(250);
    char code[9] = "";
    printf("\nPlease provide your current MFA token: ");
    fflush(stdout);

    prompt_stdin(code, 9);

    if (strlen(code) > 0) {
        mfa_wr->code = strdup(code);
    } else {
        ZITI_LOG(ERROR, "no mfa token provided, exiting");
        exit(1);
    }
}

void mfa_response_cb(ziti_context ztx, int status, void *ctx) {
    ZITI_LOG(INFO, "mfa response status: %d", status);

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "invalid MFA token provided, exiting");
        exit(1);
    }
}

void mfa_worker(uv_work_t *req) {
    struct mfa_work *mfa_wr = req->data;
    mfa_prompt(mfa_wr);
}

void mfa_worker_done(uv_work_t *req, int status) {
    struct mfa_work *mfa_wr = (struct mfa_work *)req;
    if (status != 0) {
        ZITI_LOG(ERROR, "MFA prompt work failed: %s", uv_strerror(status));
    } else {
        ziti_mfa_auth(mfa_wr->ztx, mfa_wr->code, mfa_response_cb, mfa_wr);
    }
    FREE(mfa_wr->code);
    FREE(mfa_wr);
}

void mfa_auth_event_handler(ziti_context ztx) {
    NEWP(mfa_wr, struct mfa_work);
    mfa_wr->ztx = ztx;
    mfa_wr->w.data = mfa_wr;
    struct proxy_app_ctx *pxy = ziti_app_ctx(ztx);

    uv_queue_work(pxy->loop, &mfa_wr->w, mfa_worker, mfa_worker_done);
}

static void ext_auth_prompt(uv_work_t *wr) {
    printf("continue with external signer[Y/n]? ");
    fflush(stdout);

    char resp[1];
    prompt_stdin(resp, 1);
}

static void ext_url_launch(ziti_context ztx, const char *url, void *ctx) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "/usr/bin/open '%s'", url);
    system(cmd);
}
static void ext_auth_done(uv_work_t *wr, int status) {
    struct proxy_app_ctx *pxy = wr->data;

    ziti_ext_auth(pxy->ziti, ext_url_launch, NULL);
    free(wr);
}

void ext_auth_event_handler(ziti_context ztx, const char *name) {
    struct proxy_app_ctx *pxy = ziti_app_ctx(ztx);
    if (name) {
        // this will trigger another auth event with action login
        ziti_use_ext_jwt_signer(ztx, name);
        return;
    }

    NEWP(ext_wr, uv_work_t);
    ext_wr->data = pxy;
    uv_queue_work(pxy->loop, ext_wr, ext_auth_prompt, ext_auth_done);
}

static struct proxy_app_ctx app_ctx = {0};

static void stopper_alloc(uv_handle_t *h, size_t i, uv_buf_t *pBuf) {
    static char buf[1024];
    *pBuf = uv_buf_init(buf, sizeof(buf));
}

#define PROXC_CMD(XX, ...) \
XX(dump, __VA_ARGS__)      \
XX(stop, __VA_ARGS__)      \
XX(enable, __VA_ARGS__)    \
XX(refresh, __VA_ARGS__)   \
XX(disable, __VA_ARGS__)   \


DECLARE_ENUM(ProxyCmd, PROXC_CMD)

IMPL_ENUM(ProxyCmd, PROXC_CMD)


static void stopper_recv(uv_udp_t *u, ssize_t len,
                         const uv_buf_t *b,
                         const struct sockaddr *addr, unsigned int flags) {

    if (len == 0) return;

    ProxyCmd cmd = ProxyCmds.value_ofn(b->base, len - 1);

    switch (cmd) {
        case ProxyCmd_Unknown:
            ZITI_LOG(WARN, "unknown cmd: %.*s", (int)len, b->base);
            break;
        case ProxyCmd_dump:
            u->data = addr;
            debug_dump(&app_ctx, dump, u);
            break;
        case ProxyCmd_stop:
            process_stop(u->loop, &app_ctx);
            uv_close((uv_handle_t *) u, NULL);
            break;
        case ProxyCmd_enable:
            ziti_set_enabled(app_ctx.ziti, true);
            break;
        case ProxyCmd_refresh:
            ziti_refresh(app_ctx.ziti);
            break;
        case ProxyCmd_disable:
            ziti_set_enabled(app_ctx.ziti, false);
            break;
    }
}

static int add_binding(const char *spec, bool udp) {
    int errors = 0;
    model_list args = {0};
    str_split(spec, ":", &args);
    size_t args_len = model_list_size(&args);
    if (args_len < 2) {
        fprintf(stderr, "-b|--bind|-B|--bind-udp option should be <service:host:port>\n");
        errors++;
        goto done;
    }

    model_list_iter it = model_list_iterator(&args);
    NEWP(b, struct binding);
    b->service_name = (char*)model_list_it_element(it);
    it = model_list_it_remove(it);

    if (model_list_size(&args) > 1) {
        char *host = (char*)model_list_it_element(it);
        if (strlen(host) == 0) {
            host = "localhost";
        }
        it = model_list_it_next(it);
        char *port = (char*)model_list_it_element(it);
        struct addrinfo hints = {
            .ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM,
            .ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP,
        };
        int rc = getaddrinfo(host, port, &hints, &b->addr);
        if (rc != 0) {
            errors++;
            fprintf(stderr, "failed to resolve %s:%s for service[%s] binding", host, port, b->service_name);
        }
        model_map_set(&app_ctx.bindings, b->service_name, b);
    }
done:
    model_list_clear(&args, free);
    return errors;
}

static void set_proxy(const char *proxy_url) {
    struct tlsuv_url_s url;
    tlsuv_parse_url(&url, proxy_url);
    char host[128], port[6];
    snprintf(host, sizeof(host), "%.*s", (int)url.hostname_len, url.hostname);
    snprintf(port, sizeof(port), "%d", url.port);
    tlsuv_connector_t *proxy = tlsuv_new_proxy_connector(tlsuv_PROXY_HTTP, host, port);
    if (url.username) {
        char user[128], passwd[128];
        snprintf(user, sizeof(user), "%.*s", (int)url.username_len, url.username);
        snprintf(passwd, sizeof(passwd), "%.*s", (int)url.password_len, url.password);
        proxy->set_auth(proxy, tlsuv_PROXY_BASIC, user, passwd);
    }
    tlsuv_set_global_connector(proxy);
}

int run_proxy(struct run_opts *opts) {

    PREPF(uv, uv_strerror);

    NEWP(loop, uv_loop_t);
    uv_loop_init(loop);
    app_ctx.loop = loop;

    ziti_log_init(loop, opts->debug, NULL);

    // test shutting down by sending a UDP packet
    uv_udp_t stopper;
    struct sockaddr_in stopper_addr = {
            .sin_addr = INADDR_LOOPBACK,
            .sin_port = htons(12345),
            .sin_family = AF_INET};
    uv_udp_init(loop, &stopper);
    uv_ip4_addr("127.0.0.1", 12345, &stopper_addr);
    int rc = uv_udp_bind(&stopper, (const struct sockaddr *) &stopper_addr, 0);
    rc = uv_udp_recv_start(&stopper, stopper_alloc, stopper_recv);
    uv_unref((uv_handle_t *) &stopper);

    if (opts->proxy) set_proxy(opts->proxy);

    const char* intercept;
    MODEL_LIST_FOREACH(intercept, opts->intercepts) {
        char *p = strchr(intercept, ':');
        char *service_name = pxoxystrndup(intercept, p - intercept);

        NEWP(l, struct listener);
        l->service_name = service_name;
        l->port = (int) strtol(p + 1, NULL, 10);
        l->app_ctx = &app_ctx;

        TRY(uv, uv_tcp_init(loop, &l->server));

        l->server.data = l;

        model_map_set(&app_ctx.listeners, service_name, l);
    }

    const char *binding;
    MODEL_LIST_FOREACH(binding, opts->bindings) {
        add_binding(binding, false);
    }
    MODEL_LIST_FOREACH(binding, opts->udp_bindings) {
        add_binding(binding, true);
    }

    ziti_config cfg;

    ziti_load_config(&cfg, opts->identity);
    ziti_context_init(&app_ctx.ziti, &cfg);
    free_ziti_config(&cfg);

    ziti_options zopts = {
            .events = -1,
            .api_page_size = 25,
            .event_cb = on_ziti_event,
            .refresh_interval = 60,
            .app_ctx = &app_ctx,
            .config_types = my_configs,
            .metrics_type = INSTANT,
    };
    ziti_context_set_options(app_ctx.ziti, &zopts);

    ziti_context_run(app_ctx.ziti, loop);


#if __unix__ || __unix
    // prevent termination when running under valgrind
    // client forcefully closing connection results in SIGPIPE
    // which causes valgrind to freak out
    signal(SIGPIPE, SIG_IGN);
#endif

    for (int i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        TRY(uv, uv_signal_init(loop, &signals[i].sig));
        signals[i].sig.data = &app_ctx;
        TRY(uv, uv_signal_start(&signals[i].sig, signals[i].cb, signals[i].signum));
        uv_unref((uv_handle_t *) &signals[i].sig);
    }

    const ziti_version *ver = ziti_get_version();
    ZITI_LOG(INFO, "built with SDK version %s(%s)[%s]", ver->version, ver->revision, ver->build_date);

    if (report_metrics > 0) {
        uv_timer_init(loop, &report_timer);
        report_timer.data = &app_ctx;
        uv_timer_start(&report_timer, reporter_cb, report_metrics * 1000, report_metrics * 1000);
        uv_unref((uv_handle_t *) &report_timer);
    }
    ZITI_LOG(INFO, "starting event loop");
    uv_run(loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t *) &shutdown_timer, NULL);
    uv_run(loop, UV_RUN_DEFAULT);

    int excode = 0;
    CATCH(uv) {
        excode = ERR(uv);
    }

    model_map_clear(&app_ctx.listeners, (_free_f) free_listener);

    int close_rc = uv_loop_close(loop);
    if (close_rc != 0) {
        uv_print_active_handles(loop, stderr);
    }
    free(loop);
    exit(excode);
}

char *pxoxystrndup(const char *s, size_t n) {
    size_t len = strnlen(s, n);
    char *new = (char *) malloc(len + 1);
    if (new == NULL) {
        return NULL;
    }
    new[len] = '\0';
    return (char *) memcpy(new, s, len);
}
