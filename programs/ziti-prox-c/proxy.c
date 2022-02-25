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
#define _GNU_SOURCE

#include <uv.h>

#include <stdlib.h>
#include <string.h>

#include <utils.h>
#include <ziti/ziti.h>

#if(WIN32)
#define strsignal(s) "_windows_unimplemented_"
#endif

#if !defined (SIGUSR1)
#define SIGUSR1 10
#endif

#define MAX_WRITES 16

/* avoid xgress chunking */
#define MAX_PROXY_PAYLOAD (63*1024)

static char *config = NULL;
static int report_metrics = -1;
static uv_timer_t report_timer;

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
    LIST_HEAD(clients, client) clients;
    ziti_context ziti;
};

struct listener {
    const char *service_name;
    int port;
    uv_tcp_t server;
    struct proxy_app_ctx *app_ctx;
    //LIST_ENTRY(listener) next;
};

// typedef LIST_HEAD(listeners, listener) listener_l;

struct client {
    struct sockaddr_in addr;
    char addr_s[32];
    ziti_connection ziti_conn;
    bool read_done;
    bool write_done;
    int closed;
    size_t inb_reqs;

    LIST_ENTRY(client) next;
};

uv_loop_t *global_loop;

static int process_args(int argc, char *argv[]);
void mfa_auth_event_handler(ziti_context ztx);

int main(int argc, char *argv[]) {
    process_args(argc, argv);
}

static void close_server_cb(uv_handle_t *h) {
    struct listener *l = h->data;
    ZITI_LOG(DEBUG, "listener closed for %s", l->service_name);
}

static void shutdown_timer_cb(uv_timer_t *t) {
    uv_loop_t *l = t->loop;

    uv_print_active_handles(l, stderr);
}

static void process_stop(uv_loop_t *loop, struct proxy_app_ctx *app_ctx) {
    PREPF(uv, uv_strerror);

    // shutdown clients
    struct client *clt;
    LIST_FOREACH(clt, &app_ctx->clients, next) {
        ziti_close(clt->ziti_conn, on_ziti_close);
    }

    // shutdown listeners
    MODEL_MAP_FOR(it, app_ctx->listeners) {
        struct listener *l = model_map_it_value(it);
        if (uv_is_active((const uv_handle_t *) &l->server)) {
            uv_close((uv_handle_t *) &l->server, close_server_cb);
        }
    }

    // shutdown diagnostics
    static uv_timer_t shutdown_timer;
    uv_timer_init(loop, &shutdown_timer);
    uv_timer_start(&shutdown_timer, shutdown_timer_cb, 5000, 0);
    uv_unref((uv_handle_t *) &shutdown_timer);

    // try to cleanup
    ziti_shutdown(app_ctx->ziti);
    uv_loop_close(loop);

    CATCH(uv) {}
    ZITI_LOG(INFO, "exiting");
}

static void debug_dump(struct proxy_app_ctx *app_ctx) {
    MODEL_MAP_FOR(it, app_ctx->listeners) {
        struct listener *l = model_map_it_value(it);
        printf("listening for service[%s] on port[%d]\n", l->service_name, l->port);
    }
    ziti_dump(app_ctx->ziti, fprintf, stdout);
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
            debug_dump(s->data);
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

static void on_client_write(uv_write_t *req, int status) {
    uv_stream_t *s = req->handle;
    struct client *client = s->data;
    if (status < 0) {
        switch (status) {
            case UV_EPIPE:
            case UV_ECONNRESET:
            case UV_ECANCELED: {
                ZITI_LOG(WARN, "write failed: [%d/%s](%s) -- closing client[%s]", status,
                         uv_err_name(status), uv_strerror(status), client->addr_s);
                client->write_done = true;
                ziti_close(client->ziti_conn, on_ziti_close);
                break;
            }
            default:
                ZITI_LOG(WARN, "unexpected: [%d/%s](%s)", status, uv_err_name(status), uv_strerror(status));
        }
    }
    free(req->data);
    free(req);
}

static void alloc_cb(uv_handle_t *h, size_t suggested_size, uv_buf_t *buf) {
    struct client *clt = h->data;

    // if too many writes are in flight throttle the client
    if (clt->inb_reqs < MAX_WRITES) {
        buf->len = suggested_size > MAX_PROXY_PAYLOAD ? MAX_PROXY_PAYLOAD : suggested_size;
        buf->base = malloc(buf->len);
    } else {
        ZITI_LOG(VERBOSE, "maximum outstanding writes reached clt[%s]", clt->addr_s);
        buf->base = NULL;
        buf->len = 0;
    }
}

static void on_ziti_write(ziti_connection conn, ssize_t status, void *ctx) {
    uv_stream_t *stream = ziti_conn_data(conn);
    if (stream != NULL) {
        struct client *clt = stream->data;
        if (status < 0) {
            ZITI_LOG(ERROR, "ziti_write failed status[%zd] %s", status, ziti_errorstr(status));
            if (!clt->closed) {
                uv_close((uv_handle_t *) stream, close_cb);
                clt->closed = true;
            }
        } else {
            clt->inb_reqs--;
        }
    }
    free(ctx);
}

static void data_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client *clt = stream->data;
    ZITI_LOG(TRACE, "client[%s]: nread[%zd]", clt->addr_s, nread);
    if (nread == UV_ENOBUFS) {
        ZITI_LOG(VERBOSE, "client[%s] is throttled", clt->addr_s);
    } else if (nread == UV_EOF) {
        ZITI_LOG(DEBUG, "connection %s sent FIN write_done=%d, read_done=%d", clt->addr_s, clt->write_done,
                 clt->read_done);
        clt->read_done = true;
        if (clt->write_done) {
            ZITI_LOG(DEBUG, "closing client[%s]", clt->addr_s);
            ziti_close(clt->ziti_conn, on_ziti_close);
        } else {
            ziti_close_write(clt->ziti_conn);
            uv_read_stop(stream);
        }
        free(buf->base);
    } else if (nread < 0) {
        ZITI_LOG(DEBUG, "connection closed %s [%zd/%s](%s)",
                 clt->addr_s, nread, uv_err_name(nread), uv_strerror(nread));

        ziti_close(clt->ziti_conn, on_ziti_close);

        uv_read_stop(stream);
        uv_close((uv_handle_t *) stream, close_cb);
        clt->closed = true;
        free(buf->base);
    } else if (clt->closed) {
        free(buf->base);
    } else {
        clt->inb_reqs += 1;
        ziti_write(clt->ziti_conn, buf->base, nread, on_ziti_write, buf->base);
    }
}


void on_ziti_connect(ziti_connection conn, int status) {
    uv_stream_t *clt = ziti_conn_data(conn);

    if (status == ZITI_OK) {
        uv_read_start(clt, alloc_cb, data_cb);
        ziti_context ztx = ziti_conn_context(conn);
        struct proxy_app_ctx *app = ziti_app_ctx(ztx);
        struct client *c = clt->data;
    } else {
        ZITI_LOG(ERROR, "ziti connect failed: %s(%d)", ziti_errorstr(status), status);
        uv_close((uv_handle_t *) clt, close_cb);
        ziti_close(conn, on_ziti_close);
    }
}

static void tcp_shutdown_cb(uv_shutdown_t *sr, int code) {
    free(sr);
}

ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len) {
    uv_tcp_t *clt = ziti_conn_data(conn);
    struct client *c = clt ? clt->data : NULL;

    if (clt == NULL) {
        // ziti_conn is still in process of disconnecting just drop data on the floor
        ZITI_LOG(DEBUG, "received data[%zd] for disconnected client", len);
        return len;
    }

    if (!uv_is_active((const uv_handle_t *) clt)) {
        c->closed = true;
        ZITI_LOG(DEBUG, "tcp side of client[%s] is closed", c->addr_s);
        ziti_close(c->ziti_conn, on_ziti_close);
        return UV_ECONNABORTED;
    }

    if (len > 0) {
        NEWP(req, uv_write_t);
        char *copy = malloc(len);
        memcpy(copy, data, len);
        uv_buf_t buf = uv_buf_init(copy, len);
        req->data = copy;
        ZITI_LOG(TRACE, "writing %zd bytes to [%s] wqs[%zd]", len, c->addr_s, clt->write_queue_size);
        uv_write(req, (uv_stream_t *) clt, &buf, 1, on_client_write);
        return len;
    } else if (len == ZITI_EOF) {
        ZITI_LOG(DEBUG, "ziti sent EOF to[%s] write_done=%d, read_done=%d", c->addr_s, c->write_done, c->read_done);
        if (c->read_done) {
            if (!c->closed) {
                c->closed = true;
                uv_close((uv_handle_t *) clt, close_cb);
            }
        } else {
            uv_shutdown_t *sr = calloc(1, sizeof(uv_shutdown_t));
            uv_shutdown(sr, (uv_stream_t *) clt, tcp_shutdown_cb);
            c->write_done = true;
        }
    } else if (len < 0) {
        if (clt != NULL) {
            ZITI_LOG(DEBUG, "ziti connection closed with [%zd](%s)", len, ziti_errorstr(len));
            if (!c->closed) {
                c->closed = true;
                ZITI_LOG(DEBUG, "closing clt[%s]", c->addr_s);
                uv_close((uv_handle_t *) clt, close_cb);
            }
        }

        return 0;
    }
    return 0;
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
    TRY(ziti, ziti_dial(clt->ziti_conn, l->service_name, on_ziti_connect, on_ziti_data));
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

        // this is for illustration purposes only
        ziti_client_cfg_v1 intercept;
        int rc = ziti_service_get_config(service, "ziti-tunneler-client.v1", &intercept,
                                         (int (*)(void *, const char *, size_t)) parse_ziti_client_cfg_v1);
        if (rc < 0) {
            ZITI_LOG(ERROR, "failed to parse client intercept");
        } else {
            ZITI_LOG(INFO, "should intercepting %s:%d", intercept.hostname, intercept.port);
            free_ziti_client_cfg_v1(&intercept);
        }
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

static void service_check_cb(ziti_context ztx, ziti_service *service, int status, void *ctx) {
    struct proxy_app_ctx *app_ctx = ctx;
    ZITI_LOG(DEBUG, "service[%s]: %s", service->name, ziti_errorstr(status));
    struct listener *l = model_map_get(&app_ctx->listeners, service->name);
    if (l) {
        update_listener(service, status, l);
    }
}

static void on_ziti_event(ziti_context ztx, const ziti_event_t *event) {
    struct proxy_app_ctx *app_ctx = ziti_app_ctx(ztx);
    switch (event->type) {
        case ZitiAPIEvent:
            ZITI_LOG(INFO, "update API URL to %s", event->event.api.new_ctrl_address);
            break;

        case ZitiContextEvent:
            if (event->event.ctx.ctrl_status == ZITI_OK) {
                const ziti_version *ctrl_ver = ziti_get_controller_version(ztx);
                const ziti_identity *proxy_id = ziti_get_identity(ztx);
                ZITI_LOG(INFO, "controller version = %s(%s)[%s]", ctrl_ver->version, ctrl_ver->revision,
                         ctrl_ver->build_date);
                ZITI_LOG(INFO, "proxy identity = <%s>[%s]@%s", proxy_id->name, proxy_id->id, ziti_get_controller(ztx));
                app_ctx->ziti = ztx;
            } else {
                ZITI_LOG(ERROR, "controller is not available: %s/%s", ziti_errorstr(event->event.ctx.ctrl_status), event->event.ctx.err);
            }
            break;

        case ZitiServiceEvent:
            if (event->event.service.removed != NULL) {
                for (ziti_service **sp = event->event.service.removed; *sp != NULL; sp++) {
                    service_check_cb(ztx, *sp, ZITI_SERVICE_UNAVAILABLE, app_ctx);
                }
            }

            if (event->event.service.added != NULL) {
                for (ziti_service **sp = event->event.service.added; *sp != NULL; sp++) {
                    service_check_cb(ztx, *sp, ZITI_OK, app_ctx);
                }
            }

            if (event->event.service.changed != NULL) {
                for (ziti_service **sp = event->event.service.changed; *sp != NULL; sp++) {
                    ziti_service *service = *sp;

                    MODEL_MAP_FOR(it, service->posture_query_map) {
                        ziti_posture_query_set *policy = model_map_it_value(it);
                        for (int idx = 0; policy->posture_queries[idx] != NULL; idx++) {
                            ziti_posture_query *query = policy->posture_queries[idx];

                            if (strcmp(query->query_type, "MFA") == 0 && query->timeoutRemaining != NULL && *query->timeoutRemaining == 0) {
                                mfa_auth_event_handler(ztx);
                            }
                        }
                    }
                }
            }
            break;

        case ZitiRouterEvent:
            switch (event->event.router.status) {
                case EdgeRouterAdded:
                    ZITI_LOG(INFO, "ziti added edge router %s address=%s", event->event.router.name, event->event.router.address);
                    break;
                case EdgeRouterConnected:
                    ZITI_LOG(INFO, "ziti connected to edge router %s, version = %s", event->event.router.name, event->event.router.version);
                    break;
                case EdgeRouterDisconnected:
                    ZITI_LOG(INFO, "ziti disconnected from edge router %s", event->event.router.name);
                    break;
                case EdgeRouterRemoved:
                    ZITI_LOG(INFO, "ziti removed edge router %s", event->event.router.name);
                    break;
                case EdgeRouterUnavailable:
                    ZITI_LOG(INFO, "edge router %s is not available", event->event.router.name);
                    break;
            }
            break;
        case ZitiMfaAuthEvent:
            mfa_auth_event_handler(ztx);

        default:
            break;
    }
}

char *pxoxystrndup(const char *s, int n);

const char *my_configs[] = {
        "all", NULL
};

struct mfa_work {
    uv_work_t w;
    ziti_context ztx;
};

void mfa_response_cb(ziti_context ztx, int status, void *ctx);

void prompt_stdin(char *buffer, size_t buflen) {
    if (fgets(buffer, buflen, stdin) != 0) {
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
        ziti_mfa_auth(mfa_wr->ztx, code, mfa_response_cb, mfa_wr);
    } else {
        ZITI_LOG(ERROR, "no mfa token provided, exiting");
        exit(1);
    };


}

void mfa_response_cb(ziti_context ztx, int status, void *ctx) {
    struct mfa_work *mfa_wr = ctx;
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
    FREE(req);
}

void mfa_auth_event_handler(ziti_context ztx) {
    NEWP(mfa_wr, struct mfa_work);
    mfa_wr->ztx = ztx;
    mfa_wr->w.data = mfa_wr;

    uv_queue_work(global_loop, &mfa_wr->w, mfa_worker, mfa_worker_done);
}


void run(int argc, char **argv) {

    PREPF(uv, uv_strerror);

    NEWP(loop, uv_loop_t);
    uv_loop_init(loop);
    global_loop = loop;

    struct proxy_app_ctx app_ctx = {0};
    for (int i = 0; i < argc; i++) {

        char *p = strchr(argv[i], ':');
        char *service_name = pxoxystrndup(argv[i], p - argv[i]);

        NEWP(l, struct listener);
        l->service_name = service_name;
        l->port = (int) strtol(p + 1, NULL, 10);
        l->app_ctx = &app_ctx;

        TRY(uv, uv_tcp_init(loop, &l->server));

        l->server.data = l;

        model_map_set(&app_ctx.listeners, service_name, l);
    }

    ziti_options opts = {
            .config = config,
            .events = -1,
            .event_cb = on_ziti_event,
            .refresh_interval = 60,
            .router_keepalive = 10,
            .app_ctx = &app_ctx,
            .config_types = my_configs,
            .metrics_type = INSTANT,
    };

    ziti_init_opts(&opts, loop);


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

    int excode = 0;
    CATCH(uv) {
        excode = ERR(uv);
    }

    ZITI_LOG(INFO, "proxy event loop is done");
    free(loop);
    exit(excode);
}

#define COMMAND_LINE_IMPLEMENTATION

#include <commandline.h>
#include <getopt.h>
#include <stdbool.h>

CommandLine main_cmd;
#define GLOBAL_FLAGS "[--debug=level|-d[ddd]] [--config|-c=<path>] "

int run_opts(int argc, char **argv) {
    static struct option long_options[] = {
            {"debug",   optional_argument, NULL, 'd'},
            {"config",  required_argument, NULL, 'c'},
            {"metrics", optional_argument, NULL, 'm'},
            {NULL,      0,                 NULL, 0}
    };

    int c, option_index, errors = 0;
    int debug_level = 1;
    bool debug_set = false;

    optind = 0;

    while ((c = getopt_long(argc, argv, "d:c:m:",
                            long_options, &option_index)) != -1) {
        switch (c) {
            case 'd':
                debug_set = true;
                if (optarg) {
                    debug_level = (int) strtol(optarg, NULL, 10);
                } else {
                    debug_level++;
                }
                break;

            case 'c':
                config = strdup(optarg);
                break;

            case 'm':
                report_metrics = 10;
                if (optarg) {
                    report_metrics = (int) strtol(optarg, NULL, 10);
                }
                break;

            default: {
                fprintf(stderr, "Unknown option \"%c\"\n", c);
                errors++;
                break;
            }
        }
    }

    if (errors > 0) {
        commandline_help(stderr);
        exit(1);
    }

    if (debug_set) {
        char level[6];
        sprintf(level, "%d", debug_level);
#if _WIN32
        SetEnvironmentVariable("ZITI_LOG", level);
#else
        setenv("ZITI_LOG", level, 1);
#endif

    }
    return optind;
}

void usage(int argc, char **argv) {
    commandline_print_usage(&main_cmd, stderr);
}

static int ver_verbose = 0;

int version_opts(int argc, char **argv) {
    static struct option long_options[] = {
            {"verbose", no_argument, NULL, 'v'},
            {NULL,      0,           NULL, 0}
    };

    int c, option_index, errors = 0;
    optind = 0;

    while ((c = getopt_long(argc, argv, "v",
                            long_options, &option_index)) != -1) {
        switch (c) {
            case 'v':
                ver_verbose = 1;
                break;

            default: {
                fprintf(stderr, "Unknown option '%c'\n", c);
                errors++;
                break;
            }
        }
    }

    if (errors > 0) {
        commandline_help(stderr);
        exit(1);
    }

    return optind;
}

void version(int argc, char **argv) {
    printf("%s\n", ziti_get_build_version(ver_verbose));
}

CommandLine run_cmd = make_command("run", "run proxy", "run <service-name>:port", "run help", run_opts, run);
CommandLine ver_cmd = make_command("version", "show version", "version", NULL, version_opts, version);
CommandLine help_cmd = make_command("help", "help", NULL, NULL, NULL, usage);
CommandLine *main_cmds[] = {
        &run_cmd,
        &ver_cmd,
        &help_cmd,
        NULL
};

CommandLine main_cmd = make_command_set("ziti-prox-c",
                                        "Ziti Proxy",
                                        GLOBAL_FLAGS
                                                "<command> [<args>]", "Ziti Proxy",
                                        NULL, main_cmds);

static int process_args(int argc, char *argv[]) {
    ziti_set_app_info(main_cmd.name, to_str(ZITI_VERSION));
    commandline_run(&main_cmd, argc, argv);
    return 0;
}

char *pxoxystrndup(const char *s, int n) {
    size_t len = strnlen(s, n);
    char *new = (char *) malloc(len + 1);
    if (new == NULL)
        return NULL;
    new[len] = '\0';
    return (char *) memcpy(new, s, len);
}
