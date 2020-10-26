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

#define MAX_WRITES 4

static char *config = NULL;
static int report_metrics = -1;
static uv_timer_t report_timer;
static ziti_context ziti;
static uv_signal_t sig;

struct listener {
    const char *service_name;
    int port;
    uv_tcp_t server;
    LIST_ENTRY(listener) next;
};

typedef LIST_HEAD(listeners, listener) listener_l;

struct client {
    struct sockaddr_in addr;
    char addr_s[32];
    ziti_connection ziti_conn;
    int closed;
    size_t inb_reqs;
};

static int process_args(int argc, char *argv[]);

int main(int argc, char *argv[]) {
    process_args(argc, argv);
}

static void close_server_cb(uv_handle_t *h) {
    struct listener *l = h->data;
    ZITI_LOG(DEBUG, "listener closed for %s", l->service_name);
}

static void process_stop(uv_loop_t *loop, listener_l *listeners) {
    PREPF(uv, uv_strerror);

    // shutdown listeners
    struct listener *l;
    LIST_FOREACH(l, listeners, next) {
        if (uv_is_active((const uv_handle_t *) &l->server)) {
            uv_close((uv_handle_t *) &l->server, close_server_cb);
        }
    }

    // try to cleanup
    ziti_shutdown(ziti);
    uv_loop_close(loop);

    CATCH(uv);
    ZITI_LOG(INFO, "exiting");
}

static void debug_dump(listener_l *listeners) {
    struct listener *l;

    LIST_FOREACH(l, listeners, next) {
        printf("listening for service[%s] on port[%d]\n", l->service_name, l->port);
    }
    ziti_dump(ziti);
}

static void reporter_cb(uv_timer_t *t) {
    double up, down;
    if (ziti != NULL) {
        ziti_get_transfer_rates(ziti, &up, &down);
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
            reporter_cb(&report_timer);
            break;

        default:
            break;
    }
}

static void close_cb(uv_handle_t *h) {
    struct client *clt = h->data;
    ZITI_LOG(DEBUG, "client connection closed for %s", clt->addr_s);
    free(clt);
    free(h);
}

static void on_client_write(uv_write_t *req, int status) {

    if (status < 0) {
        switch (status) {
            case UV_EPIPE:
            case UV_ECONNRESET:
            case UV_ECANCELED:
                break;
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
        buf->base = malloc(suggested_size);
        buf->len = suggested_size;
    }
    else {
        ZITI_LOG(DEBUG, "maximum outstanding writes reached clt[%s]", clt->addr_s);
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
        }
        else {
            clt->inb_reqs--;
        }
    }
    free(ctx);
}

static void data_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client *clt = stream->data;

    if (nread == UV_ENOBUFS) {
        ZITI_LOG(DEBUG, "client[%s] is throttled", clt->addr_s);
    }
    else if (nread < 0) {
        ZITI_LOG(DEBUG, "connection closed %s [%zd/%s](%s)",
                 clt->addr_s, nread, uv_err_name(nread), uv_strerror(nread));

        ziti_conn_set_data(clt->ziti_conn, NULL);
        ziti_close(&clt->ziti_conn);

        uv_read_stop(stream);
        uv_close((uv_handle_t *) stream, close_cb);
        clt->closed = true;
        free(buf->base);
    }
    else if (clt->closed) {
        free(buf->base);
    }
    else {
        clt->inb_reqs += 1;
        ziti_write(clt->ziti_conn, buf->base, nread, on_ziti_write, buf->base);
    }
}


void on_ziti_connect(ziti_connection conn, int status) {
    uv_stream_t *clt = ziti_conn_data(conn);

    if (status == ZITI_OK) {
        uv_read_start(clt, alloc_cb, data_cb);
    }
    else {
        ZITI_LOG(ERROR, "ziti connect failed: %s(%d)", ziti_errorstr(status), status);
        uv_close((uv_handle_t *) clt, close_cb);
    }
}

ssize_t on_ziti_data(ziti_connection conn, uint8_t *data, ssize_t len) {
    uv_tcp_t *clt = ziti_conn_data(conn);
    struct client *c = clt ? clt->data : NULL;

    if (clt == NULL) {
        // ziti_conn is still in process of disconnecting just drop data on the floor
        ZITI_LOG(DEBUG, "received data[%zd] for disconnected client", len);
        return len;
    }
    else if (len > 0) {
        NEWP(req, uv_write_t);
        char *copy = malloc(len);
        memcpy(copy, data, len);
        uv_buf_t buf = uv_buf_init(copy, len);
        req->data = copy;
        ZITI_LOG(TRACE, "writing %zd bytes to [%s] wqs[%zd]", len, c->addr_s, clt->write_queue_size);
        uv_write(req, (uv_stream_t *) clt, &buf, 1, on_client_write);
        return len;
    }
    else if (len < 0) {
        if (clt != NULL) {
            ZITI_LOG(DEBUG, "ziti connection closed with [%zd](%s)", len, ziti_errorstr(len));
            ziti_conn_set_data(conn, NULL);
            c->ziti_conn = NULL;
            if (!c->closed) {
                c->closed = true;
                uv_close((uv_handle_t *) clt, close_cb);
            }
        }

        return 0;
    }
    return 0;
}

static void on_client(uv_stream_t *server, int status) {
    PREPF(uv, uv_err_name);

    NEWP(c,uv_tcp_t);

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

    PREPF(ziti, ziti_errorstr);
    TRY(ziti, ziti_conn_init(ziti, &clt->ziti_conn, c));
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
        if (rc != 0) {
            ZITI_LOG(ERROR, "failed to parse client intercept");
        }
        else {
            ZITI_LOG(INFO, "should intercepting %s:%d", intercept.hostname, intercept.port);
            free_ziti_client_cfg_v1(&intercept);
        }
    }
    else {
        ZITI_LOG(WARN, "service %s is not available. stopping listener[%d]", l->service_name, l->port);
        uv_close((uv_handle_t *) &l->server, on_listener_close);
    }

    CATCH(uv) {
        exit(2);
    }
}

static void service_check_cb(ziti_context ztx, ziti_service *service, int status, void *ctx) {
    listener_l *listeners = ctx;

    struct listener *l = NULL;
    LIST_FOREACH(l, listeners, next) {
        if (strcmp(l->service_name, service->name) == 0) {
            update_listener(service, status, l);
        }
    }
}

static void on_ziti_init(ziti_context ztx, int status, void *ctx) {
    PREPF(ziti, ziti_errorstr);
    TRY(ziti, status);
    CATCH(ziti) {
        exit(status);
    }
    const ziti_version *ctrl_ver = ziti_get_controller_version(ztx);
    const ziti_identity *proxy_id = ziti_get_identity(ztx);
    ZITI_LOG(INFO, "controller version = %s(%s)[%s]", ctrl_ver->version, ctrl_ver->revision, ctrl_ver->build_date);
    ZITI_LOG(INFO, "proxy identity = <%s>[%s]@%s", proxy_id->name, proxy_id->id, ziti_get_controller(ztx));

    ziti = ztx;
}


char* pxoxystrndup(const char* s, int n);
const char *my_configs[] = {
        "all", NULL
};

void run(int argc, char **argv) {

    PREPF(uv, uv_strerror);

    NEWP(loop, uv_loop_t);
    uv_loop_init(loop);

    listener_l listeners = LIST_HEAD_INITIALIZER(listeners);
    for (int i = 0; i < argc; i++) {

        char *p = strchr(argv[i], ':');
        char* service_name = pxoxystrndup(argv[i], p - argv[i]);

        NEWP(l, struct listener);
        l->service_name = service_name;
        l->port = (int) strtol(p + 1, NULL, 10);

        TRY(uv, uv_tcp_init(loop, &l->server));

        l->server.data = l;

        LIST_INSERT_HEAD(&listeners, l, next);
    }

    ziti_options opts = {
            .config = config,
            .init_cb = on_ziti_init,
            .service_cb = service_check_cb,
            .refresh_interval = 600,
            .ctx = &listeners,
            .config_types = my_configs,
            .metrics_type = INSTANT,
    };

    ziti_init_opts(&opts, loop, &listeners);

    TRY(uv, uv_signal_init(loop, &sig));
    sig.data = &listeners;
    TRY(uv, uv_signal_start(&sig, signal_cb, SIGINT));
    TRY(uv, uv_signal_start(&sig, signal_cb, SIGTERM));
    TRY(uv, uv_signal_start(&sig, signal_cb, SIGUSR1));

    uv_unref((uv_handle_t *) &sig);

    const ziti_version *ver = ziti_get_version();
    ZITI_LOG(INFO, "built with SDK version %s(%s)[%s]", ver->version, ver->revision, ver->build_date);

    if (report_metrics > 0) {
        uv_timer_init(loop, &report_timer);
        uv_timer_start(&report_timer, reporter_cb, report_metrics * 1000, report_metrics * 1000);
        uv_unref((uv_handle_t*)&report_timer);
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
            {"debug",  optional_argument, NULL, 'd'},
            {"config", required_argument, NULL, 'c'},
            {"metrics", optional_argument, NULL, 'm'},
            {NULL, 0,                     NULL, 0}
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
                }
                else {
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
            {NULL, 0, NULL, 0}
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
    commandline_run(&main_cmd, argc, argv);
    return 0;
}

char* pxoxystrndup(const char* s, int n)
{
    size_t len = strnlen(s, n);
    char* new = (char*)malloc(len + 1);
    if (new == NULL)
        return NULL;
    new[len] = '\0';
    return (char*)memcpy(new, s, len);
}