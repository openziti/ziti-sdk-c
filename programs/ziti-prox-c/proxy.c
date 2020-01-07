/*
Copyright 2019-2020 Netfoundry, Inc.

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

#include <uv.h>

#include <stdlib.h>
#include <string.h>

#include <utils.h>
#include <nf/ziti.h>

#if(WIN32)
#define strsignal(s) "_windows_unimplemented_"
#endif

#define MAX_WRITES 4

static const char *config = NULL;
static nf_context nf;
static uv_signal_t sig;

struct listener {
    const char *service_name;
    int port;
    uv_tcp_t server;
    SLIST_ENTRY(listener) next;
};

struct client {
    struct sockaddr_in addr;
    char addr_s[32];
    nf_connection nf_conn;
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

static void signal_cb(uv_signal_t *s, int signum) {
    ZITI_LOG(INFO, "signal[%d/%s] received", signum, strsignal(signum));
    PREPF(uv, uv_strerror);
     
    // shutdown listeners
    SLIST_HEAD(listeners, listener) *listeners = s->data;
    struct listener *l;
    SLIST_FOREACH(l, listeners, next) {
        if (uv_is_active((const uv_handle_t *) &l->server)) {
            uv_close((uv_handle_t *) &l->server, close_server_cb);
        }
    }

    // try to cleanup
    NF_shutdown(nf);
    uv_loop_close(s->loop);

    CATCH(uv);
    ZITI_LOG(INFO, "exiting");
}

static void close_cb(uv_handle_t *h) {
    struct client *clt = h->data;
    ZITI_LOG(DEBUG, "client connection closed for %s", clt->addr_s);
    clt->closed = 1;
    if (clt->inb_reqs == 0) {
        free(clt);
        free(h);
    }
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
        buf->base = NULL;
        buf->len = 0;
    }
}

static void on_nf_write(nf_connection conn, ssize_t status, void *ctx) {
    uv_stream_t *stream = NF_conn_data(conn);
    struct client *clt = stream->data;
    if (status < 0) {
        ZITI_LOG(ERROR, "nf_write failed status[%zd] %s", status, ziti_errorstr(status));
        uv_close((uv_handle_t *) stream, close_cb);
    }
    else {
        clt->inb_reqs--;
        if (clt->inb_reqs == 0 && clt->closed) {
            free(clt);
            free(stream);
        }
    }
    free(ctx);
}

static void data_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client *clt = stream->data;

    if (nread == UV_ENOBUFS) {
        // this error indicates that we are throttled by backend, see alloc_cb()
    }
    else if (nread < 0) {
        ZITI_LOG(DEBUG,  "connection closed %s [%zd/%s](%s)",
                 clt->addr_s, nread, uv_err_name(nread), uv_strerror(nread));

        NF_close((nf_connection *) &clt->nf_conn);

        uv_read_stop(stream);
    }
    else {
        clt->inb_reqs += 1;
        NF_write(clt->nf_conn, buf->base, nread, on_nf_write, buf->base);
    }
}


void on_ziti_connect(nf_connection conn, int status) {
    uv_stream_t *clt = NF_conn_data(conn);

    if (status == ZITI_OK) {
        uv_read_start(clt, alloc_cb, data_cb);
    }
    else {
        ZITI_LOG(ERROR, "ziti connect failed: %s(%d)", ziti_errorstr(status), status);
        uv_close((uv_handle_t *) clt, close_cb);
    }
}

void on_ziti_data(nf_connection conn, uint8_t *data, int len) {
    uv_tcp_t *clt = NF_conn_data(conn);
    struct client *c = clt->data;

    if (len > 0) {
        NEWP(req, uv_write_t);
        char *copy = malloc(len);
        memcpy(copy, data, len);
        uv_buf_t buf = uv_buf_init(copy, len);
        req->data = copy;
        uv_write(req, (uv_stream_t *) clt, &buf, 1, on_client_write);
        ZITI_LOG(TRACE, "[%s] wqs[%zd]", c->addr_s, clt->write_queue_size);
    }
    else {
        ZITI_LOG(DEBUG, "ziti connection closed with [%d](%s)", len, ziti_errorstr(len));
        uv_close((uv_handle_t *) clt, close_cb);
    }

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

    PREPF(nf, ziti_errorstr);
    TRY(nf, NF_conn_init(nf, &clt->nf_conn, c));
    TRY(nf, NF_dial(clt->nf_conn, l->service_name, on_ziti_connect, on_ziti_data));
    c->data = clt;

    CATCH(nf) {
        free(clt);
        ZITI_LOG(ERROR, "closing client [%s]", clt->addr_s);
        uv_close((uv_handle_t *) c, close_cb);
    }

}

static void service_avail_cb(nf_context nf_ctx, const char* service, int status, void *ctx) {
    struct listener *l = ctx;
    PREPF(uv, uv_strerror);

    if (status == ZITI_OK) {
        ZITI_LOG(INFO, "starting listener for service[%s] on port[%d]", l->service_name, l->port);

        NEWP(addr, struct sockaddr_in);
        TRY(uv, uv_ip4_addr("0.0.0.0", l->port, addr));
        TRY(uv, uv_tcp_bind(&l->server, (const struct sockaddr *) addr, 0));
        TRY(uv, uv_listen((uv_stream_t *) &l->server, 5, on_client));
    }
    else {
        ZITI_LOG(ERROR, "service %s is not available. not starting listener", service);
    }

    CATCH(uv) {
        exit(2);
    }
}

static void on_nf_init(nf_context nf_ctx, int status, void* ctx) {
    PREPF(ziti, ziti_errorstr);
    TRY(ziti, status);
    CATCH(ziti) {
        exit(status);
    }

    nf = nf_ctx;

    SLIST_HEAD(listeners, listener) *listeners = ctx;
    struct listener *l;
    SLIST_FOREACH(l, listeners, next) {
        NF_service_available(nf, l->service_name, service_avail_cb, l);
    }
}


char* pxoxystrndup(const char* s, int n);

void run(int argc, char **argv) {
    PREPF(uv, uv_strerror);

    NEWP(loop, uv_loop_t);
    uv_loop_init(loop);

    SLIST_HEAD(listeners, listener) listeners = SLIST_HEAD_INITIALIZER(listeners);
    for (int i = 0; i < argc; i++) {

        char *p = strchr(argv[i], ':');
        char* service_name = pxoxystrndup(argv[i], p - argv[i]);

        NEWP(l, struct listener);
        l->service_name = service_name;
        l->port = (int) strtol(p + 1, NULL, 10);

        TRY(uv, uv_tcp_init(loop, &l->server));

        l->server.data = l;

        SLIST_INSERT_HEAD(&listeners, l, next);
    }

    NF_init(config, loop, on_nf_init, &listeners);

    TRY(uv, uv_signal_init(loop, &sig));
    sig.data = &listeners;
    TRY(uv, uv_signal_start(&sig, signal_cb, SIGINT));
    TRY(uv, uv_signal_start(&sig, signal_cb, SIGTERM));
    uv_unref((uv_handle_t *) &sig);

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
            {NULL, 0,                     NULL, 0}
    };

    int c, option_index, errors = 0;
    int debug_level = 1;
    bool debug_set = false;

    optind = 0;

    while ((c = getopt_long(argc, argv, "dc:",
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
    printf("%s\n", ziti_get_version(ver_verbose));
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