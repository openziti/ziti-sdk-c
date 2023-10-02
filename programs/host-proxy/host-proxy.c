// Copyright (c) 2021-2023.  NetFoundry Inc.
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

#include <ziti/ziti.h>
#include <string.h>
#include "ziti/ziti_log.h"

struct app_ctx {
    uv_loop_t *loop;
    ziti_context ztx;

    model_map bindings;
};

typedef struct {
    char *service_id;
    char *service_name;
    ziti_server_cfg_v1 *host_cfg;
    ziti_connection server;
    struct app_ctx *app;
} host_binding;

typedef struct {
    ziti_connection ziti_conn;
    uv_tcp_t tcp;
} host_connection;

static const char *config_types[] = {
        "ziti-tunneler-server.v1"
};

static void on_ziti_event(ziti_context ztx, const ziti_event_t *event);

static void bind_service(struct app_ctx *app, ziti_context ztx, ziti_service *s, ziti_server_cfg_v1 *host_cfg);

int main(int argc, char *argv[]) {
    uv_loop_t *loop = uv_default_loop();
    ziti_log_init(loop, ZITI_LOG_DEFAULT_LEVEL, NULL);

    struct app_ctx ctx = {
            .loop = loop,
    };

    ziti_config cfg;
    ziti_context ztx = NULL;

#define check(op) do{ \
int err = (op); if (err != ZITI_OK) { \
fprintf(stderr, "ERROR: %s", ziti_errorstr(err)); \
exit(err);\
}}while(0)

    check(ziti_load_config(&cfg, argv[1]));
    check(ziti_context_init(&ztx, &cfg));
    check(ziti_context_set_options(ztx, &(ziti_options){
            .app_ctx = &ctx,
            .refresh_interval = 60,
            .config_types = config_types,
            .event_cb = on_ziti_event,
            .events = ZitiContextEvent | ZitiServiceEvent,
    }));

    ziti_context_run(ztx, loop);

    uv_run(loop, UV_RUN_DEFAULT);
}

void on_ziti_event(ziti_context ztx, const ziti_event_t *event) {
    struct app_ctx *ctx = ziti_app_ctx(ztx);

    if (event->type == ZitiServiceEvent) {
        const struct ziti_service_event *se = &event->event.service;
        for (int i = 0; se->added[i] != NULL; i++) {
            ziti_service *s = se->added[i];
            if ((s->perm_flags & ZITI_CAN_BIND) == 0) {
                continue;
            }

            ziti_server_cfg_v1 *host_cfg = calloc(1, sizeof(ziti_server_cfg_v1));
            int rc = ziti_service_get_config(s, config_types[0], host_cfg,
                                             (int (*)(void *, const char *, size_t)) parse_ziti_server_cfg_v1);
            if (rc != ZITI_OK) {
                fprintf(stderr, "skipping service[%s] hosting config: %s\n", s->name, ziti_errorstr(rc));
                free_ziti_server_cfg_v1(host_cfg);
                free(host_cfg);
                continue;
            }

            bind_service(ctx, ztx, s, host_cfg);
        }
    }
}

/*************** Proxy functions ************/

static void on_tcp_write(uv_write_t *wr, int status) {
    free(wr->data);
    free(wr);
    if (status != 0) {
        fprintf(stderr, "failed to write to client: %s\n", uv_strerror(status));
    }
}

static void on_tcp_shutdown(uv_shutdown_t *sr, int status) {
    free(sr);
}

static void on_tcp_close(uv_handle_t *s) {
    host_connection *hc = s->data;
    free(hc);
}

static void ziti_proxy_close_cb(ziti_connection c) {
    host_connection *hc = ziti_conn_data(c);
    uv_close((uv_handle_t *) &hc->tcp, on_tcp_close);
}

static ssize_t on_ziti_data(ziti_connection c, const uint8_t *b, ssize_t len) {
    host_connection *hc = ziti_conn_data(c);

    if (len > 0) {
        uv_write_t *wr = calloc(1, sizeof(uv_write_t));

        char *copy = malloc(len);
        memcpy(copy, b, len);
        uv_buf_t buf = uv_buf_init(copy, len);

        wr->data = copy;
        uv_write(wr, (uv_stream_t *) &hc->tcp, &buf, 1, on_tcp_write);
    } else if (len == ZITI_EOF) {
        uv_shutdown_t *sr = calloc(1, sizeof(uv_shutdown_t));
        uv_shutdown(sr, (uv_stream_t *) &hc->tcp, on_tcp_shutdown);
    } else {
        uv_read_stop((uv_stream_t *) &hc->tcp);
        ziti_close(hc->ziti_conn, ziti_proxy_close_cb);
    }
    return len;
}

static void alloc_cb(uv_handle_t *h, size_t len, uv_buf_t *b) {
    b->base = malloc(len);
    if (b->base) {
        b->len = len;
    } else {
        b->len = 0;
    }
}

static void on_ziti_write(ziti_connection c, ssize_t status, void *ctx) {
    free(ctx);

    if (status < ZITI_OK) {
        host_connection *hc = ziti_conn_data(c);
        uv_read_stop((uv_stream_t *) &hc->tcp);
        ziti_close(c, ziti_proxy_close_cb);
    }
}

static void on_tcp_data(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    host_connection *hc = s->data;
    if (len > 0) {
        ziti_write(hc->ziti_conn, (uint8_t *) buf->base, len, on_ziti_write, buf->base);
    } else {
        if (len == UV_EOF) {
            ziti_close_write(hc->ziti_conn);
        } else {
            printf("tcp peer closed: %s\n", uv_strerror(len));
            ziti_close(hc->ziti_conn, ziti_proxy_close_cb);
        }

        if (buf->base) {
            free(buf->base);
        }
    }
}

static void on_accept(ziti_connection c, int status) {
    printf("ziti connection established\n");
}

static void on_tcp_connect(uv_connect_t *cr, int status) {
    uv_tcp_t *tcp = (uv_tcp_t *) cr->handle;
    host_connection *hc = tcp->data;
    if (status == 0) {
        ziti_accept(hc->ziti_conn, on_accept, on_ziti_data);
        uv_read_start(cr->handle, alloc_cb, on_tcp_data);
    }

    free(cr);
}

/************* Binding functions *************/
static void listen_cb(ziti_connection server, int status) {
    host_binding *b = ziti_conn_data(server);
    if (status == ZITI_OK) {
        printf("successfully bound to service[%s]\n", b->service_name);
    } else {
        fprintf(stderr, "failed to bind to service[%s]\n", b->service_name);
        // TODO close/retry?
    }
}

static void on_client(ziti_connection server, ziti_connection conn, int status, ziti_client_ctx *clt_ctx) {
    if (status == ZITI_OK) {
        host_binding *binding = ziti_conn_data(server);
        struct app_ctx *app = binding->app;

        printf("accepting connection from <<<%s>>>\n", clt_ctx->caller_id);
        printf("client supplied data: '%.*s'", (int) clt_ctx->app_data_sz, clt_ctx->app_data);

        uv_getaddrinfo_t resolve;
        char port[6];
        snprintf(port, sizeof(port), "%hu", (short) binding->host_cfg->port);
        if (uv_getaddrinfo(app->loop, &resolve, NULL, binding->host_cfg->hostname, port, NULL) != 0) {
            fprintf(stderr, "failed to resolve %s:%d\n", binding->host_cfg->hostname, binding->host_cfg->port);
            return;
        }

        host_connection *hc = calloc(1, sizeof(host_connection));
        hc->ziti_conn = conn;
        uv_tcp_init(app->loop, &hc->tcp);
        uv_handle_set_data((uv_handle_t *) &hc->tcp, hc);

        uv_connect_t *cr = calloc(1, sizeof(uv_connect_t));
        if (uv_tcp_connect(cr, &hc->tcp, resolve.addrinfo->ai_addr, on_tcp_connect) != 0) {
            uv_freeaddrinfo(resolve.addrinfo);
            fprintf(stderr, "failed to connect to tcp:%s:%d\n", binding->host_cfg->hostname, binding->host_cfg->port);
            ziti_close(hc->ziti_conn, NULL);
            free(hc);
            free(cr);
            return;
        }

        uv_freeaddrinfo(resolve.addrinfo);
        ziti_conn_set_data(hc->ziti_conn, hc);
    } else {
        fprintf(stderr, "hosting error: %d(%s)\n", status, ziti_errorstr(status));
    }
}

void bind_service(struct app_ctx *app, ziti_context ztx, ziti_service *s, ziti_server_cfg_v1 *host_cfg) {
    host_binding *b = calloc(1, sizeof(host_binding));
    b->app = app;
    b->service_id = strdup(s->id);
    b->service_name = strdup(s->name);
    b->host_cfg = host_cfg;
    ziti_conn_init(ztx, &b->server, b);
    ziti_listen(b->server, b->service_name, listen_cb, on_client);

    model_map_set(&app->bindings, s->id, b);
}
