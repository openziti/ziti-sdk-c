// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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

#include <ziti/errors.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include <stdlib.h>
#include <string.h>

static const char *service;

static void on_client_write(ziti_connection clt, ssize_t status, void *ctx) {
    free(ctx);
}

static ssize_t on_client_data(ziti_connection clt, const uint8_t *data, ssize_t len) {
    if (len > 0) {
        uint8_t *copy = malloc(len);
        memcpy(copy, data, len);
        ziti_write(clt, copy, len, on_client_write, copy);
    } else if (len == ZITI_EOF) {
        ziti_close_write(clt);
    } else {
        ZITI_LOG(ERROR, "client data error: %zd(%s)", len, ziti_errorstr(len));
        ziti_close(clt, NULL);
    }
    return len;
}

static void on_client_connect(ziti_connection clt, int status) {
    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "client accept failed: %d(%s)", status, ziti_errorstr(status));
        ziti_close(clt, NULL);
    }
}

static void on_client(ziti_connection serv, ziti_connection client, int status, const ziti_client_ctx *clt_ctx) {
    if (status == ZITI_OK) {
        ziti_accept(client, on_client_connect, on_client_data);
    } else if (status == ZITI_DISABLED) {
        ziti_close(serv, NULL);
    } else {
        ZITI_LOG(ERROR, "failed to accept client: %s(%d)", ziti_errorstr(status), status);
    }
}

static void listen_cb(ziti_connection serv, int status) {
    if (status == ZITI_OK) {
        ZITI_LOG(INFO, "echo server is ready");
        printf("ECHO_SERVER_READY\n");
        fflush(stdout);
    } else {
        ZITI_LOG(ERROR, "listen failed: %d(%s)", status, ziti_errorstr(status));
        exit(1);
    }
}

static void on_ziti_init(ziti_context ztx, const ziti_event_t *ev) {
    if (ev->type != ZitiContextEvent) return;
    if (ev->ctx.ctrl_status == ZITI_PARTIALLY_AUTHENTICATED) return;

    if (ev->ctx.ctrl_status != ZITI_OK) {
        ZITI_LOG(ERROR, "ziti context error: %d(%s)",
                ev->ctx.ctrl_status, ziti_errorstr(ev->ctx.ctrl_status));
        exit(1);
    }

    ziti_connection conn;
    ziti_conn_init(ztx, &conn, NULL);
    ziti_listen(conn, service, listen_cb, on_client);
}

static void input_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    static char input_buf[1024];
    buf->base = input_buf;
    buf->len = sizeof(input_buf);
}

static void input_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        if (strncmp(buf->base, "stop", nread) == 0) {
            ZITI_LOG(INFO, "exiting on user request");
            ziti_context ztx = stream->data;
            ziti_shutdown(ztx);
        } else {
            ZITI_LOG(INFO, "got input: %.*s", (int)nread, buf->base);
        }
        return;
    }

    ZITI_LOG(ERROR, "input error: %zd(%s)", nread, ziti_errorstr(nread));
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <config-file> <service-name>\n", argv[0]);
        return 1;
    }

    uv_loop_t *loop = uv_default_loop();
    ziti_log_init(loop, ZITI_LOG_DEFAULT_LEVEL, NULL);
    service = argv[2];

    ziti_config cfg;
    ziti_context ztx;

    int rc = ziti_load_config(&cfg, argv[1]);
    if (rc != ZITI_OK) {
        ZITI_LOG(ERROR, "failed to load config: %s", ziti_errorstr(rc));
        return rc;
    }

    rc = ziti_context_init(&ztx, &cfg);
    if (rc != ZITI_OK) {
        ZITI_LOG(ERROR, "failed to init context: %s", ziti_errorstr(rc));
        return rc;
    }

    uv_pipe_t input = { .data = ztx, };
    uv_pipe_init(loop, &input, 0);
    uv_unref((uv_handle_t*)&input);
    if (uv_pipe_open(&input, stdin->_file) == 0) {
        uv_read_start((uv_stream_t*)&input, input_alloc, input_read);
    } else {
        ZITI_LOG(WARN, "failed to open stdin for reading");
    }

    rc = ziti_context_set_options(ztx, &(ziti_options){
        .event_cb = on_ziti_init,
        .events = ZitiContextEvent,
    });
    if (rc != ZITI_OK) {
        ZITI_LOG(ERROR, "failed to set options: %s", ziti_errorstr(rc));
        return rc;
    }

    rc = ziti_context_run(ztx, loop);
    if (rc != ZITI_OK) {
        ZITI_LOG(ERROR, "failed to run context: %s", ziti_errorstr(rc));
        return rc;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    ziti_shutdown(ztx);
    return 0;
}
