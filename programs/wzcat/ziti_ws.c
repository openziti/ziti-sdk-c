
// Copyright (c) 2020-2023.  NetFoundry Inc.
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

#include <uv.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_src.h>
#include <tlsuv/websocket.h>

#include <stdio.h>

#define NEWP(var,t) t* var = calloc(1, sizeof(t))

static struct app_ctx {
    const char *service;
    uv_loop_t *l;
} appCtx;

static void init_cb(ziti_context ztx, const ziti_event_t *ev);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <config> <service>", argv[0]);
        exit(1);
    }

    const char *config = argv[1];
    appCtx.service = argv[2];

    uv_loop_t *l = uv_loop_new();
    ziti_config cfg;
    ziti_context ztx = NULL;

    ziti_log_init(l, ZITI_LOG_DEFAULT_LEVEL, NULL);

#define check(op) do{ \
int err = (op); if (err != ZITI_OK) { \
fprintf(stderr, "ERROR: %s", ziti_errorstr(err)); \
exit(err);\
}}while(0)

    check(ziti_load_config(&cfg, config));
    check(ziti_context_init(&ztx, &cfg));
    check(ziti_context_set_options(ztx, &(ziti_options){
            .app_ctx = &appCtx,
            .event_cb = init_cb,
            .events = ZitiContextEvent,
    }));

    ziti_context_run(ztx, l);

    uv_run(l, UV_RUN_DEFAULT);

    return 0;
}
static void on_ws_write(uv_write_t *wr, int status) {
    printf("websocket write: %d\n", status);
    free(wr->data);
    free(wr);
}

static void input_read(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    tlsuv_websocket_t *ws = s->data;
    if (len > 0) {
        NEWP(wr, uv_write_t);
        uv_buf_t wb = uv_buf_init(buf->base, len);
        wr->data = buf->base;
        tlsuv_websocket_write(wr, ws, &wb, on_ws_write);
    } else {
        tlsuv_websocket_close(ws, NULL);
    }
}

static void alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static uv_pipe_t input;
static void on_connect(uv_connect_t *r, int status) {
    tlsuv_websocket_t *ws = r->data;
    if (status == 0) {
        printf("websocket connected\n");
        uv_pipe_init(ws->loop, &input, 0);
        input.data = ws;
        uv_pipe_open(&input, 0);
        uv_read_start((uv_stream_t *) &input, alloc, input_read);
    } else {

    }
}

static void on_ws_data(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    ziti_context ctx = s->data;
    if (len > 0) {
        printf("< %.*s", (int)len, buf->base);
    } else if (len < 0) {
        fprintf(stderr, "=========================\nwebsocket error[%zd]: %s\n", len, ziti_errorstr(len));
        tlsuv_websocket_close((tlsuv_websocket_t *) s, (uv_close_cb) free);
        uv_close((uv_handle_t *) &input, NULL);
        ziti_shutdown(ctx);
    }
}

static void init_cb(ziti_context ztx, const ziti_event_t *ev) {
    struct app_ctx *ctx = ziti_app_ctx(ztx);
    NEWP(src, tlsuv_src_t);
    ziti_src_init(ctx->l, src, ctx->service, ztx);

    NEWP(ws, tlsuv_websocket_t);
    ws->data = ztx;
    tlsuv_websocket_init_with_src(ctx->l, ws, src);

    NEWP(connr, uv_connect_t);
    connr->data = ws;
    tlsuv_websocket_connect(connr, ws, "wss://echo.websocket.org", on_connect, on_ws_data);
}