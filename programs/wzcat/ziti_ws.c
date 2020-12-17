
/*
Copyright (c) 2020 Netfoundry, Inc.

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
#include <ziti/ziti.h>
#include <uv_mbed/um_http_src_t.h>
#include <ziti/ziti_src.h>
#include <uv_mbed/um_websocket.h>
#include "../../inc_internal/utils.h"
#include "../../inc_internal/zt_internal.h"

static void init_cb(ziti_context ztx, const ziti_event_t *ev);

int main(int argc, char *argv[]) {
    const char *config = argv[1];
    const char *ws_service = argv[2];

    uv_loop_t *l = uv_loop_new();

    ziti_options opts = {
            .config = config,
            .router_keepalive = 15,
            .event_cb = init_cb,
            .events = ZitiContextEvent,
            .app_ctx = ws_service,
    };
    ziti_init_opts(&opts, l, ws_service);

    uv_run(l, UV_RUN_DEFAULT);

    return 0;
}
static void on_ws_write(uv_write_t *wr, int status) {
    printf("websocket write: %d\n", status);
    free(wr->data);
    free(wr);
}

static void input_read(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    um_websocket_t *ws = s->data;
    if (len > 0) {
        NEWP(wr, uv_write_t);
        uv_buf_t wb = uv_buf_init(buf->base, len);
        wr->data = buf->base;
        um_websocket_write(wr, ws, &wb, on_ws_write);
    } else {
        um_websocket_close(ws, NULL);
    }
}

static void alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static uv_pipe_t input;
static void on_connect(uv_connect_t *r, int status) {
    um_websocket_t *ws = r->data;
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
        um_websocket_close(s, (uv_close_cb) free);
        uv_close(&input, NULL);
        ziti_shutdown(ctx);
    }
}

static void init_cb(ziti_context ztx, const ziti_event_t *ev) {
    const char *service = ziti_app_ctx(ztx);
    NEWP(src, um_http_src_t);
    ziti_src_init(ztx->loop, src, service, ztx);

    NEWP(ws, um_websocket_t);
    ws->data = ztx;
    um_websocket_init_with_src(ztx->loop, ws, src);

    NEWP(connr, uv_connect_t);
    connr->data = ws;
    um_websocket_connect(connr, ws, "wss://echo.websocket.org", on_connect, on_ws_data);
}