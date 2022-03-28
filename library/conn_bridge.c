/*
Copyright (c) 2022 NetFoundry, Inc.

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

#include "zt_internal.h"
#include "utils.h"

struct ziti_bridge_s {
    ziti_connection conn;
    uv_stream_t *input;
    uv_stream_t *output;
    uv_close_cb close_cb;
    void *data;
};

static ssize_t on_ziti_data(ziti_connection conn, const uint8_t *data, ssize_t len);

static void bridge_alloc(uv_handle_t *h, size_t req, uv_buf_t *b);

static void on_input(uv_stream_t *s, ssize_t len, const uv_buf_t *b);


extern int ziti_conn_bridge(ziti_connection conn, uv_stream_t *stream, uv_close_cb on_close) {
    NEWP(br, struct ziti_bridge_s);
    br->conn = conn;
    br->input = stream;
    br->output = stream;
    br->close_cb = on_close;
    br->data = uv_handle_get_data((const uv_handle_t *) stream);

    uv_handle_set_data((uv_handle_t *) stream, br);
    ziti_conn_set_data(conn, br);

    ziti_conn_set_data_cb(conn, on_ziti_data);
    uv_read_start(br->input, bridge_alloc, on_input);

    return ZITI_OK;
}


extern int ziti_conn_bridge_fds(ziti_connection conn, uv_os_fd_t input, uv_os_fd_t output) {
    // TODO
    return ZITI_WTF;
}

static void on_ziti_close(ziti_connection conn) {
    struct ziti_bridge_s *br = ziti_conn_data(conn);

    uv_handle_set_data((uv_handle_t *) br->input, br->data);
    br->close_cb((uv_handle_t *) br->input);
    free(br);
}

static void close_bridge(struct ziti_bridge_s *br) {
    ziti_close(br->conn, on_ziti_close);
}

static void on_output(uv_write_t *wr, int status) {
    if (status != 0) {
        struct ziti_bridge_s *br = wr->handle->data;
        ZITI_LOG(WARN, "write failed: %d(%s)", status, uv_strerror(status));
        close_bridge(br);
    }
    free(wr->data);
    free(wr);
}

static void on_shutdown(uv_shutdown_t *sr, int status) {
    if (status != 0) {
        ZITI_LOG(WARN, "shutdown failed: %d(%s)", status, uv_strerror(status));
        close_bridge(sr->handle->data);
    }
    free(sr);
}

ssize_t on_ziti_data(ziti_connection conn, const uint8_t *data, ssize_t len) {
    struct ziti_bridge_s *br = ziti_conn_data(conn);
    if (len > 0) {
        NEWP(wr, uv_write_t);
        uv_buf_t b = uv_buf_init(malloc(len), len);
        memcpy(b.base, data, len);
        wr->data = b.base;
        uv_write(wr, br->output, &b, 1, on_output);
        return len;
    } else if (len == ZITI_EOF) {
        NEWP(sr, uv_shutdown_t);
        uv_shutdown(sr, br->output, on_shutdown);
    } else {
        close_bridge(br);
    }
    return 0;
}

void bridge_alloc(uv_handle_t *h, size_t req, uv_buf_t *b) {
    b->base = malloc(req);
    b->len = b->base ? req : 0;
}

static void on_ziti_write(ziti_connection conn, ssize_t status, void *ctx) {
    FREE(ctx);
    if (status < ZITI_OK) {
        close_bridge(ziti_conn_data(conn));
    }
}

void on_input(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    struct ziti_bridge_s *br = s->data;
    if (len == 0) {
        free(b->base);
    } else if (len > 0) {
        ziti_write(br->conn, b->base, len, on_ziti_write, b->base);
    } else if (len == UV_EOF) {
        free(b->base);
        ziti_close_write(br->conn);
    } else {
        free(b->base);
        close_bridge(br);
    }
}
