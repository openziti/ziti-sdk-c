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

#include <nf/ziti_link.h>
#include <nf/ziti_log.h>

// connect method for um_http custom source link
static int ziti_link_connect(um_http_t *c, um_http_custom_connect_cb cb);

// uv_link methods
static int zl_read_start(uv_link_t *l);
static int zl_write(uv_link_t *link, uv_link_t *source, const uv_buf_t bufs[],
                     unsigned int nbufs, uv_stream_t *send_handle, uv_link_write_cb cb, void *arg);
void zl_close(uv_link_t* link, uv_link_t* source, uv_link_close_cb cb);
const char* zl_strerror(uv_link_t* link, int err);

static void zl_conn_cb(nf_connection conn, int status);
static ssize_t zl_data_cb(nf_connection conn, uint8_t *data, ssize_t length);

struct zl_write_req_s {
    ziti_link_t *zl;
    uv_link_write_cb cb;
    void *arg;
};

static const uv_link_methods_t ziti_link_methods = {
        .read_start = zl_read_start,
        .write = zl_write,
        .close = zl_close,
        .strerror = zl_strerror,
        .alloc_cb_override = NULL,
        .read_cb_override = NULL
};

static void ziti_link_release();

int ziti_link_init(ziti_link_t *zl, um_http_t *clt, const char *svc, nf_context nfc) {
    zl->service = strdup(svc);
    zl->nfc = nfc;
    uv_link_init((uv_link_t *)zl, &ziti_link_methods);
    um_http_set_link_source(clt, (uv_link_t *)zl, ziti_link_connect, ziti_link_release);
    return 0; 
}

static void ziti_link_release(uv_link_t *l) {
    ziti_link_t *zl = (ziti_link_t *)l;
    free(zl->service);
}

static int ziti_link_connect(um_http_t *c, um_http_custom_connect_cb cb) {
    ziti_link_t *zl = (ziti_link_t *)c->custom_src;
    ZITI_LOG(TRACE, "service %s", zl->service);
    zl->clt = c;
    zl->connect_cb = cb;

    int status = NF_conn_init(zl->nfc, &zl->conn, zl);
    if (status != ZITI_OK) {
        return status;
    }
    return NF_dial(zl->conn, zl->service, zl_conn_cb, zl_data_cb);
}

static void zl_conn_cb(nf_connection conn, int status) {
    ziti_link_t *zl = (ziti_link_t *)NF_conn_data(conn);
    zl->connect_cb(zl->clt, status);
}

static ssize_t zl_data_cb(nf_connection conn, uint8_t *data, ssize_t length) {
    ziti_link_t *zl = (ziti_link_t *)NF_conn_data(conn);

    uv_buf_t read_buf;
    uv_link_propagate_alloc_cb((uv_link_t *)zl, length, &read_buf);
    memcpy(read_buf.base, data, length);
    uv_link_propagate_read_cb((uv_link_t *)zl, length, &read_buf);

    return length;
}

static int zl_read_start(uv_link_t *l) {
    return 0; 
}

static void zl_write_cb(nf_connection conn, ssize_t status, void *write_ctx) {
    struct zl_write_req_s *req = write_ctx;
    req->cb((uv_link_t *)req->zl, status, req->arg); 
    free(req);
}

static int zl_write(uv_link_t *link, uv_link_t *source, 
    const uv_buf_t bufs[], unsigned int nbufs, 
    uv_stream_t *send_handle, uv_link_write_cb cb, void *arg) {

    ziti_link_t *zl = (ziti_link_t *)link;
    struct zl_write_req_s *req = malloc(sizeof(struct zl_write_req_s));
    req->zl = zl;
    req->cb = cb;
    req->arg = arg;

    ZITI_LOG(TRACE, "%s, nbuf=%u, buf[0].len=%lu", zl->service, nbufs, bufs[0].len);
    return NF_write(zl->conn, (uint8_t *)bufs[0].base, bufs[0].len, zl_write_cb, req);
}

void zl_close(uv_link_t* link, uv_link_t* source, uv_link_close_cb link_close_cb) {
    ziti_link_t *zl = (ziti_link_t *)link;

    ZITI_LOG(TRACE, "%s", zl->service);
    NF_close(&zl->conn);
}

const char* zl_strerror(uv_link_t* link, int err) {
    return ziti_errorstr(err);
}