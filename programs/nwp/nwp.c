
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

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)

static ziti_context ziti;
static ziti_connection conn;
static uv_tty_t tty;

static void init_cb(ziti_context ztx, int status, void *init_ctx);

static void process_cb(ziti_context ztx, char *id, char *path, ziti_pr_process_cb response_cb);

static void os_cb(ziti_context ztx, char *id, ziti_pr_os_cb response_cb);

static void domain_cb(ziti_context ztx, char *id, ziti_pr_domain_cb response_cb);

static void mac_cb(ziti_context ztx, char *id, ziti_pr_mac_cb response_cb);

/* nwp is "Netcat With Posture". It provides simple static data to
 * posture check callbacks.
 */
int main(int argc, char *argv[]) {
#if _WIN32
    SetConsoleOutputCP(65001);
#endif
    const char *config = argv[1];
    char *service_name = argv[2];

    uv_loop_t *l = uv_loop_new();

    ziti_options opts = {
            .config = config,
            .router_keepalive = 15,
            .init_cb = init_cb,
            .pq_process_cb = process_cb,
            .pq_os_cb = os_cb,
            .pq_mac_cb = mac_cb,
            .pq_domain_cb = domain_cb,
    };
    ziti_init_opts(&opts, l, service_name);

    uv_run(l, UV_RUN_DEFAULT);

    return 0;
}

ssize_t on_data(ziti_connection c, uint8_t *buf, ssize_t len) {
    if (len == ZITI_EOF) {

        printf("request completed: %s\n", ziti_errorstr(len));
        ziti_close(&c);
        ziti_shutdown(ziti);

    } else if (len < 0) {
        fprintf(stderr, "unexpected error: %s\n", ziti_errorstr(len));
        ziti_close(&c);
        ziti_shutdown(ziti);
    } else {
        printf("%.*s\n", (int) len, buf);
    }
    return len;
}

static void on_write(ziti_connection conn, ssize_t status, void *ctx) {
    if (status < 0) {
        fprintf(stderr, "failed to send[%zd]: %s\n", status, ziti_errorstr((int) status));
    }
}

static void on_ziti_write(ziti_connection conn, ssize_t status, void *write_ctx) {
    DIE(status);
}

static void tty_read_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void tty_read_cb(uv_stream_t *stream,
                        ssize_t nread,
                        const uv_buf_t *buf) {

    if(nread < 0){
        uv_close((uv_handle_t*)stream, NULL);
        return;
    }

    uint8_t data = (uint8_t)atoi(buf->base);
    DIE(ziti_write(conn, &data, nread, on_ziti_write, NULL));
    free(buf->base);
}

void on_connect(ziti_connection conn, int status) {
    DIE(status);



    uv_pipe_t stdin_pipe;
    uv_pipe_init(uv_default_loop(), (uv_pipe_t *)&stdin_pipe, 0);
    uv_pipe_open((uv_pipe_t *)&stdin_pipe, 0);
    uv_read_start((uv_stream_t *)&stdin_pipe, tty_read_alloc_cb, tty_read_cb);
}

static void init_cb(ziti_context ztx, int status, void *init_ctx) {
    DIE(status);
    ziti = ztx;

    DIE(ziti_conn_init(ziti, &conn, NULL));
    DIE(ziti_dial(conn, init_ctx, on_connect, on_data));


}


static void process_cb(ziti_context ztx, char *id, char *path, ziti_pr_process_cb response_cb) {
    char sha512[129] = "B4F3228217A2BAE3F21F6B6DF3750D0723A5C3973DB9AAD360A8F25BC31E3676D38180CF0ABC89D7FCA7A26E1919A1E52739ED3116011ACC7E96630313DA56B8";
    response_cb(ztx, id, path, true, sha512, NULL, 0);
}

static void os_cb(ziti_context ztx, char *id, ziti_pr_os_cb response_cb) {
    response_cb(ztx, id, "Windows", "10", "1409");
}

static void domain_cb(ziti_context ztx, char *id, ziti_pr_domain_cb response_cb) {
    response_cb(ztx, id, "mycompany.com");
}

static void mac_cb(ziti_context ztx, char *id, ziti_pr_mac_cb response_cb) {
    char *address = "62-69-B3-72-7D-05";
    char **mac_addresses = malloc(sizeof(char *));
    mac_addresses[0] = address;

    response_cb(ztx, id, mac_addresses, 1);

    free(mac_addresses);
}