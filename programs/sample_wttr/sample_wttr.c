// Copyright (c) 2023.  NetFoundry Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <uv.h>

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)

static size_t total;
static ziti_context ziti;

ssize_t on_data(ziti_connection c, const uint8_t *buf, ssize_t len) {
    if (len == ZITI_EOF) {

        printf("request completed: %s\n", ziti_errorstr(len));
        ziti_close(c, NULL);
        ziti_shutdown(ziti);

    }
    else if (len < 0) {
        fprintf(stderr, "unexpected error: %s\n", ziti_errorstr(len));
        ziti_close(c, NULL);
        ziti_shutdown(ziti);
    }
    else {
        total += len;
        printf("%.*s",  (int)len, buf);
    }
    return len;
}

static void on_write(ziti_connection conn, ssize_t status, void *ctx) {
    if (status < 0) {
        fprintf(stderr, "request failed to submit status[%zd]: %s\n", status, ziti_errorstr((int) status));
    }
    else {
        printf("request success: %zd bytes sent\n", status);
    }
}

void on_connect(ziti_connection conn, int status) {
    DIE(status);

    printf("sending HTTP request\n");

    uint8_t *req = "GET /Rochester HTTP/1.0\r\n"
                   "Accept: */*\r\n"
                   "Connection: close\r\n"
                   "Host: wttr.in\r\n"
                   "User-Agent: curl/7.59.0\r\n"
                   "\r\n";

    DIE(ziti_write(conn, req, strlen(req), on_write, NULL));
}

void on_ziti_init(ziti_context ztx, const ziti_event_t *ev) {
    DIE(ev->event.ctx.ctrl_status);
    ziti = ztx;

    ziti_connection conn;
    DIE(ziti_conn_init(ziti, &conn, NULL));
    DIE(ziti_dial(conn, "demo-weather", on_connect, on_data));
}

int main(int argc, char** argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);
#endif
    uv_loop_t *loop = uv_default_loop();
    ziti_config cfg;
    ziti_context ztx;
    ziti_options options = (ziti_options) {
            .event_cb = on_ziti_init,
            .events = ZitiContextEvent,
    };

    DIE(ziti_load_config(&cfg, argv[1]));
    DIE(ziti_context_init(&ztx, &cfg));
    DIE(ziti_context_set_options(ztx, &options));
    DIE(ziti_context_run(ztx, loop));

    // loop will finish after the request is complete and ziti_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n");

    ziti_shutdown(ziti);
}