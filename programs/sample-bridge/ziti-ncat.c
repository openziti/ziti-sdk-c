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


#include <ziti/ziti.h>
#include <stdio.h>

#define STDIN 0
#define STDOUT 1

typedef struct {
    uv_loop_t *loop;
    const char *service;
} zcat_opts;

// on successful connect bridge Ziti connection to standard input and output
void on_connect(ziti_connection conn, int status) {
    if (status == ZITI_OK) {
        ziti_conn_bridge_fds(conn, STDIN, STDOUT, ziti_shutdown, ziti_conn_context(conn));
    } else {
        fprintf(stderr, "ziti connection failed: %s", ziti_errorstr(status));
        ziti_shutdown(ziti_conn_context(conn));
    }
}

void on_ziti_event(ziti_context ztx, const ziti_event_t *ev) {
    if (ev->type == ZitiContextEvent && ev->event.ctx.ctrl_status == ZITI_OK) {
        zcat_opts *opts = ziti_app_ctx(ztx);
        ziti_connection zconn;
        ziti_conn_init(ztx, &zconn, NULL);
        ziti_dial(zconn, opts->service, on_connect, NULL);
    }
}

int main(int argc, char *argv[]) {
    uv_loop_t *l = uv_loop_new();
    zcat_opts opts = {
            .loop = l,
            .service = argv[2]
    };
    ziti_options zopts = {
            .config = argv[1],
            .event_cb = on_ziti_event,
            .events = ZitiContextEvent,
            .app_ctx = &opts
    };

    ziti_init_opts(&zopts, l);

    uv_run(l, UV_RUN_DEFAULT);
}

