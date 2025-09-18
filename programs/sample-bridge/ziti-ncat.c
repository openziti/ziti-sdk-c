// Copyright (c) 2022-2023.  NetFoundry Inc.
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
#include <stdio.h>
#include "ziti/ziti_log.h"

#ifdef _WIN32
#define STDIN GetStdHandle(STD_INPUT_HANDLE)
#define STDOUT GetStdHandle(STD_OUTPUT_HANDLE)
#else
#define STDIN 0
#define STDOUT 1
#endif

typedef struct {
    uv_loop_t *loop;
    const char *service;
} zcat_opts;

// on successful connect bridge Ziti connection to standard input and output
void on_connect(ziti_connection conn, int status) {
    if (status == ZITI_OK) {
        ziti_conn_bridge_fds(conn, STDIN, STDOUT, (void (*)(void *)) ziti_shutdown, ziti_conn_context(conn));
    } else {
        fprintf(stderr, "ziti connection failed: %s", ziti_errorstr(status));
        ziti_shutdown(ziti_conn_context(conn));
    }
}

void on_ziti_event(ziti_context ztx, const ziti_event_t *ev) {
    if (ev->type == ZitiContextEvent && ev->ctx.ctrl_status == ZITI_OK) {
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
            .event_cb = on_ziti_event,
            .events = ZitiContextEvent,
            .app_ctx = &opts
    };

    ziti_config cfg;
    ziti_context ztx = NULL;

    ziti_log_init(l, ZITI_LOG_DEFAULT_LEVEL, NULL);

#define check(op) do{ \
int err = (op); if (err != ZITI_OK) { \
fprintf(stderr, "ERROR: %s", ziti_errorstr(err)); \
exit(err);\
}}while(0)

    check(ziti_load_config(&cfg, argv[1]));
    check(ziti_context_init(&ztx, &cfg));
    check(ziti_context_set_options(ztx, &zopts));

    ziti_context_run(ztx, l);

    uv_run(l, UV_RUN_DEFAULT);
}

