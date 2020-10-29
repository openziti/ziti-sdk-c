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

#include <ziti/errors.h>
#include <ziti/ziti.h>
#include <string.h>

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)


static ziti_context ziti;
static int server = 0;
static const char *service;

static void on_client_write(ziti_connection clt, ssize_t status, void *ctx) {
    free(ctx);
}

static ssize_t on_client_data(ziti_connection clt, uint8_t *data, ssize_t len) {
    if (len > 0) {
        printf("client sent:\n%.*s", (int) len, data);
        char *reply = malloc(128);
        size_t l = sprintf(reply, "%zd\n", len);
        ziti_write(clt, reply, l, on_client_write, reply);
    }
    else if (len == ZITI_EOF) {
        printf("client disconnected\n");
    }
    else {
        fprintf(stderr, "error: %zd(%s)", len, ziti_errorstr(len));
    }
    return len;
}

static void on_client_connect(ziti_connection clt, int status) {
    if (status == ZITI_OK) {
        uint8_t *msg = "Hello from byte counter!\n";
        ziti_write(clt, msg, strlen(msg), on_client_write, NULL);
    }
}

static void on_client(ziti_connection serv, ziti_connection client, int status) {
    char *app_data = ziti_conn_data(client);
    if (app_data != NULL) {
        fprintf(stderr, "got app data '%s'!\n", app_data);
    }
    ziti_accept(client, on_client_connect, on_client_data);
}

static void listen_cb(ziti_connection serv, int status) {
    if (status == ZITI_OK) {
        printf("Byte Counter is ready! %d(%s)\n", status, ziti_errorstr(status));
    }
    else {
        printf("ERROR The Byte Counter could not be started: %d(%s)\n", status, ziti_errorstr(status));
        ziti_close(&serv);
    }
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

    uint8_t *req = "hello";

    DIE(ziti_write(conn, req, strlen(req), on_write, NULL));
}

static size_t total;

ssize_t on_data(ziti_connection c, uint8_t *buf, ssize_t len) {
    if (len == ZITI_EOF) {

        printf("request completed: %s\n", ziti_errorstr(len));
        ziti_close(&c);
        ziti_shutdown(ziti);

    }
    else if (len < 0) {
        fprintf(stderr, "unexpected error: %s\n", ziti_errorstr(len));
        ziti_close(&c);
        ziti_shutdown(ziti);
    }
    else {
        total += len;
        printf("%.*s", (int)len, buf);
    }
    return len;
}

static void on_ziti_init(ziti_context ztx, int status, void *ctx) {
    ziti = ztx;
    ziti_connection conn;
    ziti_conn_init(ziti, &conn, NULL);
    if (server) {
        ziti_listen_opts listen_opts = {
//                .identity = "itsamee",
//                .bind_using_edge_identity = true,
//                .terminator_precedence = PRECEDENCE_REQUIRED,
//                .terminator_cost = 10,
        };
        ziti_listen_with_options(conn, service, &listen_opts, listen_cb, on_client);
    }
    else {
        char *app_data = "here is some data from the client to get you started";
        ziti_dial_opts dial_opts = {
//                .identity = "itsamee",
//                .app_data = app_data,
//                .app_data_sz = strlen(app_data) + 1,
        };
        DIE(ziti_dial_with_options(conn, service, &dial_opts, on_connect, on_data));
    }
}

int main(int argc, char **argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);

#endif
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <client|server> <config-file> <service-name>", argv[0]);
        exit(1);
    }
    uv_loop_t *loop = uv_default_loop();

    if (strcmp("server", argv[1])) {
        printf("Running as client\n");
    }
    else {
        printf("Running as server\n");
        server = 1;
    }

    service = argv[3];

    DIE(ziti_init(argv[2], loop, on_ziti_init, NULL));

    // loop will finish after the request is complete and ziti_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n"
           "uv loop is done\n");

    ziti_shutdown(ziti);
}

