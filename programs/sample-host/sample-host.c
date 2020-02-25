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

#include <nf/errors.h>
#include <nf/ziti.h>
#include <string.h>

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)


static nf_context nf;
static int server = 0;
static const char *service;

static void on_client_write(nf_connection clt, ssize_t status, void *ctx) {
    free(ctx);
}

static void on_client_data(nf_connection clt, uint8_t *data, int len) {
    if (len > 0) {
        printf("client sent:\n%*.*s", len, len, data);
        char *reply = malloc(128);
        size_t l = sprintf(reply, "%d\n", len);
        NF_write(clt, reply, l, on_client_write, reply);
    }
    else if (len == ZITI_EOF) {
        printf("client disconnected\n");
    }
    else {
        fprintf(stderr, "error: %d(%s)", len, ziti_errorstr(len));
    }
}

static void on_client_connect(nf_connection clt, int status) {
    if (status == ZITI_OK) {
        uint8_t *msg = "Hello from byte counter!\n";
        NF_write(clt, msg, strlen(msg), on_client_write, NULL);
    }
}

static void on_client(nf_connection serv, nf_connection client, int status) {
    NF_accept(client, on_client_connect, on_client_data);
}

static void listen_cb(nf_connection serv, int status) {
    if (status == ZITI_OK) {
        printf("Byte Counter is ready! %d(%s)\n", status, ziti_errorstr(status));
    }
    else {
        printf("ERROR The Byte Counter could not be started: %d(%s)\n", status, ziti_errorstr(status));
        NF_close(&serv);
    }
}

static void on_write(nf_connection conn, ssize_t status, void* ctx) {
    if (status < 0) {
        fprintf(stderr, "request failed to submit status[%zd]: %s\n", status, ziti_errorstr((int)status));
    }
    else {
        printf("request success: %zd bytes sent\n", status);
    }
}

void on_connect(nf_connection conn, int status) {
    DIE(status);

    printf("sending HTTP request\n");

    uint8_t* req = "hello";

    DIE(NF_write(conn, req, strlen(req), on_write, NULL));
}

static size_t total;
void on_data(nf_connection c, uint8_t* buf, int len) {
    if (len == ZITI_EOF) {

        printf("request completed: %s\n", ziti_errorstr(len));
        NF_close(&c);
        NF_shutdown(nf);

    }
    else if (len < 0) {
        fprintf(stderr, "unexpected error: %s\n", ziti_errorstr(len));
        NF_close(&c);
        NF_shutdown(nf);
    }
    else {
        total += len;
        printf("%*.*s", len, len, buf);
    }

}

static void on_nf_init(nf_context nf_ctx, int status, void* init_ctx) {
    nf = nf_ctx;
    nf_connection conn;
    NF_conn_init(nf, &conn, NULL);
    if (server) {
        NF_listen(conn, service, listen_cb, on_client);
    }
    else {
        DIE(NF_dial(conn, service, on_connect, on_data));
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

    DIE(NF_init(argv[2], loop, on_nf_init, NULL));

    // loop will finish afger the request is complete and NF_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n"
           "uv loop is done\n");

    NF_shutdown(nf);
}

