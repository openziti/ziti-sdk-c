//
// Created by eugene on 2/25/19.
//

#include <nf/ziti.h>

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
static nf_context nf;

void on_data(nf_connection c, uint8_t *buf, int len) {
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

static void on_write(nf_connection conn, ssize_t status, void *ctx) {
    if (status < 0) {
        fprintf(stderr, "request failed to submit status[%zd]: %s\n", status, ziti_errorstr(status));
    }
    else {
        printf("request success: %zd bytes sent\n", status);
    }
}

void on_connect(nf_connection conn, int status) {
    DIE(status);

    printf("sending HTTP request\n");
    
    uint8_t *req = "GET /Rochester HTTP/1.0\r\n"
                   "Accept: */*\r\n"
                   "Connection: close\r\n"
                   "Host: wttr.in\r\n"
                   "User-Agent: curl/7.59.0\r\n"
                   "\r\n";

    DIE(NF_write(conn, req, strlen(req), on_write, NULL));
}

void on_nf_init(nf_context _nf, int status, void* ctx) {
    DIE(status);
    nf = _nf;

    nf_connection conn;
    DIE(NF_conn_init(nf, &conn, NULL));
    DIE(NF_dial(conn, "demo-weather", on_connect, on_data));
}

int main(int argc, char** argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);
#endif
    int res;
    uv_loop_t *loop = uv_default_loop();

    DIE(NF_init(argv[1], loop, on_nf_init, NULL));

    // loop will finish afger the request is complete and NF_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n");

    NF_free(&nf);
}