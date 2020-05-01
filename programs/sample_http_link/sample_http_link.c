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

#include <nf/ziti.h>
#include <nf/ziti_src.h>
#include <uv_mbed/uv_mbed.h>
#include <uv_mbed/um_http.h>
#include <string.h>

static uv_loop_t *loop;
static nf_context nf;
static um_http_t clt;
static um_http_src_t zs;

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)

void resp_cb(um_http_resp_t *resp, void *data) {
    if (resp->code < 0) {
        fprintf(stderr, "ERROR: %d(%s)", resp->code, uv_strerror(resp->code));
        exit(-1);
    }
    um_http_hdr *h;
    printf("Response (%d) >>>\nHeaders >>>\n", resp->code);
    for (h = resp->headers; h != NULL && h->name != NULL; h++) {
        printf("\t%s: %s\n", h->name, h->value);
    }
    printf("\n");
}

void body_cb(um_http_req_t *req, const char *body, ssize_t len) {
    if (len == UV_EOF) {
        printf("\n\n====================\nRequest completed\n");
        NF_shutdown(nf);
    } else if (len < 0) {
        fprintf(stderr, "error(%zd) %s", len, uv_strerror(len));
        exit(-1);
    } else {
        printf("%*.*s", (int) len, (int) len, body);
    }
}

void on_nf_init(nf_context _nf, int status, void* ctx) {
    DIE(status);

    nf = _nf;
    ziti_src_init(loop, &zs, "httpbin", nf);
    um_http_init_with_src(loop, &clt, "http://httpbin.org", (um_http_src_t *)&zs);

    um_http_req_t *r = um_http_req(&clt, "GET", "/json", resp_cb, NULL);
    r->resp.body_cb = body_cb;
}

int main(int argc, char** argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);
#endif
    
    loop = uv_default_loop();
    DIE(NF_init(argv[1], loop, on_nf_init, NULL));

    uv_mbed_set_debug(5, stdout);

    // loop will finish after the request is complete and NF_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n");
}