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

#include <ziti/ziti.h>
#include <ziti/ziti_src.h>
#include <tlsuv/tlsuv.h>
#include <tlsuv/http.h>
#include <string.h>

static uv_loop_t *loop;
static ziti_context ziti;
static tlsuv_http_t clt;
static tlsuv_src_t zs;

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)

void resp_cb(tlsuv_http_resp_t *resp, void *data) {
    if (resp->code < 0) {
        fprintf(stderr, "ERROR: %d(%s)", resp->code, uv_strerror(resp->code));
        exit(-1);
    }
    tlsuv_http_hdr *h;
    printf("Response (%d) >>>\nHeaders >>>\n", resp->code);
    LIST_FOREACH(h, &resp->headers, _next) {
        printf("\t%s: %s\n", h->name, h->value);
    }
    printf("\n");
}

void body_cb(tlsuv_http_req_t *req, char *body, ssize_t len) {
    if (len == UV_EOF) {
        printf("\n\n====================\nRequest completed\n");
        ziti_shutdown(ziti);
    } else if (len < 0) {
        fprintf(stderr, "error(%zd) %s", len, uv_strerror(len));
        exit(-1);
    } else {
        printf("%*.*s", (int) len, (int) len, body);
    }
}

void on_ziti_init(ziti_context ztx, const ziti_event_t *ev) {

    DIE(ev->event.ctx.ctrl_status);

    ziti = ztx;
    ziti_src_init(loop, &zs, "httpbin", ziti);
    tlsuv_http_init_with_src(loop, &clt, "http://httpbin.org", (tlsuv_src_t *) &zs);

    tlsuv_http_req_t *r = tlsuv_http_req(&clt, "GET", "/json", resp_cb, NULL);
    r->resp.body_cb = body_cb;
}

int main(int argc, char** argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);
#endif

    loop = uv_default_loop();

    ziti_config cfg;
    ziti_context ztx;
    DIE(ziti_load_config(&cfg, argv[1]));
    DIE(ziti_context_init(&ztx, &cfg));
    DIE(ziti_context_set_options(ztx, &(ziti_options){
            .event_cb = on_ziti_init,
            .events = ZitiContextEvent,
    }));
    DIE(ziti_context_run(ztx, loop));

    // loop will finish after the request is complete and ziti_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n");
}