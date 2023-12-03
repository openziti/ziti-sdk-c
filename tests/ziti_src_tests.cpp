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

#include "catch2_includes.hpp"

#include <uv.h>
#include <ziti/ziti.h>
#include <ziti/ziti_src.h>

struct source_test {
    source_test(): err(0), loop(nullptr), done(false), code(-1) {}
    int err;
    uv_loop_t *loop;
    ziti_context ztx;
    tlsuv_src_t src;
    tlsuv_http_t clt;
    int code;
    std::string body;
    bool done;
};

TEST_CASE("httpbin.ziti:ziti_src", "[integ]") {
    auto cfg = getenv("ZITI_TEST_IDENTITY");

    if (cfg == nullptr) {
        WARN("ZITI_TEST_IDENTITY is not set");
        return;
    }

    source_test test;
    test.loop = uv_loop_new();

    int rc = ziti_init(cfg, test.loop, [](ziti_context ztx, const ziti_event_t *ev){
        auto t = (source_test*)ziti_app_ctx(ztx);
        switch (ev->type) {
            case ZitiContextEvent: {
                auto ctx_ev = ev->event.ctx;
                t->ztx = ztx;
                if (!t->done && ctx_ev.ctrl_status != ZITI_OK)
                    t->err = ctx_ev.ctrl_status;
                break;
            }
            case ZitiServiceEvent:
                if (t->done) break;

                ziti_src_init(t->loop, &t->src, nullptr, ztx);
                tlsuv_http_init_with_src(t->loop, &t->clt, "http://httpbin.ziti", &t->src);
                tlsuv_http_req(&t->clt, "GET", "/json", [](tlsuv_http_resp_t *resp, void *ctx){
                    auto t = (source_test*)ctx;
                    t->code = resp->code;

                    resp->body_cb = [](tlsuv_http_req_t *req, char *body, ssize_t len){
                        auto t = (source_test*)req->data;
                        if (len > 0)
                            t->body.append(body, len);
                        else if (len == UV_EOF) {
                            t->done = true;
                            ziti_shutdown(t->ztx);
                        } else {
                            t->err = (int)len;
                            t->done = true;
                            ziti_shutdown(t->ztx);
                        }
                    };
                    }, t);
                break;
            default:
                FAIL("unexpected event");
        }
    }, ZitiContextEvent|ZitiServiceEvent, &test);
    REQUIRE(rc == 0);

    uv_timer_t t = {0};
    uv_timer_init(test.loop, &t);
    t.data = &test;
    uv_unref((uv_handle_t *)&t);
    uv_timer_start(&t, [](uv_timer_t *timer){
                       uv_print_active_handles(timer->loop, stderr);
                       uv_stop(timer->loop);
                   },
                   20000, 0);

    uv_run(test.loop, UV_RUN_DEFAULT);

    printf("%s", test.body.c_str());
    CHECK_THAT(test.body, Catch::Matchers::ContainsSubstring(R"("title": "Wake up to WonderWidgets!")"));
    CHECK(test.err == 0);
}
