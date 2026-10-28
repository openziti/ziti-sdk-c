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
#include "fake_controller.h"

#include <uv.h>
#include <ziti/ziti.h>
#include <ziti/ziti_src.h>

#include <vector>

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

    auto handler = [](ziti_context ztx, const ziti_event_t *ev) {
        auto t = (source_test *) ziti_app_ctx(ztx);
        switch (ev->type) {
            case ZitiContextEvent: {
                auto ctx_ev = ev->ctx;
                t->ztx = ztx;
                if (!t->done && ctx_ev.ctrl_status != ZITI_OK)
                    t->err = ctx_ev.ctrl_status;
                break;
            }
            case ZitiServiceEvent:
                if (t->done) break;

                ziti_src_init(t->loop, &t->src, nullptr, ztx);
                tlsuv_http_init_with_src(t->loop, &t->clt, "http://httpbin.ziti", &t->src);
                tlsuv_http_req(&t->clt, "GET", "/json", [](tlsuv_http_resp_t *resp, void *ctx) {
                    auto t = (source_test *) ctx;
                    t->code = resp->code;

                    resp->body_cb = [](tlsuv_http_req_t *req, char *body, ssize_t len) {
                        auto t = (source_test *) req->data;
                        if (len > 0)
                            t->body.append(body, len);
                        else if (len == UV_EOF) {
                            t->done = true;
                            ziti_shutdown(t->ztx);
                        } else {
                            t->err = (int) len;
                            t->done = true;
                            ziti_shutdown(t->ztx);
                        }
                    };
                }, t);
                break;
            default:
                FAIL("unexpected event");
        }
    };

    ziti_config zfg;
    ziti_context ztx;
    ziti_options zopts = {};
    zopts.app_ctx = &test;
    zopts.events = ZitiContextEvent | ZitiServiceEvent;
    zopts.event_cb = handler;

    REQUIRE(ziti_load_config(&zfg, cfg) == ZITI_OK);
    REQUIRE(ziti_context_init(&ztx, &zfg) == ZITI_OK);
    REQUIRE(ziti_context_set_options(ztx, &zopts) == ZITI_OK);
    REQUIRE(ziti_context_run(ztx, test.loop) == ZITI_OK);

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


extern "C" int ztx_test_open_conns(ziti_context ztx);  // ztx_test_helper.c

namespace {
    struct failed_dials {
        ziti_context ztx = nullptr;
        tlsuv_src_t src{};
        tlsuv_http_t clt{};
        int ticks = 0;
        int sent = 0;
        int failed = 0;
        std::vector<int> open_conns; // connections the app has not closed, after each failed request
    };

    // Sends three requests, one after the other, on an HTTP client whose source cannot connect:
    // `disable` has the context refuse the dial (ZITI_DISABLED), otherwise the context is not
    // authenticated and the dial fails through its conn cb.
    void fail_dials(failed_dials &t, bool disable) {
        using namespace fake_controller;
        FakeHttpServer ctrl([](const std::string &, const std::string &) { return not_found(); });

        auto done = [&](const context_run &run) {
            switch (++t.ticks) {
                case 1:
                    if (disable) {
                        ziti_set_enabled(run.ztx, false);
                    }
                    return false;
                case 4:
                    // the context has had its turns to stop
                    t.ztx = run.ztx;
                    ziti_src_init(test_loop(), &t.src, "svc", run.ztx);
                    tlsuv_http_init_with_src(test_loop(), &t.clt, "http://svc", &t.src);
                    break;
                default:
                    break;
            }

            if (t.ticks >= 4 && t.sent == t.failed && t.sent < 3) {
                t.sent++;
                tlsuv_http_req(&t.clt, "GET", "/", [](tlsuv_http_resp_t *resp, void *ctx) {
                    auto t = static_cast<failed_dials *>(ctx);
                    if (resp->code < 0) {
                        t->failed++;
                        t->open_conns.push_back(ztx_test_open_conns(t->ztx));
                    }
                }, &t);
            }

            if (t.failed == 3 || t.ticks > 40) {
                if (t.ticks >= 4) {
                    tlsuv_http_close(&t.clt, nullptr);
                }
                return true;
            }
            return false;
        };
        run_context(ctrl.url(), 10000, done);

        // the client never connected, so it has not released the source
        t.src.release(&t.src);
    }
}

// a source whose connect fails leaves tlsuv without links, so zl_close() never runs: ziti_src has to
// close the connection of a failed dial itself, or each retry of the client leaves one more open
TEST_CASE("ziti_src closes the connection of a dial that the context refused", "[ziti_src][GH-1187]") {
    failed_dials t;
    fail_dials(t, true);

    REQUIRE(t.failed == 3);
    CHECK(t.open_conns == std::vector<int>{0, 0, 0});
}

TEST_CASE("ziti_src closes the connection of a dial that failed", "[ziti_src][GH-1187]") {
    failed_dials t;
    fail_dials(t, false);

    REQUIRE(t.failed == 3);
    CHECK(t.open_conns == std::vector<int>{0, 0, 0});
}

// internal: the api session token, which the context has only while it is authenticated
extern "C" const char *ziti_get_api_session_token(ziti_context ztx);

namespace {
    struct timed_out_dial {
        tlsuv_src_t src{};
        tlsuv_http_t clt{};
        bool sent = false;
        bool timed_out = false;
        int ticks_after_answer = 0;
        int open_conns = -1;
    };
}

// tlsuv gives up on a connect that takes longer than its timeout and tells the source to cancel it: the
// dial that is still in flight must not be left open
TEST_CASE("ziti_src closes the connection of a dial that tlsuv timed out", "[ziti_src][GH-1187]") {
    using namespace fake_controller;
    FakeDialController ctrl(700);

    timed_out_dial t;
    auto done = [&](const context_run &run) {
        if (!t.sent) {
            if (ziti_get_api_session_token(run.ztx) == nullptr) return false;

            t.sent = true;
            ziti_src_init(test_loop(), &t.src, "svc", run.ztx);
            tlsuv_http_init_with_src(test_loop(), &t.clt, "http://svc", &t.src);
            tlsuv_http_connect_timeout(&t.clt, 200);
            tlsuv_http_req(&t.clt, "GET", "/", [](tlsuv_http_resp_t *resp, void *ctx) {
                if (resp->code < 0) {
                    static_cast<timed_out_dial *>(ctx)->timed_out = true;
                }
            }, &t);
            return false;
        }

        // the controller answers after tlsuv gave up: give the context turns to act on it
        if (ctrl.session_answered() && ++t.ticks_after_answer > 5) {
            t.open_conns = ztx_test_open_conns(run.ztx);
            tlsuv_http_close(&t.clt, nullptr);
            return true;
        }
        return false;
    };
    run_context(ctrl.url(), 10000, done);

    // the client never connected, so it has not released the source
    t.src.release(&t.src);

    CHECK(t.timed_out);
    CHECK(t.open_conns == 0);
}
