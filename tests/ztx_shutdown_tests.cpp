// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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
#include <ziti/errors.h>

namespace {
    // one loop for every case: creating and closing a loop per case trips libuv's fd assertion when
    // the whole suite runs in one process
    uv_loop_t *test_loop() {
        static uv_loop_t *loop = uv_loop_new();
        return loop;
    }

    struct shutdown_test {
        bool from_timer = false;
        int init_err = ZITI_OK;
        bool disabled = false;
        uv_timer_t shutdown_timer{};
        ziti_context ztx = nullptr;
    };

    void on_event(ziti_context ztx, const ziti_event_t *ev) {
        auto t = (shutdown_test *) ziti_app_ctx(ztx);
        if (ev->type != ZitiContextEvent) return;

        if (ev->ctx.ctrl_status == ZITI_DISABLED) {
            t->disabled = true;
            return;
        }
        if (ev->ctx.ctrl_status == ZITI_OK || t->init_err != ZITI_OK) return;

        t->init_err = ev->ctx.ctrl_status;
        if (t->from_timer) {
            t->ztx = ztx;
            uv_timer_init(test_loop(), &t->shutdown_timer);
            t->shutdown_timer.data = t;
            uv_timer_start(&t->shutdown_timer, [](uv_timer_t *timer) {
                auto t = (shutdown_test *) timer->data;
                ziti_shutdown(t->ztx);
                uv_close((uv_handle_t *) timer, nullptr);
            }, 10, 0);
        } else {
            ziti_shutdown(ztx);
        }
    }
}

TEST_CASE("ziti_shutdown completes after a TLS init failure", "[ztx]") {
    shutdown_test test;
    SECTION("shutdown from the event callback") {
        test.from_timer = false;
    }
    SECTION("shutdown from a later loop callback") {
        test.from_timer = true;
    }

    // 192.0.2.0/24 is the RFC 5737 documentation range: the controller is never contacted
    ziti_config cfg = {};
    cfg.controller_url = (char *) "https://192.0.2.1:1280";
    cfg.id.key = (char *) "pem:not a private key";

    ziti_context ztx = nullptr;
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);

    ziti_options opts = {};
    opts.app_ctx = &test;
    opts.events = ZitiContextEvent;
    opts.event_cb = on_event;
    REQUIRE(ziti_context_set_options(ztx, &opts) == ZITI_OK);

    uv_loop_t *loop = test_loop();
    REQUIRE(ziti_context_run(ztx, loop) == ZITI_OK);

    // unref'd: it ends a hung shutdown but does not keep a finished loop alive
    uv_timer_t guard;
    uv_timer_init(loop, &guard);
    uv_unref((uv_handle_t *) &guard);
    uv_timer_start(&guard, [](uv_timer_t *timer) { uv_stop(timer->loop); }, 5000, 0);

    uv_run(loop, UV_RUN_DEFAULT);

    bool timed_out = uv_is_active((uv_handle_t *) &guard) == 0;
    uv_close((uv_handle_t *) &guard, nullptr);
    uv_run(loop, UV_RUN_DEFAULT);

    CHECK(test.init_err == ZITI_INVALID_CONFIG);
    CHECK_FALSE(timed_out);
    CHECK(test.disabled);
}
