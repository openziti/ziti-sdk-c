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

// Controller responses that fail: what the callback of the caller gets, and that the request is released
// (LeakSanitizer reports a request that is not).
//
// A response that fails after its headers arrived ends in the failure branch of the body callback of
// ziti_ctrl.c. That branch called the callback of the caller with the request as its context (and crashed
// on the internal /version request, which has no caller callback) and never freed the request. A body that
// does not inflate is a deterministic way to get there: tlsuv reports it to the body callback when the
// message ends.

#include "fake_controller.h"

#include "catch2_includes.hpp"
#include "ziti_ctrl.h"

#include <ziti/errors.h>

using namespace fake_controller;

namespace {
    // claims deflate, but "{}" is not a zlib stream
    std::string body_that_does_not_inflate() {
        return http_response("200 OK", {{"Content-Type", "application/json"}, {"Content-Encoding", "deflate"}}, "{}");
    }

    // runs the loop until `done` is true (asked every 10 ms) or `timeout_ms` have passed
    void run_until(uv_loop_t *loop, const std::function<bool()> &done, unsigned timeout_ms) {
        struct state {
            const std::function<bool()> *done;
            uint64_t deadline;
        };
        uv_update_time(loop);
        state s{&done, uv_now(loop) + timeout_ms};

        uv_timer_t t;
        uv_timer_init(loop, &t);
        t.data = &s;
        uv_timer_start(&t, [](uv_timer_t *t) {
            auto s = (state *) t->data;
            if ((*s->done)() || uv_now(t->loop) >= s->deadline) {
                uv_stop(t->loop);
            }
        }, 10, 10);
        uv_run(loop, UV_RUN_DEFAULT);
        uv_close((uv_handle_t *) &t, nullptr);
        uv_run(loop, UV_RUN_NOWAIT);
    }

    struct ctrl_under_test {
        uv_loop_t *loop = test_loop();
        tls_context *tls = default_tls_context();
        ziti_controller ctrl{};

        explicit ctrl_under_test(const std::string &url) {
            model_list urls = {};
            model_list_append(&urls, (void *) url.c_str());
            REQUIRE(ziti_ctrl_init(loop, &ctrl, &urls, tls) == ZITI_OK);
            model_list_clear(&urls, nullptr);
        }

        ~ctrl_under_test() {
            ziti_ctrl_close(&ctrl);
            uv_run(loop, UV_RUN_DEFAULT);
            tls->free_ctx(tls);
        }
    };

    struct result {
        bool called = false;
        bool got_data = false;
        int err = ZITI_OK;
    };
}

TEST_CASE("controller response failing mid-body reaches the caller with its context", "[controller]") {
    FakeHttpServer server([](const std::string &, const std::string &path) {
        if (path == "/version") return json_response("200 OK", R"({"data":{"version":"v0.0.0"}})");
        if (path == "/network-jwts") return body_that_does_not_inflate();
        return not_found();
    });
    ctrl_under_test c(server.url());

    result res;
    ziti_ctrl_get_network_jwt(&c.ctrl, [](ziti_network_jwt_array arr, const ziti_error *err, void *ctx) {
        auto r = static_cast<result *>(ctx);
        r->called = true;
        r->got_data = arr != nullptr;
        r->err = err ? err->err : ZITI_OK;
        free_ziti_network_jwt_array(&arr);
    }, &res);
    run_until(c.loop, [&] { return res.called; }, 5000);

    REQUIRE(server.count("/network-jwts") == 1);
    CHECK(res.called);
    CHECK_FALSE(res.got_data);
    CHECK(res.err == ZITI_CONTROLLER_UNAVAILABLE);
}

TEST_CASE("version response failing mid-body fails the version request", "[controller]") {
    FakeHttpServer server([](const std::string &, const std::string &path) {
        if (path == "/version") return body_that_does_not_inflate();
        return not_found();
    });
    ctrl_under_test c(server.url());

    result res;
    ziti_ctrl_get_version(&c.ctrl, [](const ziti_ctrl_version *v, const ziti_error *err, void *ctx) {
        auto r = static_cast<result *>(ctx);
        r->called = true;
        r->got_data = v != nullptr;
        r->err = err ? err->err : ZITI_OK;
    }, &res);
    run_until(c.loop, [&] { return res.called; }, 5000);

    REQUIRE(server.count("/version") == 1);
    CHECK(res.called);
    CHECK_FALSE(res.got_data);
    CHECK(res.err == ZITI_CONTROLLER_UNAVAILABLE);
}

// An /enroll answered with a PEM certificate is a non-JSON response: an error, with no enrollment response
// for the callback (the enrollment code does not free one on errors). The SDK asks for JSON, which every
// controller sends it; a PEM path that got here gave the callback a response with the error and never
// freed the request.
TEST_CASE("failed PEM enrollment response gives the callback only the error", "[controller]") {
    FakeHttpServer server([](const std::string &, const std::string &path) {
        if (path == "/version") return json_response("200 OK", R"({"data":{"version":"v0.0.0"}})");
        if (path == "/enroll") {
            return http_response("200 OK", {{"Content-Type", "application/x-pem-file"}},
                                 "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n");
        }
        return not_found();
    });
    ctrl_under_test c(server.url());

    result res;
    ziti_ctrl_enroll(&c.ctrl, ziti_enrollment_method_ott, "token", "csr", nullptr,
                     [](ziti_enrollment_resp *er, const ziti_error *err, void *ctx) {
                         auto r = static_cast<result *>(ctx);
                         r->called = true;
                         r->got_data = er != nullptr;
                         r->err = err ? err->err : ZITI_OK;
                         free_ziti_enrollment_resp_ptr(er);
                     }, &res);
    run_until(c.loop, [&] { return res.called; }, 5000);

    REQUIRE(server.count("/enroll") == 1);
    CHECK(res.called);
    CHECK(res.err != ZITI_OK);
    CHECK_FALSE(res.got_data);
}
