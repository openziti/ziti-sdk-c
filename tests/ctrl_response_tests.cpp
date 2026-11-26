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

// Controller requests against a fake controller: the body that is sent, and for responses that fail, what
// the callback of the caller gets and that the request is released (LeakSanitizer reports one that is not).
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
#include <json-c/json.h>

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

// A controller that answers from another address says so, and the endpoint it was reached at moves there.
TEST_CASE("controller-supplied-address-replaces-the-endpoint-it-came-from", "[controller]") {
    const std::string moved_to = "http://203.0.113.9:1280";
    FakeHttpServer server([&](const std::string &, const std::string &path) {
        if (path == "/version") {
            return http_response("200 OK", {{"Content-Type", "application/json"}, {"ziti-ctrl-address", moved_to}},
                                 R"({"data":{"version":"v0.0.0"}})");
        }
        return not_found();
    });
    ctrl_under_test c(server.url());
    const std::string started_at = server.url();

    run_until(c.loop, [&] { return moved_to == cstr_str(&c.ctrl.url); }, 5000);

    CHECK(moved_to == cstr_str(&c.ctrl.url));
    CHECK(model_map_size(&c.ctrl.endpoints) == 1);
    CHECK(model_map_get(&c.ctrl.endpoints, moved_to.c_str()) != nullptr);
    CHECK(model_map_get(&c.ctrl.endpoints, started_at.c_str()) == nullptr);
}

// The address a controller supplies is "https://" and its configured host:port, so it always has a port, and
// the endpoint is known by its origin: the same origin in another spelling is no move. A redirect rewrites the
// identity file, and one per start would rewrite it every time.
TEST_CASE("controller-supplied-address-of-the-same-origin-is-no-redirect", "[controller]") {
    std::string advertised;
    FakeHttpServer server([&](const std::string &, const std::string &path) {
        if (path == "/version") {
            return http_response("200 OK", {{"Content-Type", "application/json"}, {"ziti-ctrl-address", advertised}},
                                 R"({"data":{"version":"v0.0.0"}})");
        }
        return not_found();
    });
    const std::string started_at = server.url();
    advertised = "HTTP" + started_at.substr(4); // the scheme is not case sensitive
    ctrl_under_test c(started_at);

    int redirects = 0;
    ziti_ctrl_set_callbacks(&c.ctrl, &redirects, [](const char *, void *ctx) { ++*static_cast<int *>(ctx); }, nullptr);

    run_until(c.loop, [&] { return c.ctrl.version.version != nullptr; }, 5000);

    REQUIRE(c.ctrl.version.version != nullptr);
    CHECK(redirects == 0);
    CHECK(started_at == cstr_str(&c.ctrl.url));
    CHECK(model_map_size(&c.ctrl.endpoints) == 1);
}

// The controller names an address the list of controllers already holds, for example after it moved from an IP
// to a host name: the listed controller is the endpoint, with its id and its state, not a new one that replaces
// it. The detail that was replaced was leaked.
TEST_CASE("controller-supplied-address-of-a-listed-controller-keeps-the-listed-one", "[controller]") {
    const std::string moved_to = "http://203.0.113.9:1280";
    FakeHttpServer server([&](const std::string &, const std::string &path) {
        if (path == "/version") {
            return http_response("200 OK", {{"Content-Type", "application/json"}, {"ziti-ctrl-address", moved_to}},
                                 R"({"data":{"version":"v0.0.0"}})");
        }
        return not_found();
    });
    ctrl_under_test c(server.url());

    // the list names this controller by the address the context uses and, once more, by the address it moves to
    const std::vector<std::pair<std::string, std::string>> listed = {
            {"here", server.url() + "/edge/client/v1"},
            {"listed", moved_to + "/edge/client/v1"},
    };
    auto arr = (ziti_controller_detail_array) calloc(listed.size() + 1, sizeof(ziti_controller_detail *));
    for (size_t i = 0; i < listed.size(); i++) {
        ziti_controller_detail *d = alloc_ziti_controller_detail();
        d->id = strdup(listed[i].first.c_str());
        d->name = strdup(d->id);
        d->is_online = true;

        api_address *addr = alloc_api_address();
        addr->version = strdup("v1");
        addr->url = strdup(listed[i].second.c_str());
        model_list_append(&d->apis.edge, addr);
        arr[i] = d;
    }
    ziti_ctrl_set_endpoints(&c.ctrl, arr);
    REQUIRE(model_map_size(&c.ctrl.endpoints) == 2);

    run_until(c.loop, [&] { return moved_to == cstr_str(&c.ctrl.url); }, 5000);

    CHECK(moved_to == cstr_str(&c.ctrl.url));
    CHECK(model_map_size(&c.ctrl.endpoints) == 1);
    auto kept = static_cast<ziti_controller_detail *>(model_map_get(&c.ctrl.endpoints, moved_to.c_str()));
    REQUIRE(kept != nullptr);
    CHECK(std::string("listed") == kept->id);
    CHECK(kept->is_online);
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

// The body of POST /sessions was formatted into a 128-byte buffer and sent with the untruncated length, so
// a service id (it comes from the controller) longer than 95 characters sent the heap past that buffer.
// The id was not escaped either.
TEST_CASE("session request carries a long service id intact", "[controller]") {
    const std::string service_id = std::string(200, 'x') + R"("quoted\)";
    FakeHttpServer server([](const std::string &, const std::string &path) {
        if (path == "/version") return json_response("200 OK", R"({"data":{"version":"v0.0.0"}})");
        return not_found();
    });
    ctrl_under_test c(server.url());
    ziti_ctrl_set_token(&c.ctrl, "token");

    result res;
    ziti_ctrl_create_session(&c.ctrl, service_id.c_str(), ziti_session_types.Dial,
                             [](ziti_session *s, const ziti_error *, void *ctx) {
                                 auto r = static_cast<result *>(ctx);
                                 r->called = true;
                                 if (s) free_ziti_session_ptr(s);
                             }, &res);
    run_until(c.loop, [&] { return res.called; }, 5000);

    REQUIRE(server.count("/sessions") == 1);
    const std::string body = server.last_body("/sessions");
    CHECK(body.find('\0') == std::string::npos);

    std::unique_ptr<json_object, decltype(&json_object_put)> json(json_tokener_parse(body.c_str()), json_object_put);
    REQUIRE(json != nullptr);
    CHECK(json_object_get_string(json_object_object_get(json.get(), "serviceId")) == service_id);
    CHECK(json_object_get_string(json_object_object_get(json.get(), "type")) == std::string("Dial"));
}
