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

// GH-1185: an app that is in the background has no network (the process keeps running). The login of the OIDC
// client fails with a transport error, not with an answer of the controller, and the SDK reported that as an
// authentication failure once its window for retries was over; nothing authenticated the context again when the
// network came back.
//
// These tests drive a real ziti_context against a fake controller whose authorization endpoint (the first leg of a
// login) is on a port that refuses connections until the test opens it: the network is down, the rest is known.

#include "fake_controller.h"

#include "catch2_includes.hpp"

using namespace fake_controller;

extern "C" int ztx_test_oidc_retry_window(ziti_context ztx, uint64_t window_ms);  // ztx_test_helper.c
extern "C" int ztx_test_oidc_cancel_retry(ziti_context ztx);                      // ztx_test_helper.c

namespace {
    bool ends_with(const std::string &s, const std::string &suffix) {
        return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    class FakeOidcController {
    public:
        // declared first: the OIDC configuration names its address
        FakeOidcController()
                : authorize_([](const std::string &, const std::string &) {
                    // the test stops at the first sign of a login
                    return json_response("503 Service Unavailable", "{}");
                }, false),
                  oidc_([this](const std::string &, const std::string &path) { return oidc(path); }),
                  ctrl_([this](const std::string &, const std::string &path) { return ctrl(path); }) {}

        std::string url() const { return ctrl_.url(); }

        // from here on the first leg of a login gets an answer
        void network_is_back() { authorize_.listen(); }

        // a login got as far as the authorization endpoint
        int login_attempts() const { return authorize_.count("/authorize"); }

    private:
        std::string ctrl(const std::string &path) {
            if (ends_with(path, "/version")) {
                return json_response(
                        "200 OK",
                        R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                        R"("runtimeVersion":"fake","capabilities":["OIDC_AUTH"],"buildFlags":[],"apiVersions":{)"
                        R"("edge":{"v1":{"path":"/edge/client/v1"}},)"
                        R"("edge-oidc":{"v1":{"path":"/oidc","apiBaseUrls":[")" + oidc_.url() + R"("]}}}},"meta":{}})");
            }
            return not_found();
        }

        std::string oidc(const std::string &path) {
            if (ends_with(path, "/.well-known/openid-configuration")) {
                return json_response(
                        "200 OK",
                        R"({"authorization_endpoint":")" + authorize_.url() + R"(/oidc/authorize",)"
                        R"("token_endpoint":")" + authorize_.url() + R"(/oidc/token"})");
            }
            return not_found();
        }

        FakeHttpServer authorize_;
        FakeHttpServer oidc_;
        FakeHttpServer ctrl_;
    };
}

// The network is down for longer than the window of the OIDC client for retries, and comes back. The identity is the
// same, the controller is the same: the context authenticates again without the app having to ask, and the app is not
// told that the authentication failed.
TEST_CASE("oidc-login-survives-an-outage-of-the-network", "[reauth][GH-1185]") {
    FakeOidcController ctrl;

    const uint64_t window_ms = 500;
    const uint64_t outage_ms = 1500; // the window is over by then
    uint64_t started = 0;
    bool back = false;
    auto done = [&](const context_run &run) {
        uint64_t now = uv_now(test_loop());
        if (started == 0) started = now;
        ztx_test_oidc_retry_window(run.ztx, window_ms);

        if (!back && now - started >= outage_ms) {
            ctrl.network_is_back();
            back = true;
        }
        return ctrl.login_attempts() >= 1;
    };
    context_run run = run_context(ctrl.url(), 30000, done);

    CHECK(run.auth_failed == 0);
    CHECK(ctrl.login_attempts() >= 1);
}

// The SDK waits for the end of a backoff, the network is back, and the device wakes up: the app says so, and the
// context does not wait for the backoff.
TEST_CASE("oidc-login-does-not-wait-for-the-backoff-when-the-device-wakes-up", "[reauth][GH-1185]") {
    FakeOidcController ctrl;

    const uint64_t outage_ms = 1500;
    uint64_t started = 0;
    bool back = false;
    auto done = [&](const context_run &run) {
        uint64_t now = uv_now(test_loop());
        if (started == 0) started = now;

        if (!back && now - started < outage_ms) {
            // the backoff is longer than the test
            ztx_test_oidc_cancel_retry(run.ztx);
            return false;
        }
        if (!back) {
            back = true;
            ctrl.network_is_back();
            ziti_endpoint_state_change(run.ztx, true, false);
        }
        return ctrl.login_attempts() >= 1;
    };
    run_context(ctrl.url(), 10000, done);

    CHECK(ctrl.login_attempts() >= 1);
}
