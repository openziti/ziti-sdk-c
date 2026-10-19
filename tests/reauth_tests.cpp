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

// GH-1157: once the context has the version of the controller, ziti_ctrl_get_version() answers from
// its cache, in the same call. When the OIDC endpoint then refuses connections (or its name does not
// resolve), the auth provider is "not available", and ztx_set_impossible_to_authenticate() re-entered
// authentication on the spot: version, ext-jwt-signers, OIDC configuration, failure, and again, with
// no timer anywhere in the cycle, for as fast as the failures came back.
//
// These tests drive a real ziti_context against a fake controller that advertises OIDC at an address
// of its own, which refuses connections until the test opens it. Every pass of the cycle asks the
// controller for its ext-jwt-signers, so those requests are the count of passes.

#include "fake_controller.h"

#include "catch2_includes.hpp"

using namespace fake_controller;

// internal (zt_internal.h cannot be included from C++)
extern "C" void ziti_services_refresh(ziti_context ztx, bool now);
extern "C" int ztx_test_auth_retries(ziti_context ztx);  // ztx_test_helper.c

namespace {
    bool ends_with(const std::string &s, const std::string &suffix) {
        return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    class FakeOidcController {
    public:
        // the OIDC endpoint is declared first: the version of the controller names its address
        FakeOidcController()
                : oidc_([this](const std::string &, const std::string &path) { return oidc(path); }, false),
                  ctrl_([this](const std::string &, const std::string &path) { return ctrl(path); }) {}

        std::string url() const { return ctrl_.url(); }

        // from here on the OIDC endpoint takes connections
        void open_oidc() { oidc_.listen(); }

        int signer_requests() const { return ctrl_.count("/external-jwt-signers"); }

        // the first leg of a login: the context got through the OIDC configuration
        int login_attempts() const { return oidc_.count("/authorize"); }

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
                        R"({"authorization_endpoint":")" + oidc_.url() + R"(/oidc/authorize",)"
                        R"("token_endpoint":")" + oidc_.url() + R"(/oidc/token"})");
            }
            // the test stops at the first sign of a login
            return json_response("503 Service Unavailable", "{}");
        }

        FakeHttpServer oidc_;
        FakeHttpServer ctrl_;
    };
}

// the authentication provider refusing connections is retried with a backoff
TEST_CASE("reauth-backs-off-while-the-oidc-endpoint-refuses-connections", "[reauth][GH-1157]") {
    FakeOidcController ctrl;
    run_context(ctrl.url(), 3000);

    // a first attempt on start, then waits that are at least a second and grow: seconds apart, not
    // thousands of times a second (an unlimited cycle gets a few thousand passes in these 3 s)
    CHECK(ctrl.signer_requests() >= 1);
    CHECK(ctrl.signer_requests() <= 5);
}

// the refresh of the services is for a context that has an api session: it does not start while the
// context has none, and so does not displace the retry of the authentication
TEST_CASE("reauth-retry-survives-a-services-refresh-of-an-unauthenticated-context", "[reauth][GH-1157]") {
    FakeOidcController ctrl;

    int ticks = 0;
    auto done = [&](const context_run &run) {
        // the first attempt has failed by now, and the retry is waiting for its second
        if (++ticks == 4) {
            ziti_services_refresh(run.ztx, true);
        }
        return ctrl.signer_requests() >= 2;
    };
    run_context(ctrl.url(), 10000, done);

    CHECK(ctrl.signer_requests() >= 2);
}

// the failures in a row belong to the run of the context: disabling it ends the wait for the next retry, and the
// count does not stay for the next time the context is enabled (its first failure would wait as long as the last)
TEST_CASE("reauth-backoff-starts-over-when-the-context-is-disabled", "[reauth][GH-1157]") {
    FakeOidcController ctrl;

    int retries_before = 0;
    int retries_after = -1;
    int ticks_since_disable = -1;
    auto done = [&](const context_run &run) {
        if (ticks_since_disable < 0) {
            // two failures so far: the wait for the next one is longer than the first was
            if (ctrl.signer_requests() < 3) {
                return false;
            }
            retries_before = ztx_test_auth_retries(run.ztx);
            ziti_set_enabled(run.ztx, false);
            ticks_since_disable = 0;
            return false;
        }
        // the context has had its turns to stop
        if (++ticks_since_disable < 3) {
            return false;
        }
        retries_after = ztx_test_auth_retries(run.ztx);
        return true;
    };
    run_context(ctrl.url(), 30000, done);

    CHECK(retries_before >= 2);
    CHECK(retries_after == 0);
}

// and the retries carry on until the endpoint is back
TEST_CASE("reauth-recovers-when-the-oidc-endpoint-is-back", "[reauth][GH-1157]") {
    FakeOidcController ctrl;

    auto done = [&](const context_run &) {
        // the first retry happened: the endpoint comes back
        if (ctrl.signer_requests() >= 2) {
            ctrl.open_oidc();
        }
        return ctrl.login_attempts() >= 1;
    };
    run_context(ctrl.url(), 30000, done);

    CHECK(ctrl.login_attempts() >= 1);
}
