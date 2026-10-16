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

// GH-1163: a controller that hands out an API session which is already expired by the clock of this
// machine (the usual reason is a wrong local clock) used to put the context into a loop that
// authenticated every ~20 ms: the legacy auth method asked for the next refresh in 0 s, and
// ztx_prepare() throws out a session token that is past its expiration on every loop iteration.
//
// These tests drive a real ziti_context against a fake legacy controller: it answers /version without
// the OIDC capability, so the context picks legacy authentication, and /authenticate with a session
// whose times the test chooses.

#include "fake_controller.h"

#include "catch2_includes.hpp"

#include <ctime>

using namespace fake_controller;

// internal (zt_internal.h cannot be included from C++): the api session token, which the context has
// only while it is fully authenticated
extern "C" const char *ziti_get_api_session_token(ziti_context ztx);

namespace {
    std::string iso8601(time_t t) {
        struct tm tm = {};
#if _WIN32
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char buf[40];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000000Z", &tm);
        return buf;
    }

    // A legacy (non-OIDC) controller that answers just enough for a context to authenticate.
    class FakeLegacyController {
    public:
        // `clock_offset`: seconds the controller's clock is ahead of ours (negative: behind).
        // `expires_in`: seconds from "now" on the controller's clock to the expiration of the
        // sessions it issues (negative: already expired when issued).
        FakeLegacyController(int64_t clock_offset, int64_t expires_in)
                : server_([this, clock_offset, expires_in](const std::string &, const std::string &path) {
            return respond(path, clock_offset, expires_in);
        }) {}

        std::string url() const { return server_.url(); }

        std::atomic<int> authenticate_count{0};

    private:
        static bool ends_with(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        std::string respond(const std::string &path, int64_t clock_offset, int64_t expires_in) {
            if (ends_with(path, "/version")) {
                return json_response("200 OK", R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                                      R"("runtimeVersion":"fake","capabilities":[],"buildFlags":[],)"
                                      R"("apiVersions":{"edge":{"v1":{"path":"/edge/client/v1"}}}},"meta":{}})");
            }
            if (ends_with(path, "/authenticate")) {
                int n = ++authenticate_count;
                time_t ctrl_now = time(nullptr) + (time_t) clock_offset;
                std::string body =
                        R"({"data":{"id":"fake-session-)" + std::to_string(n) + R"(","token":"fake-token-)" +
                        std::to_string(n) + R"(","identityId":"fake-id",)" +
                        R"("expiresAt":")" + iso8601(ctrl_now + (time_t) expires_in) + R"(",)" +
                        R"("updatedAt":")" + iso8601(ctrl_now) + R"(",)" +
                        R"("cachedLastActivityAt":")" + iso8601(ctrl_now) + R"(",)" +
                        R"("authQueries":[],"identity":{"id":"fake-id","name":"fake"}},"meta":{}})";
                return json_response("200 OK", body);
            }
            return not_found();
        }

        FakeHttpServer server_;
    };
}

// ziti_refresh() asks the controller for the model of the context, which takes an api session: it says
// no when the context has none, instead of starting requests that can only fail
TEST_CASE("ziti-refresh-is-refused-when-the-context-is-not-fully-authenticated", "[legacy-auth][refresh]") {
    FakeLegacyController ctrl(0, -60);  // every session it issues is expired: the authentication fails
    int rc = ZITI_OK;
    run_context(ctrl.url(), 10000, [&](const context_run &run) {
        if (run.auth_failed == 0) {
            return false;
        }
        rc = ziti_refresh(run.ztx);
        return true;
    });

    CHECK(rc == ZITI_INVALID_STATE);
}

TEST_CASE("ziti-refresh-is-accepted-when-the-context-is-fully-authenticated", "[legacy-auth][refresh]") {
    FakeLegacyController ctrl(0, 1800);
    int rc = ZITI_INVALID_STATE;
    run_context(ctrl.url(), 10000, [&](const context_run &run) {
        if (ziti_get_api_session_token(run.ztx) == nullptr) {
            return false;
        }
        rc = ziti_refresh(run.ztx);
        return true;
    });

    CHECK(rc == ZITI_OK);
}

// control: nothing is wrong with the clocks or the session
TEST_CASE("legacy-auth-healthy-session", "[legacy-auth][GH-1163]") {
    FakeLegacyController ctrl(0, 1800);
    auto run = run_context(ctrl.url(), 3000);

    CHECK(ctrl.authenticate_count.load() == 1);
    CHECK(run.auth_failed == 0);
}

// the controller's clock is a day behind ours: its sessions look expired here, they are not,
// and the context carries on with the session
TEST_CASE("legacy-auth-controller-clock-behind", "[legacy-auth][GH-1163]") {
    FakeLegacyController ctrl(-86400, 1800);
    auto run = run_context(ctrl.url(), 3000);

    CHECK(ctrl.authenticate_count.load() == 1);
    CHECK(run.auth_failed == 0);
}

// the controller issues a session that is already expired on its own clock: that is a failed
// authentication, and the next attempt waits instead of asking right away
TEST_CASE("legacy-auth-controller-issues-expired-session", "[legacy-auth][GH-1163]") {
    FakeLegacyController ctrl(0, -60);
    auto run = run_context(ctrl.url(), 3000);

    CHECK(ctrl.authenticate_count.load() == 1);
    CHECK(run.auth_failed == 1);
}
