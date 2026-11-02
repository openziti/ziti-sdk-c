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
extern "C" void ziti_services_refresh(ziti_context ztx, bool now);
// ztx_test_helper.c: what the auth method reports
extern "C" void ztx_test_lose_session(ziti_context ztx);
extern "C" void ztx_test_restart_auth(ziti_context ztx);
extern "C" bool ztx_test_totp_required(ziti_context ztx);
extern "C" void ztx_test_set_totp_required(ziti_context ztx, bool required);

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

        // the whole response to POST /authenticate/mfa; set before the context runs
        std::string mfa_reply = not_found();

        // the authQueries of the sessions it issues (the MFA query of a login that waits for a code); set before the context runs
        std::string auth_queries = "[]";

        // the requests whose path ends with `suffix`
        int count(const std::string &suffix) const { return server_.count(suffix); }

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
                        R"("authQueries":)" + auth_queries + R"(,"identity":{"id":"fake-id","name":"fake"}},"meta":{}})";
                return json_response("200 OK", body);
            }
            if (ends_with(path, "/authenticate/mfa")) {
                return mfa_reply;
            }
            return not_found();
        }

        FakeHttpServer server_;
    };

    struct mfa_result {
        int calls = 0;
        int status = ZITI_WTF;
    };

    void on_mfa(ziti_context, int status, void *ctx) {
        auto *r = static_cast<mfa_result *>(ctx);
        r->calls++;
        r->status = status;
    }
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

namespace {
    struct refresh_effects {
        int polls;              // requests of the refresh that the controller got
        int session_refreshes;  // requests for the api session after the one that follows the login: a request that
                                // is turned down has the session refreshed
    };

    // A refresh of the services is queued while the context is fully authenticated, and the context has left that
    // state by the time it runs. The context makes none of these requests for any other reason on its own: the
    // fake controller answers nothing else.
    refresh_effects refresh_that_is_due_after_leaving_fully_authenticated(void (*leave)(ziti_context)) {
        FakeLegacyController ctrl(0, 1800);
        int ticks_since_leaving = -1;
        run_context(ctrl.url(), 10000, [&](const context_run &run) {
            if (ticks_since_leaving < 0) {
                if (ziti_get_api_session_token(run.ztx) == nullptr) {
                    return false;
                }
                ziti_services_refresh(run.ztx, true);  // runs on the next pass of the loop
                leave(run.ztx);
                ticks_since_leaving = 0;
                return false;
            }
            return ++ticks_since_leaving >= 6;
        });
        return {ctrl.count("/current-identity/edge-routers") + ctrl.count("/current-api-session/service-updates"),
                ctrl.count("/current-api-session") - 1};
    }
}

// the refresh has nothing to poll with once the api session is gone or the authentication starts over, and the
// authentication starts it again: a refresh that was due before that must not send its requests
TEST_CASE("services-refresh-that-is-due-does-not-poll-a-context-that-left-fully-authenticated",
          "[legacy-auth][refresh]") {
    // the requests have no api session token to go with and are refused before they leave: the 401 they come back
    // with is taken for a lost session, and has the session refreshed again
    SECTION("the api session is lost") {
        auto effects = refresh_that_is_due_after_leaving_fully_authenticated(ztx_test_lose_session);
        CHECK(effects.polls == 0);
        CHECK(effects.session_refreshes == 0);
    }
    SECTION("the authentication starts over") {
        auto effects = refresh_that_is_due_after_leaving_fully_authenticated(ztx_test_restart_auth);
        CHECK(effects.polls == 0);
        CHECK(effects.session_refreshes == 0);
    }
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

// A code that the controller does not take (a wrong one, or a controller that cannot answer) is reported to the caller,
// and that is all: a session that has no MFA query to answer (it is fully authenticated, a posture check that needs a
// code came later) has nothing to ask for again. The login that waits for a code is asked for it again, from the MFA
// query of its session; with no query the auth method reported "partially authenticated" with nothing to prompt for,
// and the context dereferenced the missing query.
TEST_CASE("legacy-auth-code-turned-down-on-an-authenticated-session", "[legacy-auth][mfa]") {
    auto [reply, status] = GENERATE(table<std::string, int>({
        {api_error("400 Bad Request", "MFA_INVALID_TOKEN"), ZITI_MFA_INVALID_TOKEN},
        {api_error("401 Unauthorized", "INVALID_AUTHENTICATION"), ZITI_MFA_INVALID_TOKEN},
        {json_response("503 Service Unavailable", R"({"error":{"code":"UNAVAILABLE"}})"), ZITI_CONTROLLER_UNAVAILABLE},
        {not_found(), ZITI_CONTROLLER_UNAVAILABLE},
    }));
    CAPTURE(reply);
    FakeLegacyController ctrl(0, 1800);
    ctrl.mfa_reply = reply;

    mfa_result r;
    bool asked = false;
    int polls_after_answer = 0;
    bool authenticated = false;
    run_context(ctrl.url(), 10000, [&](const context_run &run) {
        if (!asked) {
            if (ziti_get_api_session_token(run.ztx) == nullptr) {
                return false;
            }
            asked = true;
            ziti_mfa_auth(run.ztx, "000000", on_mfa, &r);
            return false;
        }
        // a few polls after the answer, what the context does about it has been done
        if (r.calls == 0 || ++polls_after_answer < 4) {
            return false;
        }
        authenticated = ziti_get_api_session_token(run.ztx) != nullptr;
        return true;
    });

    CHECK(r.calls == 1);
    CHECK(r.status == status);
    CHECK(ctrl.count("/authenticate/mfa") == 1);
    // the session is as it was
    CHECK(authenticated);
    CHECK(ctrl.authenticate_count.load() == 1);
}

// the other side of it: the login that waits for a code has the MFA query on its session, and a code that is turned
// down has the app asked for the next one
TEST_CASE("legacy-auth-code-turned-down-on-a-login-that-waits-for-one-asks-again", "[legacy-auth][mfa]") {
    FakeLegacyController ctrl(0, 1800);
    ctrl.mfa_reply = api_error("400 Bad Request", "MFA_INVALID_TOKEN");
    ctrl.auth_queries = R"([{"id":"mfa-1","typeId":"MFA","provider":"ziti","isTotpEnrolled":true,)"
                        R"("httpMethod":"POST","httpUrl":"./authenticate/mfa","minLength":4,"maxLength":8,)"
                        R"("format":"numeric"}])";

    mfa_result r;
    bool asked = false;
    int polls_after_answer = 0;
    bool asked_again = false;
    bool authenticated = true;
    run_context(ctrl.url(), 10000, [&](const context_run &run) {
        if (!asked) {
            // the context asks the app for a code when the login says so
            if (!ztx_test_totp_required(run.ztx)) {
                return false;
            }
            asked = true;
            // forget it, to see that the app is told again
            ztx_test_set_totp_required(run.ztx, false);
            ziti_mfa_auth(run.ztx, "000000", on_mfa, &r);
            return false;
        }
        if (r.calls == 0 || ++polls_after_answer < 4) {
            return false;
        }
        asked_again = ztx_test_totp_required(run.ztx);
        authenticated = ziti_get_api_session_token(run.ztx) != nullptr;
        return true;
    });

    CHECK(r.calls == 1);
    CHECK(r.status == ZITI_MFA_INVALID_TOKEN);
    CHECK(asked_again);
    // the login is not over
    CHECK_FALSE(authenticated);
}
