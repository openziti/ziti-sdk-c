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

// An OIDC api session that comes to owe a TOTP code: the identity is moved onto an auth policy that requires TOTP while
// its session has none. The controller turns down every request of the session, and lists the TOTP query on
// /current-api-session. It still takes the refresh token, and hands out a new access token with the same claims, which
// it turns down in turn.
//
// The context treated the rejection as a lost session and refreshed its token: the refresh succeeded, the context was
// fully authenticated again, the next request was turned down, and around it went, dozens of times a second, without
// ever asking for the code. A code can only be given to a login on OIDC, so the context has to log in again, which
// stops at the TOTP query and asks the app for the code.

#include "fake_controller.h"
#include "totp_jwt.h"

#include "catch2_includes.hpp"

using namespace fake_controller;

// internal (zt_internal.h cannot be included from C++)
extern "C" void ziti_services_refresh(ziti_context ztx, bool now);
extern "C" int ztx_test_auth_state(ziti_context ztx);  // ztx_test_helper.c
// inc_internal/auth_method.h: ZitiAuthStatePartiallyAuthenticated
constexpr int PARTIALLY_AUTHENTICATED = 2;

namespace {
    bool ends_with(const std::string &s, const std::string &suffix) {
        return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

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

    // an access or refresh token of the api session `sess-1`, good for `ttl` seconds
    std::string oidc_jwt(const char *type, long ttl) {
        time_t now = time(nullptr);
        std::string payload = R"({"iss":"https://ctrl.example/oidc","sub":"fake-id","aud":["openziti"],)"
                              R"("amr":["cert"],"z_asid":"sess-1","z_t":")" + std::string(type) +
                              R"(","iat":)" + std::to_string(now) + R"(,"exp":)" + std::to_string(now + ttl) + "}";
        return totp_test::b64url(R"({"alg":"none","typ":"JWT"})") + "." + totp_test::b64url(payload) + ".c2ln";
    }

    const char *TOKEN_PATH = "/oidc/token";
    const char *LOGIN_PATH = "/oidc/login/cert";

    // A controller with its OIDC endpoint on the same address. The identity logs in with its certificate; from
    // require_totp() on, the api session owes a TOTP code.
    class FakeTotpPolicyController {
    public:
        FakeTotpPolicyController()
                : server_([this](const std::string &method, const std::string &path) { return respond(method, path); }) {}

        std::string url() const { return server_.url(); }

        // the auth policy of the identity requires TOTP from here on
        void require_totp() { totp_required_ = true; }

        // the login no longer asks for the code: it ends with a token the controller turns down in turn
        void skip_totp_at_login() { login_skips_totp_ = true; }

        // back to the auth policy that does not require TOTP, and to logins that ask for the code when it does
        void drop_totp_requirement() {
            totp_required_ = false;
            login_skips_totp_ = false;
        }

        int logins() const { return server_.count(LOGIN_PATH); }

        int refreshes() const { return server_.count_with_body(TOKEN_PATH, "grant_type=refresh_token"); }

        int rejected() const { return rejected_; }

    private:
        std::string respond(const std::string &method, const std::string &path) {
            if (path.rfind("/oidc", 0) == 0) {
                return oidc(path);
            }
            if (ends_with(path, "/version")) {
                return json_response(
                        "200 OK",
                        R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                        R"("runtimeVersion":"fake","capabilities":["OIDC_AUTH"],"buildFlags":[],"apiVersions":{)"
                        R"("edge":{"v1":{"path":"/edge/client/v1"}},)"
                        R"("edge-oidc":{"v1":{"path":"/oidc","apiBaseUrls":[")" + server_.url() + R"("]}}}},"meta":{}})");
            }
            // allowed while the authentication is partial: it says what the session still owes
            if (ends_with(path, "/current-api-session")) {
                return api_session();
            }
            if (totp_required_) {
                rejected_++;
                return api_error("401 Unauthorized", "UNAUTHORIZED");
            }
            if (ends_with(path, "/current-identity")) {
                return json_response("200 OK", R"({"data":{"id":"fake-id","name":"fake"},"meta":{}})");
            }
            if (ends_with(path, "/edge-routers") || ends_with(path, "/services")) {
                return json_response("200 OK", R"({"data":[],"meta":{}})");
            }
            if (ends_with(path, "/service-updates")) {
                return json_response("200 OK", R"({"data":{"lastChangeAt":")" + iso8601(time(nullptr)) +
                                               R"("},"meta":{}})");
            }
            (void) method;
            return not_found();
        }

        std::string oidc(const std::string &path) {
            if (ends_with(path, "/.well-known/openid-configuration")) {
                return json_response("200 OK",
                                     R"({"authorization_endpoint":")" + server_.url() + R"(/oidc/authorize",)"
                                     R"("token_endpoint":")" + server_.url() + TOKEN_PATH + R"("})");
            }
            if (ends_with(path, "/oidc/authorize")) {
                return http_response("302 Found", {{"Location", "/oidc/login?authRequestID=req-1"}});
            }
            if (ends_with(path, LOGIN_PATH)) {
                if (totp_required_ && !login_skips_totp_) {
                    // the login stops at the second factor
                    return json_response("200 OK", R"({"authQueries":[{"typeId":"MFA","provider":"ziti",)"
                                                   R"("httpMethod":"POST","httpUrl":"./authenticate/mfa",)"
                                                   R"("format":"alphaNumeric","minLength":4,"maxLength":8,)"
                                                   R"("isTotpEnrolled":true}]})");
                }
                return http_response("302 Found", {{"Location", "/oidc/login/done"}});
            }
            if (ends_with(path, "/oidc/login/done")) {
                return http_response("302 Found", {{"Location", "http://localhost:20314/auth/callback?code=code-1"}});
            }
            if (ends_with(path, TOKEN_PATH)) {
                // the refresh grant does not look at the auth policy: it is a token like the first one
                return json_response("200 OK", R"({"access_token":")" + oidc_jwt("a", 1800) +
                                               R"(","refresh_token":")" + oidc_jwt("r", 86400) +
                                               R"(","token_type":"Bearer","expires_in":1800})");
            }
            return not_found();
        }

        std::string api_session() {
            time_t now = time(nullptr);
            std::string queries = totp_required_
                                  ? R"([{"typeId":"MFA","provider":"ziti","httpMethod":"POST",)"
                                    R"("httpUrl":"./authenticate/mfa","format":"alphaNumeric",)"
                                    R"("minLength":4,"maxLength":8,"isTotpEnrolled":true}])"
                                  : "[]";
            return json_response("200 OK",
                                 R"({"data":{"id":"sess-1","identityId":"fake-id",)"
                                 R"("expiresAt":")" + iso8601(now + 1800) + R"(",)" +
                                 R"("updatedAt":")" + iso8601(now) + R"(",)" +
                                 R"("cachedLastActivityAt":")" + iso8601(now) + R"(",)" +
                                 R"("authQueries":)" + queries + R"(,"identity":{"id":"fake-id","name":"fake"}},"meta":{}})");
        }

        // before the server: its threads use them
        std::atomic<bool> totp_required_{false};
        std::atomic<bool> login_skips_totp_{false};
        std::atomic<int> rejected_{0};

        FakeHttpServer server_;
    };
}

TEST_CASE("an oidc session that comes to owe a totp code logs in again and asks for the code", "[reauth][totp]") {
    FakeTotpPolicyController ctrl;

    std::atomic<int> prompts{0};
    int logins_at_policy_change = -1;
    std::function<void(const ziti_event_t *)> on_event = [&](const ziti_event_t *ev) {
        if (ev->type == ZitiAuthEvent && ev->auth.action == ziti_auth_prompt_totp) {
            prompts++;
        }
    };

    int ticks_since_prompt = -1;
    int state_at_end = -1;
    auto done = [&](const context_run &run) {
        if (logins_at_policy_change < 0) {
            if (run.fully_authenticated < 1) {
                return false;
            }
            // the session is up: the identity moves onto the policy, and the next requests are turned down
            logins_at_policy_change = ctrl.logins();
            ctrl.require_totp();
            ziti_services_refresh(run.ztx, true);
            return false;
        }
        // a while longer after the prompt: nothing else is to happen
        if (prompts > 0 && ++ticks_since_prompt >= 10) {
            state_at_end = ztx_test_auth_state(run.ztx);
            return true;
        }
        return false;
    };
    run_context(ctrl.url(), 5000, done, ZitiAuthEvent, on_event);

    REQUIRE(logins_at_policy_change == 1);
    CHECK(ctrl.rejected() >= 1);
    // the app is asked for the code, once
    CHECK(prompts == 1);
    // by a new login, which stops at the second factor
    CHECK(ctrl.logins() == 2);
    // and not by refreshing the token that the controller turns down: that went on and on
    CHECK(ctrl.refreshes() == 0);
    // the requests that were turned down before the login do not end the wait for the code
    CHECK(state_at_end == PARTIALLY_AUTHENTICATED);
}

TEST_CASE("a login that does not ask for the owed totp code is not repeated right away", "[reauth][totp]") {
    FakeTotpPolicyController ctrl;

    int logins_at_policy_change = -1;
    auto done = [&](const context_run &run) {
        if (logins_at_policy_change < 0 && run.fully_authenticated >= 1) {
            logins_at_policy_change = ctrl.logins();
            ctrl.skip_totp_at_login();
            ctrl.require_totp();
            ziti_services_refresh(run.ztx, true);
        }
        return false;
    };
    run_context(ctrl.url(), 3000, done);

    REQUIRE(logins_at_policy_change == 1);
    INFO("logins: " << ctrl.logins() << ", refreshes: " << ctrl.refreshes() << ", rejected: " << ctrl.rejected());
    // the first login for the code starts right away
    CHECK(ctrl.logins() >= 2);
    // the next ones wait at least a second each (AUTH_RETRY_BASE_MS): without the wait they ran as fast as the
    // rejections came back, dozens in this time. Nor do the requests turned down during the wait start one: the
    // services refresh that the login starts (api_session_cb) sends its requests after the /current-api-session check,
    // they come back turned down during the wait, and a lost session would authenticate right away, a login now that
    // the session is invalidated. ztx_unauthorized ignores them while totp_login is set.
    CHECK(ctrl.logins() <= 5);
    // and the invalidated session is not refreshed
    CHECK(ctrl.refreshes() <= 1);
}

// The logins that did not get the controller to ask for the code are history once the context has a session that owes
// none: the next time the code is owed, its login starts right away, not after the wait those logins built up.
TEST_CASE("a session that owes no totp code ends the wait between logins for one", "[reauth][totp]") {
    FakeTotpPolicyController ctrl;

    using clock = std::chrono::steady_clock;
    std::atomic<bool> prompted{false};
    clock::time_point required_again{};
    clock::time_point prompted_at{};
    std::function<void(const ziti_event_t *)> on_event = [&](const ziti_event_t *ev) {
        if (ev->type == ZitiAuthEvent && ev->auth.action == ziti_auth_prompt_totp && !prompted) {
            prompted_at = clock::now();
            prompted = true;
        }
    };

    int phase = 0;
    int ticks = 0;
    auto done = [&](const context_run &run) {
        switch (phase) {
            case 0: // the session is up: a round of logins that do not ask for the code
                if (run.fully_authenticated < 1) return false;
                ctrl.skip_totp_at_login();
                ctrl.require_totp();
                ziti_services_refresh(run.ztx, true);
                phase = 1;
                return false;
            case 1: // the first login for the code is done, and turned down: the next one waits
                if (ctrl.logins() < 2 || ++ticks < 10) return false;
                ctrl.drop_totp_requirement();
                phase = 2;
                return false;
            case 2: // the login after the wait gets a session that owes nothing, and it works
                if (run.fully_authenticated < 2) return false;
                ctrl.require_totp();
                required_again = clock::now();
                ziti_services_refresh(run.ztx, true);
                phase = 3;
                return false;
            default:
                return prompted.load();
        }
    };
    run_context(ctrl.url(), 10000, done, ZitiAuthEvent, on_event);

    REQUIRE(phase == 3);
    REQUIRE(prompted);
    auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(prompted_at - required_again).count();
    INFO("asked for the code " << waited << " ms after it was owed again; logins: " << ctrl.logins());
    // the shortest wait between those logins is a second (AUTH_RETRY_BASE_MS)
    CHECK(waited < 900);
}
