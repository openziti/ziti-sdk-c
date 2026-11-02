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

// The MFA posture event tells the app when the last TOTP code was given. That is the controller's answer to a code, and
// it does not depend on where the posture data of the identity goes afterwards: an OIDC api session hands the routers a
// TOTP token, a legacy one has none (the controller checks it), and both are told the same.
//
// A real ziti_context runs against a fake controller of the legacy kind (the one that gets a context to full
// authentication without an OIDC login) that serves a service with an MFA posture check, and takes a TOTP code the way
// the legacy API does. What the event says is recorded in the callback of the context and checked after the run: an
// assertion that throws in there goes through the C frames of libuv and leaves the shared loop in a state that crashes the
// next case.

#include "fake_controller.h"

#include "catch2_includes.hpp"

#include <ctime>
#include <string>
#include <vector>

#include "totp_jwt.h"

using namespace fake_controller;

// internal (zt_internal.h cannot be included from C++)
extern "C" const char *ziti_get_api_session_token(ziti_context ztx);
// ztx_test_helper.c: ziti_mfa_auth() / ziti_mfa_verify() of an identity that logs in with OIDC and has no login waiting for a
// code, on a context that runs another auth method (the fake controller authenticates the legacy way)
extern "C" void ztx_test_mfa_auth_without_login(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx);
extern "C" void ztx_test_mfa_verify_without_login(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx);

namespace {
    const char *MFA_PATH = "/authenticate/mfa";
    const char *VERIFY_PATH = "/current-identity/mfa/verify";
    const char *TOTP_TOKEN_PATH = "/current-api-session/totp-token";

    // a service that its policy lets an identity dial once it has given a code, for 5 minutes
    const char *MFA_SERVICE = R"({"data":[{"id":"svc-mfa","name":"mfa-service","permissions":["Dial"],)"
                              R"("encryptionRequired":false,"postureQueries":[{"policyId":"p1","isPassing":false,)"
                              R"("policyType":"Dial","postureQueries":[{"id":"q-mfa","isPassing":false,"queryType":"MFA",)"
                              R"("timeout":300,"timeoutRemaining":-1}]}]}],"meta":{}})";

    class FakeLegacyMfaController {
    public:
        FakeLegacyMfaController()
                : server_([this](const std::string &method, const std::string &path) { return respond(method, path); }) {}

        // the whole response to POST /authenticate/mfa and to POST /current-identity/mfa/verify: a code that is taken;
        // and to POST /current-api-session/totp-token (an OIDC api session asks for it, for the routers): a controller that
        // has none. Set before the context runs
        std::string code_reply = json_response("200 OK", R"({"data":{},"meta":{}})");
        std::string totp_token_reply = not_found();

        std::string url() const { return server_.url(); }

        int count(const std::string &suffix) const { return server_.count(suffix); }

    private:
        static bool ends_with(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        static std::string iso8601(time_t t) {
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

        std::string respond(const std::string &, const std::string &path) {
            if (ends_with(path, "/version")) {
                return json_response("200 OK", R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                                      R"("runtimeVersion":"fake","capabilities":[],"buildFlags":[],)"
                                      R"("apiVersions":{"edge":{"v1":{"path":"/edge/client/v1"}}}},"meta":{}})");
            }
            // the api session of the login, and the same again for the context asking what its session is
            if (ends_with(path, "/authenticate") || ends_with(path, "/current-api-session")) {
                time_t now = time(nullptr);
                return json_response("200 OK",
                                     R"({"data":{"id":"sess-1","token":"fake-token","identityId":"fake-id",)"
                                     R"("expiresAt":")" + iso8601(now + 1800) + R"(",)" +
                                     R"("updatedAt":")" + iso8601(now) + R"(",)" +
                                     R"("cachedLastActivityAt":")" + iso8601(now) + R"(",)" +
                                     R"("authQueries":[],"identity":{"id":"fake-id","name":"fake"}},"meta":{}})");
            }
            // the context fetches the services once the controller says that they changed
            if (ends_with(path, "/current-api-session/service-updates")) {
                return json_response("200 OK", R"({"data":{"lastChangeAt":"2026-10-30T12:00:00.000Z"},"meta":{}})");
            }
            if (ends_with(path, "/services")) {
                return json_response("200 OK", MFA_SERVICE);
            }
            if (ends_with(path, MFA_PATH) || ends_with(path, VERIFY_PATH)) {
                return code_reply;
            }
            if (ends_with(path, TOTP_TOKEN_PATH)) {
                return totp_token_reply;
            }
            if (ends_with(path, "/posture-response-bulk")) {
                return json_response("200 OK", R"({"data":{"services":[]},"meta":{}})");
            }
            return not_found();
        }

        FakeHttpServer server_;
    };

    // what the app hears of the MFA checks: every event, in order
    struct mfa_event {
        int64_t last_code_at;
        int64_t timeout;
        bool expiring;
        std::vector<std::string> services;
    };

    struct mfa_events {
        std::vector<mfa_event> seen;

        void add(const ziti_event_t *ev) {
            if (ev->type != ZitiPostureStatusEvent || ev->posture_status.query_type != ziti_posture_query_type_PC_MFA) {
                return;
            }
            mfa_event e = {ev->posture_status.mfa.last_code_at, ev->posture_status.mfa.timeout,
                           ev->posture_status.mfa.expiring, {}};
            for (ziti_service **s = ev->posture_status.services; s && *s; s++) {
                e.services.emplace_back((*s)->name);
            }
            seen.push_back(std::move(e));
        }

        // the last thing the app was told: no code is what a context that was told nothing has
        int64_t last_code_at() const { return seen.empty() ? 0 : seen.back().last_code_at; }
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

    // Runs a context against `ctrl` until the app has heard that a service needs a code, then has the context send `code`
    // with `send` and waits until the controller has answered and a few polls went by (an event, if one is due, comes with
    // the answer or a little later).
    struct code_run {
        mfa_events events;
        mfa_result result;
        // what the app was told before the code, and the time around the code
        size_t told_before = 0;
        int64_t sent_at = 0;
        int64_t answered_at = 0;
    };

    code_run give_code(FakeLegacyMfaController &ctrl,
                       const std::function<void(ziti_context, mfa_result *)> &send) {
        code_run r;
        bool sent = false;
        int polls_after_answer = 0;
        run_context(ctrl.url(), 10000, [&](const context_run &run) {
            if (!sent) {
                if (ziti_get_api_session_token(run.ztx) == nullptr || r.events.seen.empty()) {
                    return false;
                }
                sent = true;
                r.told_before = r.events.seen.size();
                r.sent_at = (int64_t) time(nullptr);
                send(run.ztx, &r.result);
                return false;
            }
            if (r.result.calls == 0) {
                return false;
            }
            r.answered_at = (int64_t) time(nullptr);
            return ++polls_after_answer >= 4;
        }, ZitiPostureStatusEvent, [&](const ziti_event_t *ev) { r.events.add(ev); });
        return r;
    }
}

// the app is told that a service needs a code, and that none was given
TEST_CASE("a legacy context reports an MFA check with no code before one is given", "[posture][mfa-event]") {
    FakeLegacyMfaController ctrl;
    mfa_events events;

    run_context(ctrl.url(), 10000, [&](const context_run &) { return !events.seen.empty(); },
                ZitiPostureStatusEvent, [&](const ziti_event_t *ev) { events.add(ev); });

    REQUIRE(!events.seen.empty());
    CHECK(events.seen[0].last_code_at == 0);
    CHECK(events.seen[0].timeout == 300);
    CHECK(events.seen[0].expiring == false);
    REQUIRE(events.seen[0].services.size() == 1);
    CHECK(events.seen[0].services[0] == "mfa-service");
}

// The event is about the code that the controller took, whatever happens to the posture data afterwards: a legacy api
// session has no TOTP token to give to the routers, and its code counts all the same.
TEST_CASE("a code the legacy controller takes is reported by the MFA event", "[posture][mfa-event]") {
    FakeLegacyMfaController ctrl;

    code_run r = give_code(ctrl, [](ziti_context ztx, mfa_result *result) {
        ziti_mfa_auth(ztx, "123456", on_mfa, result);
    });

    REQUIRE(r.told_before >= 1);
    CHECK(r.events.seen[0].last_code_at == 0);
    CHECK(r.result.calls == 1);
    CHECK(r.result.status == ZITI_OK);
    CHECK(ctrl.count(MFA_PATH) == 1);
    // the token is for the routers, no part of this
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 0);

    // the app was told of the code: when the controller took it, as the context saw it
    REQUIRE(r.events.seen.size() > r.told_before);
    CHECK(r.events.last_code_at() >= r.sent_at);
    CHECK(r.events.last_code_at() <= r.answered_at);
    CHECK(r.events.seen.back().timeout == 300);
    CHECK(r.events.seen.back().expiring == false);
}

// the controller turning a code down is no code: the app is told nothing new
TEST_CASE("a code the legacy controller turns down is not reported", "[posture][mfa-event]") {
    FakeLegacyMfaController ctrl;
    ctrl.code_reply = api_error("400 Bad Request", "MFA_INVALID_TOKEN");

    code_run r = give_code(ctrl, [](ziti_context ztx, mfa_result *result) {
        ziti_mfa_auth(ztx, "000000", on_mfa, result);
    });

    REQUIRE(r.told_before >= 1);
    CHECK(r.result.calls == 1);
    CHECK(r.result.status == ZITI_MFA_INVALID_TOKEN);
    CHECK(ctrl.count(MFA_PATH) == 1);
    CHECK(r.events.seen.size() == r.told_before);
    CHECK(r.events.last_code_at() == 0);
}

// An identity that enrols MFA after its login verifies the enrollment with a code, and the controller passes the MFA of
// the api session from then on: that code counts the same.
TEST_CASE("the code that verifies an MFA enrollment on a legacy context is reported", "[posture][mfa-event]") {
    FakeLegacyMfaController ctrl;

    code_run r = give_code(ctrl, [](ziti_context ztx, mfa_result *result) {
        ziti_mfa_verify(ztx, "123456", on_mfa, result);
    });

    REQUIRE(r.told_before >= 1);
    CHECK(r.result.calls == 1);
    CHECK(r.result.status == ZITI_OK);
    CHECK(ctrl.count(VERIFY_PATH) == 1);
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 0);
    REQUIRE(r.events.seen.size() > r.told_before);
    CHECK(r.events.last_code_at() >= r.sent_at);
    CHECK(r.events.last_code_at() <= r.answered_at);
}

// An OIDC api session asks the controller for a TOTP token after it took a code, for the routers. The event is about the
// code the controller took, so what becomes of that request changes when the app hears of it, not what it hears.
namespace {
    // what the controller answers when it issues a token
    std::string token_issued(const std::string &jwt) {
        return json_response("200 OK", R"({"data":{"token":")" + jwt +
                                       R"(","issuedAt":"2026-10-23T12:00:00.000Z"},"meta":{}})");
    }
}

TEST_CASE("an OIDC code is reported when the controller has no TOTP token for the routers", "[posture][mfa-event]") {
    FakeLegacyMfaController ctrl;
    // a v1.x controller has the operation in its API and no handler for it
    ctrl.totp_token_reply = json_response("501 Not Implemented",
                                          R"("operation current_api_session.CreateTotpToken has not yet been implemented")");

    code_run r = give_code(ctrl, [](ziti_context ztx, mfa_result *result) {
        ztx_test_mfa_verify_without_login(ztx, "123456", on_mfa, result);
    });

    REQUIRE(r.told_before >= 1);
    // the verify went through, and that is what the app is told of
    CHECK(r.result.status == ZITI_OK);
    CHECK(ctrl.count(VERIFY_PATH) == 1);
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
    REQUIRE(r.events.seen.size() > r.told_before);
    CHECK(r.events.last_code_at() >= r.sent_at);
    CHECK(r.events.last_code_at() <= r.answered_at);
}

TEST_CASE("an OIDC code with a TOTP token is reported once, at the moment the controller put in the token",
          "[posture][mfa-event]") {
    const long long given_at = (long long) time(nullptr) - 5;
    FakeLegacyMfaController ctrl;
    ctrl.totp_token_reply = token_issued(totp_test::totp_jwt("sess-1", given_at));

    code_run r = give_code(ctrl, [](ziti_context ztx, mfa_result *result) {
        ztx_test_mfa_verify_without_login(ztx, "123456", on_mfa, result);
    });

    REQUIRE(r.told_before >= 1);
    CHECK(r.result.status == ZITI_OK);
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
    // one event for the code, not one for the verify and another for the token
    REQUIRE(r.events.seen.size() == r.told_before + 1);
    CHECK(r.events.last_code_at() == given_at);
}

// the code of a context that is authenticated goes to the controller as a request for a TOTP token (OIDC): the controller
// turning the code down is no code
TEST_CASE("an OIDC code the controller turns down is not reported", "[posture][mfa-event]") {
    FakeLegacyMfaController ctrl;
    ctrl.totp_token_reply = api_error("400 Bad Request", "MFA_INVALID_TOKEN");

    code_run r = give_code(ctrl, [](ziti_context ztx, mfa_result *result) {
        ztx_test_mfa_auth_without_login(ztx, "000000", on_mfa, result);
    });

    REQUIRE(r.told_before >= 1);
    CHECK(r.result.status == ZITI_MFA_INVALID_TOKEN);
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
    CHECK(r.events.seen.size() == r.told_before);
    CHECK(r.events.last_code_at() == 0);
}
