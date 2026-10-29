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

// GH-1170: routers that do not seed MFA from the api session token only pass an MFA posture check on a TotpToken posture
// response, and the SDK never asked the controller for the token (POST /current-api-session/totp-token).
//
// These tests drive a real ziti_context against a fake controller that answers the token request the way the test
// chooses. The fake is a legacy controller (it is the one that gets a context to full authentication without an OIDC
// login): the request itself does not depend on the kind of the api session, the callers check that.
//
// What the callback of run_context sees is recorded and checked after the run: an assertion that throws in there goes
// through the C frames of libuv and leaves the shared loop in a state that crashes the next case.

#include "fake_controller.h"

#include "catch2_includes.hpp"

#include <ctime>

#include "totp_jwt.h"

using namespace fake_controller;

// internal (zt_internal.h cannot be included from C++)
extern "C" const char *ziti_get_api_session_token(ziti_context ztx);
extern "C" void ztx_mfa_request_totp_token(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx);
extern "C" void ztx_mfa_keep_code(ziti_context ztx, const char *code);
// ztx_test_helper.c: what the context keeps of a TOTP login (the token for the routers, the code a login took and has not
// finished with), the auth method reporting a finished login or a lost session, and ziti_mfa_auth() / ziti_mfa_verify()
// of an OIDC identity that has no login waiting for a code
extern "C" const char *ztx_test_totp_token(ziti_context ztx);
extern "C" const char *ztx_test_totp_code(ziti_context ztx);
extern "C" void ztx_test_reauthenticated(ziti_context ztx);
extern "C" void ztx_test_lose_session(ziti_context ztx);
extern "C" void ztx_test_mfa_auth_without_login(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx);
extern "C" void ztx_test_mfa_verify_without_login(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx);

namespace {
    const char *TOTP_TOKEN_PATH = "/current-api-session/totp-token";

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

    // what the controller answers when it issues a token
    std::string token_issued(const std::string &jwt) {
        return json_response("200 OK", R"({"data":{"token":")" + jwt +
                                       R"(","issuedAt":"2026-10-23T12:00:00.000Z"},"meta":{}})");
    }

    // the token of the api session `sess-1` that the fake controller hands out
    std::string session_token() {
        return totp_test::totp_jwt("sess-1");
    }

    class FakeTotpController {
    public:
        // `totp_reply`: the whole response to the token request; `authenticates` false has /authenticate turn the
        // context down, so that it never gets an api session
        explicit FakeTotpController(std::string totp_reply, bool authenticates = true)
                : totp_reply_(std::move(totp_reply)), authenticates_(authenticates),
                  server_([this](const std::string &, const std::string &path) { return respond(path); }) {}

        // the whole response to POST /current-identity/mfa/verify (not found when empty); set before the context runs
        std::string mfa_verify_reply;

        std::string url() const { return server_.url(); }

        int count(const std::string &suffix) const { return server_.count(suffix); }

        // the code travels in the body of the token request, as the controller's MfaCode
        bool code_sent(const std::string &code) const {
            return server_.last_body(TOTP_TOKEN_PATH).find("\"code\":\"" + code + "\"") != std::string::npos;
        }

    private:
        static bool ends_with(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        std::string respond(const std::string &path) {
            if (ends_with(path, "/version")) {
                return json_response("200 OK", R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                                      R"("runtimeVersion":"fake","capabilities":[],"buildFlags":[],)"
                                      R"("apiVersions":{"edge":{"v1":{"path":"/edge/client/v1"}}}},"meta":{}})");
            }
            if (ends_with(path, "/authenticate")) {
                if (!authenticates_) {
                    return api_error("401 Unauthorized", "INVALID_AUTHENTICATION");
                }
                return api_session();
            }
            if (ends_with(path, TOTP_TOKEN_PATH)) {
                return totp_reply_;
            }
            if (ends_with(path, "/current-identity/mfa/verify") && !mfa_verify_reply.empty()) {
                return mfa_verify_reply;
            }
            return not_found();
        }

        static std::string api_session() {
            time_t now = time(nullptr);
            std::string body =
                    R"({"data":{"id":"sess-1","token":"fake-token","identityId":"fake-id",)"
                    R"("expiresAt":")" + iso8601(now + 1800) + R"(",)" +
                    R"("updatedAt":")" + iso8601(now) + R"(",)" +
                    R"("cachedLastActivityAt":")" + iso8601(now) + R"(",)" +
                    R"("authQueries":[],"identity":{"id":"fake-id","name":"fake"}},"meta":{}})";
            return json_response("200 OK", body);
        }

        const std::string totp_reply_;
        const bool authenticates_;
        FakeHttpServer server_;
    };

    struct token_request {
        int calls = 0;
        int status = ZITI_WTF;
        std::string kept;   // the token the context keeps for the routers when the callback runs
    };

    void on_token_request(ziti_context ztx, int status, void *ctx) {
        auto *r = static_cast<token_request *>(ctx);
        r->calls++;
        r->status = status;
        r->kept = ztx_test_totp_token(ztx);
    }

    // runs `act` once the context has an api session, then polls `done` until it says so
    void after_auth(FakeTotpController &ctrl, const std::function<void(ziti_context)> &act,
                    const std::function<bool(ziti_context)> &done) {
        bool acted = false;
        run_context(ctrl.url(), 10000, [&](const context_run &run) {
            if (!acted) {
                if (ziti_get_api_session_token(run.ztx) == nullptr) {
                    return false;
                }
                acted = true;
                act(run.ztx);
            }
            return done(run.ztx);
        });
    }

    // runs `ask` once the context has an api session, until the callback it hands on_token_request has run
    token_request ask_when_authenticated(FakeTotpController &ctrl,
                                         const std::function<void(ziti_context, token_request *)> &ask) {
        token_request r;
        after_auth(ctrl, [&](ziti_context ztx) { ask(ztx, &r); }, [&](ziti_context) { return r.calls > 0; });
        return r;
    }

    token_request request_token(FakeTotpController &ctrl, const char *code) {
        return ask_when_authenticated(ctrl, [&](ziti_context ztx, token_request *r) {
            ztx_mfa_request_totp_token(ztx, code, on_token_request, r);
        });
    }
}

TEST_CASE("a controller TOTP token is kept for the posture responses", "[totp][totp-token]") {
    FakeTotpController ctrl(token_issued(session_token()));

    token_request r = request_token(ctrl, "123456");

    CHECK(r.calls == 1);
    CHECK(r.status == ZITI_OK);
    CHECK(r.kept == session_token());
    CHECK(ctrl.code_sent("123456"));
}

TEST_CASE("the refusal of the controller is what the caller is told", "[totp][totp-token]") {
    auto [reply, status] = GENERATE(table<std::string, int>({
        {api_error("400 Bad Request", "MFA_INVALID_TOKEN"), ZITI_MFA_INVALID_TOKEN},
        {api_error("409 Conflict", "MFA_NOT_ENROLLED"), ZITI_MFA_NOT_ENROLLED},
        // a controller without the endpoint
        {not_found(), ZITI_NOT_FOUND},
        // a v1.x controller, which has the operation in its API and no handler for it: it answers 501, and the body is
        // a plain string, no ziti error
        {json_response("501 Not Implemented",
                       R"("operation current_api_session.CreateTotpToken has not yet been implemented")"),
         ZITI_NOT_SUPPORTED},
        // a success that has no token in it
        {json_response("200 OK", R"({"meta":{}})"), ZITI_INVALID_STATE},
    }));
    FakeTotpController ctrl(reply);

    token_request r = request_token(ctrl, "000000");

    CHECK(r.calls == 1);
    CHECK(r.status == status);
    CHECK(r.kept.empty());
    // asked once, nothing is retried
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
}

TEST_CASE("a context that is not authenticated cannot ask for a token", "[totp][totp-token]") {
    FakeTotpController ctrl(token_issued(session_token()), false);

    token_request r;
    run_context(ctrl.url(), 10000, [&](const context_run &run) {
        if (run.auth_failed == 0) {
            return false;
        }
        ztx_mfa_request_totp_token(run.ztx, "123456", on_token_request, &r);
        return true;
    });

    // answered at once, the controller was never asked
    CHECK(r.calls == 1);
    CHECK(r.status == ZITI_INVALID_STATE);
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 0);
}

// GH-1061: the code of an identity whose login is over (a posture check came later, or its timeout ran out) has no login to
// go into: it is exchanged for a TOTP token instead
TEST_CASE("ziti_mfa_auth takes a code when no login waits for one", "[totp][totp-token]") {
    FakeTotpController ctrl(token_issued(session_token()));

    token_request r = ask_when_authenticated(ctrl, [](ziti_context ztx, token_request *r) {
        ztx_test_mfa_auth_without_login(ztx, "123456", on_token_request, r);
    });

    CHECK(r.calls == 1);
    CHECK(r.status == ZITI_OK);
    CHECK(r.kept == session_token());
    CHECK(ctrl.code_sent("123456"));
    // the login (here the legacy one: /authenticate/mfa) was not asked for a code nobody waits for
    CHECK(ctrl.count("/authenticate/mfa") == 0);
}

TEST_CASE("a wrong code through ziti_mfa_auth is reported, and the next code is not turned away", "[totp][totp-token]") {
    FakeTotpController ctrl(api_error("400 Bad Request", "MFA_INVALID_TOKEN"));

    token_request first, second;
    bool asked_second = false;
    after_auth(ctrl, [&](ziti_context ztx) {
        ztx_test_mfa_auth_without_login(ztx, "000000", on_token_request, &first);
    }, [&](ziti_context ztx) {
        if (first.calls > 0 && !asked_second) {
            asked_second = true;
            ztx_test_mfa_auth_without_login(ztx, "000001", on_token_request, &second);
        }
        return second.calls > 0;
    });

    CHECK(first.calls == 1);
    CHECK(first.status == ZITI_MFA_INVALID_TOKEN);
    // the first answer left nothing "in progress" behind
    CHECK(second.calls == 1);
    CHECK(second.status == ZITI_MFA_INVALID_TOKEN);
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 2);
}

// GH-1170: the code that a login took is what buys the TOTP token of the api session the login creates
TEST_CASE("the code a login took buys a TOTP token once the login is over", "[totp][totp-token]") {
    FakeTotpController ctrl(token_issued(session_token()));

    std::string held, kept, code_left;
    after_auth(ctrl, [&](ziti_context ztx) {
        ztx_mfa_keep_code(ztx, "123456");
        held = ztx_test_totp_code(ztx);
        // the login is over: the auth method reports the authenticated context
        ztx_test_reauthenticated(ztx);
    }, [&](ziti_context ztx) {
        kept = ztx_test_totp_token(ztx);
        code_left = ztx_test_totp_code(ztx);
        return !kept.empty();
    });

    CHECK(held == "123456");
    CHECK(kept == session_token());
    CHECK(code_left.empty());
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
    CHECK(ctrl.code_sent("123456"));
}

TEST_CASE("a controller that refuses the TOTP token leaves the login alone", "[totp][totp-token]") {
    FakeTotpController ctrl(not_found());

    int polls_after_request = 0;
    bool authenticated = false;
    std::string held, code_left = "not read";
    after_auth(ctrl, [&](ziti_context ztx) {
        ztx_mfa_keep_code(ztx, "123456");
        held = ztx_test_totp_code(ztx);
        ztx_test_reauthenticated(ztx);
    }, [&](ziti_context ztx) {
        // the refusal has been handled a few polls after the request was made
        if (ctrl.count(TOTP_TOKEN_PATH) == 0 || ++polls_after_request < 3) {
            return false;
        }
        authenticated = ziti_get_api_session_token(ztx) != nullptr;
        code_left = ztx_test_totp_code(ztx);
        return true;
    });

    CHECK(held == "123456");
    CHECK(authenticated);
    CHECK(code_left.empty());
    // asked once, not again
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
}

TEST_CASE("a code does not outlive the login it was given to", "[totp][totp-token]") {
    FakeTotpController ctrl(token_issued(session_token()));

    std::string held, left;
    after_auth(ctrl, [&](ziti_context ztx) {
        ztx_mfa_keep_code(ztx, "123456");
        held = ztx_test_totp_code(ztx);
        // the login did not end well: the context lost its api session
        ztx_test_lose_session(ztx);
        left = ztx_test_totp_code(ztx);
    }, [](ziti_context) { return true; });

    CHECK(held == "123456");
    CHECK(left.empty());
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 0);
}

// GH-1061: an identity that enrols MFA after its login (nothing asked for a code) verifies the enrollment with a REST
// call, as no login waits for the code. The controller passes the MFA check of that session from then on, so the code
// that verified it has to buy the TOTP token: the routers that take only a token would deny what the controller passes,
// and nothing would ask the user for another code.
TEST_CASE("the code that verifies an enrollment after the login buys a TOTP token", "[totp][totp-token]") {
    FakeTotpController ctrl(token_issued(session_token()));
    ctrl.mfa_verify_reply = json_response("200 OK", R"({"data":{},"meta":{}})");

    token_request verified;
    std::string kept, code_left = "not read";
    after_auth(ctrl, [&](ziti_context ztx) {
        ztx_test_mfa_verify_without_login(ztx, "123456", on_token_request, &verified);
    }, [&](ziti_context ztx) {
        kept = ztx_test_totp_token(ztx);
        code_left = ztx_test_totp_code(ztx);
        return !kept.empty();
    });

    CHECK(verified.calls == 1);
    CHECK(verified.status == ZITI_OK);
    CHECK(kept == session_token());
    // the code was the request's, never the context's
    CHECK(code_left.empty());
    CHECK(ctrl.count("/current-identity/mfa/verify") == 1);
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
    CHECK(ctrl.code_sent("123456"));
}

// The verify itself went through: the controller passes the MFA of the session. That the controller has no TOTP token to
// give (a v1.x controller) does not take that back, and the routers of such a controller do not ask for the token.
TEST_CASE("a controller without TOTP tokens does not fail the verify of an enrollment", "[totp][totp-token]") {
    FakeTotpController ctrl(json_response("501 Not Implemented",
                                          R"("operation current_api_session.CreateTotpToken has not yet been implemented")"));
    ctrl.mfa_verify_reply = json_response("200 OK", R"({"data":{},"meta":{}})");

    token_request verified;
    int polls_after_answer = 0;
    std::string kept = "not read", code_left = "not read";
    after_auth(ctrl, [&](ziti_context ztx) {
        ztx_test_mfa_verify_without_login(ztx, "123456", on_token_request, &verified);
    }, [&](ziti_context ztx) {
        // the answer to the token request, which nothing reports, is handled a few polls after the verify
        if (verified.calls == 0 || ctrl.count(TOTP_TOKEN_PATH) == 0 || ++polls_after_answer < 3) {
            return false;
        }
        kept = ztx_test_totp_token(ztx);
        code_left = ztx_test_totp_code(ztx);
        return true;
    });

    CHECK(verified.calls == 1);
    CHECK(verified.status == ZITI_OK);
    CHECK(kept.empty());
    CHECK(code_left.empty());
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 1);
}

TEST_CASE("a code the controller turns down at the verify is not exchanged for a token", "[totp][totp-token]") {
    FakeTotpController ctrl(token_issued(session_token()));
    ctrl.mfa_verify_reply = api_error("400 Bad Request", "MFA_INVALID_TOKEN");

    token_request verified;
    int polls_after_answer = 0;
    std::string kept = "not read", code_left = "not read";
    after_auth(ctrl, [&](ziti_context ztx) {
        ztx_test_mfa_verify_without_login(ztx, "000000", on_token_request, &verified);
    }, [&](ziti_context ztx) {
        // a request for a token, if one were made, would be answered a few polls after the verify
        if (verified.calls == 0 || ++polls_after_answer < 3) {
            return false;
        }
        kept = ztx_test_totp_token(ztx);
        code_left = ztx_test_totp_code(ztx);
        return true;
    });

    CHECK(verified.calls == 1);
    CHECK(verified.status == ZITI_MFA_INVALID_TOKEN);
    CHECK(kept.empty());
    CHECK(code_left.empty());
    CHECK(ctrl.count(TOTP_TOKEN_PATH) == 0);
}
