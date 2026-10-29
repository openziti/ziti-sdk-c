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

// GH-1061, GH-1087: a TOTP code that no OIDC login waits for was answered "an MFA enrollment already exists", and
// ziti_mfa_auth() went on after it had refused a NULL code or a second code while one was in flight.
//
// The control flow of ziti_mfa_auth() does not reach further than the auth method: the context here is the bare one of
// ztx_test_helper.c, with an auth method that counts what it is given.

// model_support.h #defines `map`: tls_test_util.h pulls in the standard headers, so it goes first
#include "tls_test_util.h"

#include "catch2_includes.hpp"

#include <uv.h>
#include <ziti/ziti.h>
#include <ziti/errors.h>

#include "auth_method.h"
#include "credentials.h"

// ztx_test_helper.c
extern "C" {
ziti_context ztx_test_mfa_stub_new(int submit_rc, bool oidc, bool fully_authenticated);
void ztx_test_mfa_stub_free(ziti_context ztx);
int ztx_test_mfa_stub_submits(ziti_context ztx);
void ztx_test_mfa_stub_report(ziti_context ztx, int status);
void ztx_test_mfa_stub_verify_report_error(ziti_context ztx, int err);
void ztx_test_mfa_stub_verify_report_ok(ziti_context ztx);
void ztx_test_mfa_stub_set_rc(ziti_context ztx, int submit_rc);
const char *ztx_test_totp_code(ziti_context ztx);
}

namespace {
    // one loop for every case: creating and closing a loop per case trips libuv's fd assertion when
    // the whole suite runs in one process
    uv_loop_t *test_loop() {
        static uv_loop_t *loop = uv_loop_new();
        uv_update_time(loop);
        return loop;
    }

    struct stub_context {
        ziti_context ztx;

        // `submit_rc`: what the auth method answers a code with
        stub_context(int submit_rc, bool oidc, bool fully_authenticated)
                : ztx(ztx_test_mfa_stub_new(submit_rc, oidc, fully_authenticated)) {}

        ~stub_context() { ztx_test_mfa_stub_free(ztx); }

        int submits() const { return ztx_test_mfa_stub_submits(ztx); }
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

TEST_CASE("ziti_mfa_auth refuses a NULL code once, without asking the auth method", "[mfa-auth][totp]") {
    stub_context s(ZITI_OK, true, true);
    mfa_result r;

    ziti_mfa_auth(s.ztx, nullptr, on_mfa, &r);

    CHECK(r.calls == 1);
    CHECK(r.status == ZITI_WTF);
    CHECK(s.submits() == 0);
}

TEST_CASE("ziti_mfa_auth refuses a code while another is in flight", "[mfa-auth][totp]") {
    // a login that waits for a code is not fully authenticated
    stub_context s(ZITI_OK, true, false);
    mfa_result first, second;

    ziti_mfa_auth(s.ztx, "111111", on_mfa, &first);
    ziti_mfa_auth(s.ztx, "222222", on_mfa, &second);

    CHECK(second.calls == 1);
    CHECK(second.status == ZITI_INVALID_STATE);
    CHECK(first.calls == 0);
    CHECK(s.submits() == 1);

    // the answer to the code that was taken goes to the one who sent it, once
    ztx_test_mfa_stub_report(s.ztx, ZITI_OK);
    CHECK(first.calls == 1);
    CHECK(first.status == ZITI_OK);
    CHECK(second.calls == 1);
}

TEST_CASE("a code that no login waits for is refused by a context that is not authenticated, and not kept",
          "[mfa-auth][totp]") {
    stub_context s(ZITI_INVALID_STATE, true, false);
    mfa_result r;

    ziti_mfa_auth(s.ztx, "123456", on_mfa, &r);

    CHECK(r.calls == 1);
    CHECK(r.status == ZITI_INVALID_STATE);
    CHECK(s.submits() == 1);
    CHECK(std::string(ztx_test_totp_code(s.ztx)).empty());
}

// no controller behind the context: a request for a token would not get an answer, which is the point
TEST_CASE("only the OIDC auth method takes a code with a TOTP token", "[mfa-auth][totp]") {
    stub_context s(ZITI_INVALID_STATE, false, true);
    mfa_result r;

    ziti_mfa_auth(s.ztx, "123456", on_mfa, &r);

    CHECK(r.calls == 1);
    CHECK(r.status == ZITI_INVALID_STATE);
    CHECK(s.submits() == 1);
}

// The api session that a login creates needs a TOTP token, which the controller gives for a code: the context holds on to
// the code that the login took until the login is over, and not a moment longer than the login can need it.
TEST_CASE("a code the OIDC login takes is kept until the login is over, and wiped if the login turns it down",
          "[mfa-auth][totp]") {
    stub_context s(ZITI_OK, true, false);
    mfa_result r;

    ziti_mfa_auth(s.ztx, "123456", on_mfa, &r);
    REQUIRE(std::string(ztx_test_totp_code(s.ztx)) == "123456");

    SECTION("the login accepts it") {
        // its api session is not there yet
        ztx_test_mfa_stub_report(s.ztx, ZITI_OK);
        CHECK(r.status == ZITI_OK);
        CHECK(std::string(ztx_test_totp_code(s.ztx)) == "123456");
    }

    SECTION("the login turns it down") {
        ztx_test_mfa_stub_report(s.ztx, ZITI_MFA_INVALID_TOKEN);
        CHECK(r.calls == 1);
        CHECK(r.status == ZITI_MFA_INVALID_TOKEN);
        CHECK(std::string(ztx_test_totp_code(s.ztx)).empty());
    }
}

// the login has taken the first code and is still finishing: a second code finds nobody waiting, and must not touch the first
TEST_CASE("a second code while the login finishes leaves the code the login took", "[mfa-auth][totp]") {
    stub_context s(ZITI_OK, true, false);
    mfa_result first, second;

    ziti_mfa_auth(s.ztx, "111111", on_mfa, &first);
    ztx_test_mfa_stub_report(s.ztx, ZITI_OK);
    REQUIRE(first.status == ZITI_OK);
    REQUIRE(std::string(ztx_test_totp_code(s.ztx)) == "111111");

    ztx_test_mfa_stub_set_rc(s.ztx, ZITI_INVALID_STATE);
    ziti_mfa_auth(s.ztx, "222222", on_mfa, &second);

    CHECK(second.status == ZITI_INVALID_STATE);
    CHECK(std::string(ztx_test_totp_code(s.ztx)) == "111111");
}

TEST_CASE("a legacy auth method keeps no code, there is no TOTP token to buy", "[mfa-auth][totp]") {
    stub_context s(ZITI_OK, false, false);
    mfa_result r;

    ziti_mfa_auth(s.ztx, "123456", on_mfa, &r);

    CHECK(s.submits() == 1);
    CHECK(std::string(ztx_test_totp_code(s.ztx)).empty());
}

TEST_CASE("the code of ziti_mfa_verify reaches the context only once the login has taken it", "[mfa-auth][totp]") {
    stub_context s(ZITI_OK, true, false);
    mfa_result r;

    ziti_mfa_verify(s.ztx, "654321", on_mfa, &r);
    // until the login has answered, the code belongs to the request
    REQUIRE(r.calls == 0);
    CHECK(std::string(ztx_test_totp_code(s.ztx)).empty());

    SECTION("the login takes it") {
        // the api session that the login creates is not there yet
        ztx_test_mfa_stub_verify_report_ok(s.ztx);
        CHECK(r.status == ZITI_OK);
        CHECK(std::string(ztx_test_totp_code(s.ztx)) == "654321");
    }

    SECTION("the login turns it down") {
        ztx_test_mfa_stub_verify_report_error(s.ztx, ZITI_MFA_INVALID_TOKEN);
        CHECK(r.calls == 1);
        CHECK(r.status == ZITI_MFA_INVALID_TOKEN);
        CHECK(std::string(ztx_test_totp_code(s.ztx)).empty());
    }
}

TEST_CASE("the OIDC auth method answers ZITI_INVALID_STATE to a code when no login waits for one", "[mfa-auth][totp]") {
    const char *json = R"({"path": "/oidc", "apiBaseUrls": ["https://192.0.2.1:1280"]})";
    api_path oidc{};
    REQUIRE(parse_api_path(&oidc, json, strlen(json)) >= 0);

    zt_x509 creds{};
    uv_loop_t *loop = test_loop();
    ziti_auth_method_t *auth = new_oidc_auth(loop, &oidc, rsa_cert, &creds);
    REQUIRE(auth != nullptr);

    // the login has not started: nothing asked for a code
    CHECK(auth->submit_mfa(auth, "123456", [](void *, int) {}) == ZITI_INVALID_STATE);

    auth->free(auth);
    uv_run(loop, UV_RUN_DEFAULT);
    free_api_path(&oidc);
}
