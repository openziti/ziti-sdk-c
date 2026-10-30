// Copyright (c) 2023-2026.  NetFoundry Inc
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

#include <catch2/catch_all.hpp>
#include <vector>
#include <tlsuv/tlsuv.h>
#include <ziti/ziti.h>
#include <ziti/zitilib.h>

// stc/cstr.h declares _cstr_init as plain `extern`, which mangles under C++; common.h first, then cstr.h
// under C linkage, satisfies both (as in e2e_tests.cpp)
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}

#include "fixtures.h"
#include "oidc.h"
#include "test-data.h"
#include "totp.h"
#include "ziti/ziti_log.h"
#include "ziti_ctrl.h"

// the SDK's own callback for the state of the authentication, which the auth method calls
extern "C" void ztx_auth_state_cb(void *ctx, ziti_auth_state state, const void *data);
extern "C" ziti_controller *ztx_get_controller(ziti_context ztx);
extern "C" void ziti_force_api_session_refresh(ziti_context ztx);
// totp_test_helper.c: what the context keeps of a TOTP login
extern "C" const char *ztx_test_totp_token(ziti_context ztx);
extern "C" const char *ztx_test_totp_code(ziti_context ztx);

class AuthTests: public LoopTestCase {};

TEST_CASE_METHOD(AuthTests, "oidc", "[auth]") {
    auto l = loop();
    ziti_config cfg{};
    DEFER {
            free_ziti_config(&cfg);
    };
    auto *cfg_str = checkENV("test_client");
    REQUIRE(ziti_load_config(&cfg, cfg_str) == ZITI_OK);
    auto tls = default_tls_context();
    REQUIRE(tls->set_ca_bundle(tls, cfg.id.ca, strlen(cfg.id.ca)) == 0);
    tlsuv_certificate_t cert{};
    tlsuv_private_key_t key{};
    DEFER {
            if (key) key->free(key);
            if (cert) cert->free(cert);
            if (tls) tls->free_ctx(tls);
    };
    REQUIRE_ZITI_OK(tls->load_cert(&cert, cfg.id.cert, strlen(cfg.id.cert)));
    REQUIRE_ZITI_OK(tls->load_key(&key, cfg.id.key, strlen(cfg.id.key)));
    tls->set_own_cert(tls, key, cert);

    auto provider = (const char *)model_list_head(&cfg.controllers);

    oidc_client_t oidcClient{};
    DEFER {
            oidc_client_close(&oidcClient, [](oidc_client_t *clt) { });
            uv_run(l, UV_RUN_DEFAULT);
    };
    oidc_client_init(l, &oidcClient, provider, tls);
    zt_x509 x509{key, cert};
    oidcClient.tls = tls;
    oidcClient.x509 = &x509;
    struct oidc_cfg_result {
        bool called;
        int status;
    } cfg_result = {false, -1};
    oidcClient.data = &cfg_result;

    oidc_client_configure(&oidcClient, [](oidc_client_t *clt, int status, const char *err) {
        auto res = (oidc_cfg_result *)clt->data;
        res->called = true;
        res->status = status;
    });

    uv_run(l, UV_RUN_DEFAULT);

    CHECK(cfg_result.called);
    if (cfg_result.status == 404) {
        SKIP("OIDC endpoint not found");
    }
    CHECK(oidcClient.config != nullptr);

    std::string token;
    oidcClient.data = &token;
    oidc_client_start(&oidcClient, [](oidc_client_t *clt, enum oidc_status status, const void *d) {
        auto out = static_cast<std::string *>(clt->data);
        if (status == OIDC_TOKEN_OK) {
            *out = static_cast<const char *>(d);
        }
    });

    uv_run(l, UV_RUN_DEFAULT);

    REQUIRE(!token.empty());

    std::string old = token;
    token.clear();

    oidc_client_refresh(&oidcClient);
    uv_run(l, UV_RUN_DEFAULT);

    REQUIRE(!token.empty());
    REQUIRE(token != old);
}

TEST_CASE_METHOD(ZitiTestCase, "oidc-totp", "[totp]") {
    auto load_rc = load();

    CHECK(load_rc == ZITI_PARTIALLY_AUTHENTICATED);
    if (authState.action == 0) {
        CHECK(run(WHILE(authState.action == 0)));
    }

    struct mfa {
        std::string link{};
        bool verified{false};
        bool cb_called{false};
        int status{ZITI_OK};
    } mfa;

    ziti_mfa_enroll(ztx, [](ziti_context ztx, int status, ziti_mfa_enrollment *mfa_enrollment, void *ctx){
        auto m = (struct mfa *)ctx;
        CHECK(status == ZITI_OK);
        m->link = mfa_enrollment->provisioning_url;
    }, &mfa);

    CHECK(run(UNTIL(!mfa.link.empty())));
    INFO("provisioning url: " << mfa.link);
    auto secret = mfa.link.substr(mfa.link.find("secret=") + 7);
    auto key = totp::base32_decode(secret);

    // try invalid token first
    ziti_mfa_verify(ztx, "000000", [](ziti_context ztx, int status, void *ctx){
        auto m = (struct mfa *)ctx;
        m->cb_called = true;
        m->status = status;
    }, &mfa);

    REQUIRE(run(UNTIL(mfa.cb_called)));
    CHECK(mfa.status == ZITI_MFA_INVALID_TOKEN);

    for (int i = 0; i < 3; i++) {
        mfa.cb_called = false;
        mfa.status = ZITI_OK;

        auto ts = std::chrono::system_clock::now();
        auto code = totp::generate(key, ts);
        char code_str[8];
        snprintf(code_str, sizeof(code_str), "%06u", (unsigned)code);

        UNSCOPED_INFO("totp attempt: " << (i + 1));
        ziti_mfa_verify(ztx, code_str, [](ziti_context ztx, int status, void *ctx){
            auto m = (struct mfa *)ctx;
            m->cb_called = true;
            m->status = status;
            m->verified = (status == ZITI_OK);
        }, &mfa);

        REQUIRE(run(UNTIL(mfa.cb_called)));
        if (mfa.verified) {
            break;
        }
        uv_sleep(1000);
    }
    REQUIRE(mfa.verified);

    INFO("TOTP enrollment and verification successful");
    REQUIRE(run(UNTIL(this->loaded && this->load_error == ZITI_OK)));
}

namespace {
    struct mfa_result {
        bool called{false};
        int status{ZITI_OK};
    };

    void mfa_result_cb(ziti_context, int status, void *ctx) {
        auto r = (mfa_result *) ctx;
        r->called = true;
        r->status = status;
    }

    std::string totp_code(const std::vector<uint8_t> &key) {
        char code[8];
        snprintf(code, sizeof(code), "%06u", (unsigned) totp::generate(key, std::chrono::system_clock::now()));
        return code;
    }

    // a context of the same identity, as an application that was restarted would have it
    struct restarted_context {
        ziti_config config{};
        ziti_context ztx{};
        ziti_options options{
            .config_types = (const char **) ALL_CONFIGS,
            .app_ctx = this,
            .events = ZitiContextEvent | ZitiAuthEvent,
            .event_cb = [](ziti_context z, const ziti_event_t *ev) {
                auto self = (restarted_context *) ziti_app_ctx(z);
                if (ev->type == ZitiAuthEvent && ev->auth.action == ziti_auth_prompt_totp) {
                    self->totp_prompted = true;
                }
                if (ev->type == ZitiContextEvent && ev->ctx.ctrl_status == ZITI_OK) {
                    self->loaded = true;
                }
            },
        };
        bool totp_prompted{false};
        bool loaded{false};

        ~restarted_context() {
            if (ztx) ziti_shutdown(ztx);
            free_ziti_config(&config);
        }
    };
}

// ziti_is_mfa_enrolled() reports what the controller says of the identity: no for an identity without MFA,
// no for an enrollment that is not verified, yes once it is. The context learns about its own verify and
// remove at once, and a context that is started later learns it from the controller.
TEST_CASE_METHOD(ZitiTestCase, "mfa-enrolled", "[mfa-enrolled]") {
    REQUIRE_ZITI_OK(load());
    // the identity data, which has the MFA state, comes after the context is loaded
    REQUIRE(run(UNTIL(ziti_get_identity(ztx) != nullptr)));

    CHECK_FALSE(ziti_is_mfa_enrolled(ztx));

    struct {
        std::string link;
    } enrollment;
    ziti_mfa_enroll(ztx, [](ziti_context, int status, ziti_mfa_enrollment *mfa_enrollment, void *ctx) {
        CHECK(status == ZITI_OK);
        if (mfa_enrollment) ((decltype(enrollment) *) ctx)->link = mfa_enrollment->provisioning_url;
    }, &enrollment);
    REQUIRE(run(UNTIL(!enrollment.link.empty())));
    auto key = totp::base32_decode(enrollment.link.substr(enrollment.link.find("secret=") + 7));

    // started, not verified
    CHECK_FALSE(ziti_is_mfa_enrolled(ztx));

    // the code can fall on the edge of its 30 s window: try again
    mfa_result verify;
    for (int i = 0; i < 3 && (!verify.called || verify.status != ZITI_OK); i++) {
        verify = {};
        auto code = totp_code(key);
        ziti_mfa_verify(ztx, code.c_str(), mfa_result_cb, &verify);
        REQUIRE(run(UNTIL(verify.called)));
        if (verify.status != ZITI_OK) uv_sleep(1000);
    }
    REQUIRE(verify.status == ZITI_OK);
    CHECK(ziti_is_mfa_enrolled(ztx));

    // the controller asks the identity for the code from now on: the new context gets the state from it
    restarted_context second;
    REQUIRE_ZITI_OK(ziti_load_config(&second.config, test_client()));
    REQUIRE_ZITI_OK(ziti_context_init(&second.ztx, &second.config));
    REQUIRE_ZITI_OK(ziti_context_set_options(second.ztx, &second.options));
    REQUIRE_ZITI_OK(ziti_context_run(second.ztx, loop()));
    REQUIRE(run(UNTIL(second.totp_prompted)));
    CHECK_FALSE(ziti_is_mfa_enrolled(second.ztx)); // nothing is known before the login is complete

    mfa_result auth;
    for (int i = 0; i < 3 && (!auth.called || auth.status != ZITI_OK); i++) {
        auth = {};
        auto code = totp_code(key);
        ziti_mfa_auth(second.ztx, code.c_str(), mfa_result_cb, &auth);
        REQUIRE(run(UNTIL(auth.called)));
        if (auth.status != ZITI_OK) uv_sleep(1000);
    }
    REQUIRE(auth.status == ZITI_OK);
    REQUIRE(run(UNTIL(second.loaded)));
    REQUIRE(run(UNTIL(ziti_get_identity(second.ztx) != nullptr)));
    CHECK(ziti_is_mfa_enrolled(second.ztx));

    mfa_result remove;
    for (int i = 0; i < 3 && (!remove.called || remove.status != ZITI_OK); i++) {
        remove = {};
        auto code = totp_code(key);
        ziti_mfa_remove(second.ztx, code.c_str(), mfa_result_cb, &remove);
        REQUIRE(run(UNTIL(remove.called)));
        if (remove.status != ZITI_OK) uv_sleep(1000);
    }
    REQUIRE(remove.status == ZITI_OK);
    CHECK_FALSE(ziti_is_mfa_enrolled(second.ztx));
}

// GH-1170, GH-1061: the api session of a login that took a TOTP code has its TOTP token (routers that do not seed MFA
// from the api session token take only that as proof), and a code is taken at any time after the login. The identity
// has the auth policy of test_auth.py: cert as primary and TOTP as secondary.
class TotpEnrolled : public ZitiTestCase {
protected:
    TotpEnrolled() {
        options.events |= ZitiPostureStatusEvent;
        REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));
    }

    std::vector<uint8_t> key;

    std::string code_now() const {
        char buf[8];
        snprintf(buf, sizeof(buf), "%06u", (unsigned) totp::generate(key, std::chrono::system_clock::now()));
        return std::string(buf);
    }

    struct answer {
        bool called{false};
        int status{ZITI_WTF};
    };

    int submit(ziti_context z, const char *code) {
        answer a;
        ziti_mfa_auth(z, code, [](ziti_context, int status, void *ctx) {
            auto *r = (answer *) ctx;
            r->called = true;
            r->status = status;
        }, &a);
        REQUIRE(run(UNTIL(a.called)));
        return a.status;
    }

    // another context of the identity: a login and an api session of its own
    struct login {
        bool loaded{false};
        ziti_auth_action action{};
        ziti_options options{};
        ziti_context ztx{};
    };

    void start_login(login &l) {
        l.options = ziti_options{
            .config_types = (const char **) ALL_CONFIGS,
            .app_ctx = &l,
            .events = ZitiContextEvent | ZitiAuthEvent,
            .event_cb = [](ziti_context z, const ziti_event_t *ev) {
                auto *l = (struct login *) ziti_app_ctx(z);
                if (ev->type == ZitiContextEvent && ev->ctx.ctrl_status == ZITI_OK) l->loaded = true;
                if (ev->type == ZitiAuthEvent) l->action = ev->auth.action;
            },
        };
        REQUIRE_ZITI_OK(ziti_context_init(&l.ztx, &config));
        REQUIRE_ZITI_OK(ziti_context_set_options(l.ztx, &l.options));
        REQUIRE_ZITI_OK(ziti_context_run(l.ztx, loop()));
    }

    void end_login(login &l) {
        ziti_shutdown(l.ztx);
        for (int i = 0; i < 20; i++) {
            uv_run(loop(), UV_RUN_NOWAIT);
        }
    }

    // how a dial of `service` ends (ZITI_OK: connected); the connection is closed again
    int dial(ziti_context z, const char *service) {
        struct dialed {
            bool done{false};
            int status{ZITI_WTF};
            bool closed{false};
        } d;

        ziti_connection conn{};
        ziti_conn_init(z, &conn, &d);
        int rc = ziti_dial(conn, service, [](ziti_connection c, int status) {
            auto *r = (dialed *) ziti_conn_data(c);
            r->done = true;
            r->status = status;
        }, nullptr);
        if (rc == ZITI_OK) {
            REQUIRE(run(UNTIL(d.done), 20000));
        } else {
            d.status = rc;
        }

        if (ziti_close(conn, [](ziti_connection c) { ((dialed *) ziti_conn_data(c))->closed = true; }) == ZITI_OK) {
            run(UNTIL(d.closed));
        }
        return d.status;
    }

    // The router reads the posture responses off the channel and applies them in a goroutine of its own, so a dial that
    // follows the TotpToken closely can still be refused ("MFA has never been passed"). Dials again for up to a second.
    int dial_after_totp_token(ziti_context z, const char *service) {
        int rc = dial(z, service);
        for (int i = 0; i < 5 && rc != ZITI_OK; i++) {
            uv_sleep(200);
            rc = dial(z, service);
        }
        return rc;
    }

    // enrols TOTP (the secret goes to `key`), then verifies the enrollment with the code of the authenticator
    void enroll_and_verify() {
        struct mfa {
            std::string link{};
            bool verified{false};
            bool cb_called{false};
        } mfa;

        ziti_mfa_enroll(ztx, [](ziti_context ztx, int status, ziti_mfa_enrollment *mfa_enrollment, void *ctx) {
            auto m = (struct mfa *) ctx;
            CHECK(status == ZITI_OK);
            if (mfa_enrollment) {
                m->link = mfa_enrollment->provisioning_url;
            }
        }, &mfa);
        REQUIRE(run(UNTIL(!mfa.link.empty())));
        key = totp::base32_decode(mfa.link.substr(mfa.link.find("secret=") + 7));

        for (int i = 0; i < 3 && !mfa.verified; i++) {
            mfa.cb_called = false;
            auto code = code_now();
            ziti_mfa_verify(ztx, code.c_str(), [](ziti_context ztx, int status, void *ctx) {
                auto m = (struct mfa *) ctx;
                m->cb_called = true;
                m->verified = (status == ZITI_OK);
            }, &mfa);
            REQUIRE(run(UNTIL(mfa.cb_called)));
            if (!mfa.verified) {
                uv_sleep(1000);
            }
        }
        REQUIRE(mfa.verified);
    }

    // login 1, the enrollment: ziti_mfa_verify() hands the first code to the login, which ends fully authenticated
    void enroll_and_login() {
        CHECK(load() == ZITI_PARTIALLY_AUTHENTICATED);
        if (authState.action == 0) {
            CHECK(run(WHILE(authState.action == 0)));
        }

        enroll_and_verify();
        REQUIRE(run(UNTIL(loaded && load_error == ZITI_OK)));
    }
};

TEST_CASE_METHOD(TotpEnrolled, "oidc-totp-token", "[totp]") {
    enroll_and_login();

    // the login that the code was handed to is over: the api session has its token, and the code is gone
    CHECK(run(UNTIL(*ztx_test_totp_token(ztx) != '\0')));
    CHECK(std::string(ztx_test_totp_code(ztx)).empty());

    // no login waits for a code now: a code is exchanged for a token
    CHECK(submit(ztx, code_now().c_str()) == ZITI_OK);
    CHECK(submit(ztx, "000000") == ZITI_MFA_INVALID_TOKEN);
    // a code that was turned down leaves the token that is there
    CHECK(*ztx_test_totp_token(ztx) != '\0');

    // login 2, a new context of the enrolled identity: the controller asks for the code, ziti_mfa_auth() gives it
    login second;
    start_login(second);

    REQUIRE(run(UNTIL(second.action == ziti_auth_prompt_totp)));
    CHECK(submit(second.ztx, code_now().c_str()) == ZITI_OK);
    REQUIRE(run(UNTIL(second.loaded)));
    CHECK(run(UNTIL(*ztx_test_totp_token(second.ztx) != '\0')));
    CHECK(std::string(ztx_test_totp_code(second.ztx)).empty());

    end_login(second);
}

// GH-1061, steps 1-4: an identity that logs in with its cert alone (nothing asks for a code) enrols MFA afterwards. No
// login waits for the code of the enrollment, so the REST calls take it, and that code buys the TOTP token: the controller
// passes the MFA of the session from then on, the routers that take only a token need it to agree. The identity has the
// default auth policy.
TEST_CASE_METHOD(TotpEnrolled, "oidc-totp-enroll-after-login", "[totp]") {
    REQUIRE(load() == ZITI_OK);
    CHECK(std::string(ztx_test_totp_token(ztx)).empty());

    enroll_and_verify();

    CHECK(run(UNTIL(*ztx_test_totp_token(ztx) != '\0')));
    CHECK(std::string(ztx_test_totp_code(ztx)).empty());
}

// GH-1061, GH-1170: TOTP is not part of the auth policy of the identity but of the dial policy of the service, as an MFA
// posture check (test_auth.py), and the routers decide that check from the TOTP token the SDK sends. The identity logs in
// with its cert alone, nothing asks for a code (it has no MFA yet), and the router turns the dial down. It enrols MFA then:
// the api session token cannot say that the MFA has passed (it has no amr=totp, the login had no TOTP step), so the
// code of the enrollment, exchanged for a TOTP token, is the only proof the router gets. An enrolled identity is
// asked for a code at every login: the next login answers it, and its api session has the token too.
TEST_CASE_METHOD(TotpEnrolled, "oidc-totp-posture-check", "[totp]") {
    const char *service = test_service();

    REQUIRE(load() == ZITI_OK);
    CHECK(dial(ztx, service) != ZITI_OK);

    // the app is told that the service has an MFA check that no code was given for, and that it has no timeout
    CHECK(run(UNTIL(postureStatus.mfa_events > 0)));
    CHECK(postureStatus.mfa_last_code_at == 0);
    CHECK(postureStatus.mfa_timeout == -1);

    enroll_and_verify();
    CHECK(run(UNTIL(*ztx_test_totp_token(ztx) != '\0')));
    CHECK_ZITI_OK(dial_after_totp_token(ztx, service));

    // and that a code was given just now
    CHECK(run(UNTIL(postureStatus.mfa_last_code_at != 0)));
    CHECK(std::llabs((long long) time(nullptr) - postureStatus.mfa_last_code_at) < 120);

    login second;
    start_login(second);
    DEFER { end_login(second); };

    REQUIRE(run(UNTIL(second.action == ziti_auth_prompt_totp)));
    CHECK(submit(second.ztx, code_now().c_str()) == ZITI_OK);
    REQUIRE(run(UNTIL(second.loaded)));
    CHECK_ZITI_OK(dial_after_totp_token(second.ztx, service));
}

// how often the SDK has said that the issuer of a token is not one it knows a signer by
static unsigned unmatched_issuer_warnings;
// how often the OIDC client has got a new token with its refresh token
static unsigned token_refreshes;

static void count_sdk_log_lines(int level, const char *loc, const char *msg, size_t len) {
    std::string line(msg, len);
    if (line.find("matches no known external signer") != std::string::npos) {
        unmatched_issuer_warnings++;
    }
    if (line.find("token refresh success") != std::string::npos) {
        token_refreshes++;
    }
    fprintf(stderr, "(log)[%d] %s %s\n", level, loc, line.c_str());
}

// The identity logs in with its cert, and its auth policy requires a token from an ext-jwt-signer as
// secondary auth: test_auth.py sets up the policy and passes the tokens as IDP_TOKEN (and IDP_TOKEN_NEXT).
class SecondaryExtJwt : public ZitiTestCase {
protected:
    SecondaryExtJwt() {
        unmatched_issuer_warnings = 0;
        token_refreshes = 0;
        ziti_log_set_logger(count_sdk_log_lines);
    }

    void login(const std::string &token) {
        // the cert is enough for a session, but not for a full one
        CHECK(load() == ZITI_PARTIALLY_AUTHENTICATED);

        // the SDK asks the app to log in with the signer of the policy
        REQUIRE(run(UNTIL(authState.count > 0)));
        REQUIRE(authState.action == ziti_auth_login_external);
        CHECK_FALSE(loaded);

        // the token comes from that login: here, straight from the IdP
        REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, token.c_str()));

        REQUIRE(run(UNTIL(loaded)));
        CHECK(load_error == ZITI_OK);
    }

    // Logs in with the short-lived `token` and waits until it has expired and the context asks for the
    // external login again: `logins` and `events` are what the app has seen up to that request.
    void wait_for_secondary_login(const std::string &token) {
        // poll the controller as an app does: the polling must not fight the wait for the login
        options.refresh_interval = 1;
        REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

        login(token);
        logins = authState.success;
        events = authState.count;

        // the polling finds out that the controller turns the requests down
        auto expiration = jwt_expiration(token);
        REQUIRE(run(UNTIL(time(nullptr) > expiration + 1), 15000));

        // the app is asked to log in with the external signer again
        REQUIRE(run(UNTIL(authState.action == ziti_auth_login_external && authState.count > events), 5000));
        events = authState.count;
    }

    // an app that has a token at hand: `answer` is given from the event that asks for the external login,
    // before the SDK is done with that event, once or (`answer_every_time`) to every such event
    static void answering_event_cb(ziti_context ztx, const ziti_event_t *ev) {
        event_cb(ztx, ev);
        auto self = (SecondaryExtJwt *) ziti_app_ctx(ztx);
        if (ev->type == ZitiAuthEvent && ev->auth.action == ziti_auth_login_external && !self->answer.empty()) {
            std::string token = self->answer;
            if (!self->answer_every_time) {
                self->answer.clear();
            }
            ziti_ext_auth_token(ztx, token.c_str());
        }
    }

    std::string answer;
    bool answer_every_time{};
    unsigned logins{};
    unsigned events{};
};

// GH-919
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt", "[integ][oidc-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");

    login(idp_token);
}

// The token the identity logged in with expires, but the external login has refreshed it by then: the
// controller wants the new one on the requests, the old one is a rejection. GH-1158
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-rotation", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string next = checkENV("IDP_TOKEN_NEXT");

    login(first);

    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));

    auto expiration = jwt_expiration(first);
    REQUIRE(run(UNTIL(time(nullptr) > expiration + 1), 15000));

    // a request of the context: when the controller turns it down the context authenticates again
    auto logins = authState.success;
    REQUIRE_ZITI_OK(ziti_refresh(ztx));
    CHECK_FALSE(run(UNTIL(authState.success > logins), 3000));
}

namespace {

// Holds the auth/context state as fixture members so it outlives ziti_shutdown():
// the shutdown callbacks may still deliver events, and app_ctx() points back here.
class PemCaTestCase : public LoopTestCase {
protected:
    ziti_context ztx{};
    struct {
        bool loaded{false};
        int load_error{ZITI_OK};
        unsigned auth_success{0};
    } state;

    static void event_cb(ziti_context ztx, const ziti_event_t *ev) {
        auto *self = static_cast<PemCaTestCase *>(ziti_app_ctx(ztx));
        switch (ev->type) {
        case ZitiContextEvent:
            self->state.load_error = ev->ctx.ctrl_status;
            if (ev->ctx.ctrl_status == ZITI_OK) {
                self->state.loaded = true;
            }
            break;
        case ZitiAuthEvent:
            if (ev->auth.action == ziti_auth_success) {
                self->state.auth_success++;
            }
            break;
        default:
            break;
        }
    }

    ~PemCaTestCase() {
        if (ztx != nullptr) {
            ziti_shutdown(ztx);
        }
    }
};

} // namespace

// GH-1146: identities enrolled by tools other than this SDK (e.g. the Go CLI)
// store the CA as a ref ("pem:-----BEGIN ..."), not bare PEM. ziti.c used to hand
// that raw string to the OIDC client; tlsuv then treated the "pem:" prefix as PEM,
// dropped the first (here: only) certificate and left an empty trust store, so the
// OIDC handshake failed and the context never authenticated. Driving a full context
// (not new_oidc_auth directly) is what exercises the ref resolution in ziti.c.
TEST_CASE_METHOD(PemCaTestCase, "oidc-pem-prefixed-ca", "[auth]") {
    auto *path = checkENV("test_client");

    ziti_config cfg{};
    DEFER { free_ziti_config(&cfg); };
    REQUIRE_ZITI_OK(ziti_load_config(&cfg, path));

    // reproduce the CA ref a CLI-enrolled identity carries
    std::string ca_ref = cfg.id.ca != nullptr ? cfg.id.ca : "";
    if (ca_ref.rfind("pem:", 0) != 0) {
        ca_ref = "pem:" + ca_ref;
    }
    free((void *) cfg.id.ca);
    cfg.id.ca = strdup(ca_ref.c_str());

    REQUIRE_ZITI_OK(ziti_context_init(&ztx, &cfg));

    ziti_options opts{};
    opts.config_types = (const char **) ALL_CONFIGS;
    opts.app_ctx = this;
    opts.events = ZitiContextEvent | ZitiAuthEvent;
    opts.event_cb = event_cb;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &opts));
    REQUIRE_ZITI_OK(ziti_context_run(ztx, loop()));

    // before the fix the OIDC TLS handshake has no trust anchor, auth retries
    // forever and this times out without a context event
    REQUIRE(run(UNTIL(state.loaded || state.load_error != ZITI_OK)));
    CHECK(state.load_error == ZITI_OK);
    CHECK(state.loaded);
    CHECK(state.auth_success > 0);
}

// The token the identity logged in with expires and nothing replaces it, as when the IdP session has ended:
// the controller wants the secondary auth again, and the context has to say so instead of carrying on as
// authenticated and re-authenticating in a loop. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-expired", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string next = checkENV("IDP_TOKEN_NEXT");

    wait_for_secondary_login(first);

    // and the context waits for it: not authenticated, not reporting success, and the polling does not
    // restart the authentication
    run(UNTIL(false), 2000);
    CHECK(authState.success == logins);
    CHECK(authState.count == events);
    CHECK(load_error != ZITI_OK);

    // a token that has expired is turned down, and nothing changes: the app is not asked again for the same
    // login it has just failed to give, and the context does not report success
    CHECK(ziti_ext_auth_token(ztx, first.c_str()) == ZITI_JWT_INVALID);
    CHECK(authState.count == events);
    CHECK(authState.success == logins);

    // the new token from that login completes the authentication, once
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 5000));
    CHECK_FALSE(run(UNTIL(authState.success > logins + 1), 2000));
}

// The app has a token at hand and gives it from the event that asks for it, before the SDK is done with that
// event: the authentication completes there, and once. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-expired-answered-in-event", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string next = checkENV("IDP_TOKEN_NEXT");

    options.refresh_interval = 1;
    options.event_cb = answering_event_cb;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(first);
    logins = authState.success;
    answer = next;

    // the polling finds out that the controller turns the requests down, and the new token is there at once
    auto expiration = jwt_expiration(first);
    REQUIRE(run(UNTIL(time(nullptr) > expiration + 1), 15000));
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 5000));
    CHECK_FALSE(run(UNTIL(authState.success > logins + 1), 2000));

    // and the app is not asked to log in after that: success is the last it hears
    CHECK(authState.action == ziti_auth_success);
}

// The app gives the token it has, which has expired too, to every request for the login. Turned down each time, it
// must not send the SDK round in circles: the app is asked, and the context waits. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-expired-answered-with-expired", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived

    options.refresh_interval = 1;
    options.event_cb = answering_event_cb;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(first);
    logins = authState.success;
    events = authState.count;
    answer = first;
    answer_every_time = true;

    auto expiration = jwt_expiration(first);
    REQUIRE(run(UNTIL(time(nullptr) > expiration + 1), 15000));
    REQUIRE(run(UNTIL(authState.count > events), 5000));

    // the requests are over, and the context waits
    run(UNTIL(false), 2000);
    auto count = authState.count;
    run(UNTIL(false), 2000);
    CHECK(authState.count == count);
    CHECK(authState.success == logins);
    CHECK(load_error != ZITI_OK);
}

// The controller turns down a token that has not expired (the signature does not verify; a revoked token or a clock that
// is off do as well). The context cannot tell from the 401, and the re-authentication that follows succeeds without a new
// token: a loop. It asks the controller what is missing, and that is the external login. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-rejected", "[integ][oidc-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");
    std::string next = checkENV("IDP_TOKEN_NEXT");
    std::string rejected = checkENV("IDP_TOKEN_BAD_SIGNATURE");

    options.refresh_interval = 1;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(idp_token);
    logins = authState.success;
    events = authState.count;

    // the app gives the token of its login, and it is the one the controller gets from now on
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, rejected.c_str()));

    // the polling finds out that the controller turns it down: the app is asked to log in with the external signer again
    REQUIRE(run(UNTIL(authState.action == ziti_auth_login_external && authState.count > events), 5000));
    events = authState.count;

    // and the context waits for it: not authenticated, not reporting success, not authenticating again
    run(UNTIL(false), 2000);
    CHECK(authState.success == logins);
    CHECK(authState.count == events);
    CHECK(load_error != ZITI_OK);

    // the token that was turned down is not what is waited for: it is turned down again, and nothing changes
    CHECK(ziti_ext_auth_token(ztx, rejected.c_str()) == ZITI_JWT_INVALID);
    CHECK(authState.count == events);
    CHECK(authState.success == logins);

    // the new token from that login completes the authentication, once
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 5000));
    CHECK_FALSE(run(UNTIL(authState.success > logins + 1), 2000));

    // the tokens are the signer's own: there is nothing to say about their issuer
    CHECK(unmatched_issuer_warnings == 0);
}

// The SDK knows the signer by where its IdP is (test_auth.py sets that to somewhere else than the issuer of the tokens, which
// is what the controller knows it by), so it cannot tell whose token is whose. It says so once, and it leaves the decision
// to the controller: the controller turns the token down, and the one that completes the login is not one the SDK takes
// for the signer's. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-issuer-differs", "[integ][oidc-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");
    std::string next = checkENV("IDP_TOKEN_NEXT");
    std::string rejected = checkENV("IDP_TOKEN_BAD_SIGNATURE");

    options.refresh_interval = 1;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(idp_token);
    CHECK(unmatched_issuer_warnings == 1);
    logins = authState.success;
    events = authState.count;

    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, rejected.c_str()));
    REQUIRE(run(UNTIL(authState.action == ziti_auth_login_external && authState.count > events), 5000));
    events = authState.count;

    // the issuer is the same, and has been said
    CHECK(unmatched_issuer_warnings == 1);

    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 5000));
    CHECK_FALSE(run(UNTIL(authState.success > logins + 1), 2000));
}

// The api session is no good to the controller any more (it is gone): that says nothing about the secondary token, the
// controller wants no external login, and the context authenticates again as it always did. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-session-lost", "[integ][oidc-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");

    options.refresh_interval = 1;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(idp_token);
    logins = authState.success;

    // what the controller client sends from now on is not a session
    ziti_ctrl_set_token(ztx_get_controller(ztx), "not-a-session-token");

    // the polling is turned down, the controller has no query for the context, and it authenticates again
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 10000));
    CHECK(authState.action == ziti_auth_success);
}

// The app gives the token it has, which the controller has just turned down, to every request for the login. That must
// not send the context round in circles either (login, requests turned down, login...): the app is asked, and the
// context waits. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-rejected-answered-with-rejected", "[integ][oidc-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");
    std::string rejected = checkENV("IDP_TOKEN_BAD_SIGNATURE");

    options.refresh_interval = 1;
    options.event_cb = answering_event_cb;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(idp_token);
    logins = authState.success;
    events = authState.count;
    answer = rejected;
    answer_every_time = true;

    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, rejected.c_str()));
    REQUIRE(run(UNTIL(authState.count > events), 5000));

    // the requests are over, and the context waits
    run(UNTIL(false), 2000);
    auto count = authState.count;
    run(UNTIL(false), 2000);
    CHECK(authState.count == count);
    CHECK(authState.success == logins);
    CHECK(load_error != ZITI_OK);
}

// Every success the context reports is put to the controller: the services are requested from inside the event, with
// the auth the context has just declared good (a request made later could see a wait that has started over since).
//
// What the callbacks leave behind is not in the fixture: the callbacks of the requests still in flight get called when
// ziti_shutdown() and the draining of the loop run, in the destructors of its bases, after its members are gone.
static unsigned service_events;
static unsigned services_responses;
static std::vector<std::string> services_errors;

class SecondaryExtJwtVerified : public SecondaryExtJwt {
protected:
    SecondaryExtJwtVerified() {
        service_events = 0;
        services_responses = 0;
        services_errors.clear();
        options.event_cb = verifying_event_cb;
        options.events |= ZitiServiceEvent;
    }

    static void verifying_event_cb(ziti_context ztx, const ziti_event_t *ev) {
        event_cb(ztx, ev);
        if (ev->type == ZitiServiceEvent) {
            service_events++;
        }
        if (ev->type == ZitiAuthEvent && ev->auth.action == ziti_auth_success) {
            ziti_ctrl_get_services(ztx_get_controller(ztx), services_cb, nullptr);
        }
    }

    static void services_cb(ziti_service_array services, const ziti_error *err, void *ctx) {
        if (err) {
            services_errors.push_back(std::string(err->code ? err->code : "") + "/" + (err->message ? err->message : ""));
        }
        free_ziti_service_array(&services);
        services_responses++;
    }

    // wait for answers to the /services requests of every "successful" auth so far. return the errors from the failed requests
    std::vector<std::string> verify() {
        REQUIRE(run(UNTIL(services_responses == authState.success), 5000));
        return services_errors;
    }
};

// The context waits for the login after the controller turned down a token that has not expired, and the auth method
// refreshes its api session token meanwhile, as it does on its timer. The refresh succeeds (the controller does not ask
// for the external token on a refresh), but the token the controller turned down is still all the context has: the
// refresh must not end the wait and report success. GH-1159
TEST_CASE_METHOD(SecondaryExtJwtVerified, "oidc-secondary-ext-jwt-rejected-refreshed", "[integ][oidc-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");
    std::string next = checkENV("IDP_TOKEN_NEXT");
    std::string rejected = checkENV("IDP_TOKEN_BAD_SIGNATURE");

    options.refresh_interval = 1;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(idp_token);
    REQUIRE(authState.success == 1);
    REQUIRE(verify().empty());

    // let the first load of the services finish: a /services request that's still out when the token is rejected
    // triggers re-auth, which is not what this is about
    REQUIRE(run(UNTIL(service_events > 0), 5000));
    logins = authState.success;
    events = authState.count;

    // use the bad-signature token, and wait until the context asks for login_external.
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, rejected.c_str()));
    REQUIRE(run(UNTIL(authState.action == ziti_auth_login_external && authState.count > events), 5000));
    run(UNTIL(false), 1000);
    events = authState.count;

    // trigger oidc_client_refresh without waiting for the token lifetime: the refresh has to get its token,
    // or what follows would pass for a refresh that never happened
    auto refreshes = token_refreshes;
    ziti_force_api_session_refresh(ztx);
    REQUIRE(run(UNTIL(token_refreshes > refreshes), 5000));
    run(UNTIL(false), 2000);

    // every successful auth the SDK reports is used to make a /services request
    auto failures = verify();
    INFO("successes reported after the refresh: " << authState.success - logins
         << ", turned down by the controller: " << failures.size()
         << (failures.empty() ? "" : ", first: " + failures.front()));
    REQUIRE(failures.empty());

    // no successful logins should be reported
    REQUIRE(authState.success == logins);
    CHECK(authState.count == events);
    CHECK(authState.action == ziti_auth_login_external);
    CHECK(load_error != ZITI_OK);

    // the new token from that login completes the authentication, once, and the controller takes the requests
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 5000));
    CHECK_FALSE(run(UNTIL(authState.success > logins + 1), 2000));
    CHECK_THAT(verify(), Catch::Matchers::IsEmpty());
}

// The secondary token expired and the context is waiting for the external login. A refresh of the api session token
// (as the auth method's timer does) must not prompt the app for the login again: it already has been, once. GH-1159
TEST_CASE_METHOD(SecondaryExtJwtVerified, "oidc-secondary-ext-jwt-expired-refreshed", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string next = checkENV("IDP_TOKEN_NEXT");

    // log in with the short-lived token, and wait until it expires and the context asks for login_external
    wait_for_secondary_login(first);
    run(UNTIL(false), 1000);
    events = authState.count;

    // trigger oidc_client_refresh without waiting for the token lifetime: the refresh has to get its token,
    // or what follows would pass for a refresh that never happened
    auto refreshes = token_refreshes;
    ziti_force_api_session_refresh(ztx);
    REQUIRE(run(UNTIL(token_refreshes > refreshes), 5000));
    run(UNTIL(false), 2000);

    // no new prompt for the login, and no success
    INFO("auth events after the refresh: " << authState.count - events
         << ", successes: " << authState.success - logins);
    REQUIRE(authState.count == events);
    REQUIRE(authState.success == logins);
    CHECK(authState.action == ziti_auth_login_external);
    CHECK(load_error != ZITI_OK);

    // the new token from that login completes the authentication, once, and the controller takes the requests
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 5000));
    CHECK_FALSE(run(UNTIL(authState.success > logins + 1), 2000));
    CHECK_THAT(verify(), Catch::Matchers::IsEmpty());
}

// what the SDK has logged about /current-identity requests rejected during the wait for the external login
static bool late_unauthorized_waiting;
static unsigned late_unauthorized_identity_401s;

static void late_unauthorized_logger(int level, const char *loc, const char *msg, size_t len) {
    std::string line(msg, len);
    if (line.find("waiting for the external login") != std::string::npos) {
        late_unauthorized_waiting = true;
    }
    if (late_unauthorized_waiting && line.find("failed to get identity_data") != std::string::npos) {
        late_unauthorized_identity_401s++;
    }
    count_sdk_log_lines(level, loc, msg, len);
}

// The controller starts rejecting a secondary token that has not expired (revoked, signing key rotated), and an api
// session refresh is what finds out: the refresh succeeds (the controller does not check the external token on a
// refresh) and the SDK reports success, as on every refresh. It sends /current-identity, whose 401 starts the wait, and
// /current-api-session, whose answer sends another /current-identity behind ztx_unauthorized's check. That 401 arrives
// during the wait. It is the same rejection, not a lost api session: the context must keep waiting, not re-authenticate
// and report a success the controller doesn't accept. GH-1159
TEST_CASE_METHOD(SecondaryExtJwtVerified, "oidc-secondary-ext-jwt-rejected-late-unauthorized", "[integ][oidc-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");
    std::string next = checkENV("IDP_TOKEN_NEXT");
    std::string rejected = checkENV("IDP_TOKEN_BAD_SIGNATURE");

    // no background polling (the SDK default): nothing finds out about the bad token until the refresh
    options.refresh_interval = 0;
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));

    login(idp_token);
    REQUIRE(authState.success == 1);
    REQUIRE(verify().empty());
    REQUIRE(run(UNTIL(service_events > 0), 5000));
    events = authState.count;

    late_unauthorized_waiting = false;
    late_unauthorized_identity_401s = 0;
    ziti_log_set_logger(late_unauthorized_logger);

    // the controller rejects the token from now on, and nothing has noticed yet
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, rejected.c_str()));
    run(UNTIL(false), 1000);
    REQUIRE(authState.count == events);

    // the api session token is refreshed, as the timer of the auth method does it: it reports success (the SDK cannot
    // know yet), and the requests that follow find out and start the wait for the login
    auto refreshes = token_refreshes;
    ziti_force_api_session_refresh(ztx);
    REQUIRE(run(UNTIL(token_refreshes > refreshes), 5000));
    REQUIRE(run(UNTIL(authState.action == ziti_auth_login_external), 5000));
    logins = authState.success;
    events = authState.count;
    auto expected_failures = verify().size();

    // a 401 has to arrive during the wait, or the test checks nothing
    REQUIRE(run(UNTIL(late_unauthorized_identity_401s > 0), 5000));
    run(UNTIL(false), 2000);

    // no success after the wait started: every one the SDK reports gets a /services request, and the controller rejects them
    auto failures = verify();
    INFO("successes reported after the wait started: " << authState.success - logins
         << ", turned down by the controller: " << failures.size() - expected_failures
         << (failures.size() == expected_failures ? "" : ", first: " + failures[expected_failures]));
    REQUIRE(authState.success == logins);
    CHECK(failures.size() == expected_failures);

    // still waiting for the login, without asking again
    CHECK(authState.count == events);
    CHECK(authState.action == ziti_auth_login_external);

    // the new token from that login completes the authentication, once, and the controller takes the requests
    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));
    REQUIRE(run(UNTIL(authState.success == logins + 1 && load_error == ZITI_OK), 5000));
    CHECK_FALSE(run(UNTIL(authState.success > logins + 1), 2000));
    CHECK(verify().size() == expected_failures);
}

// A token of another issuer is not the one that is waited for: it must not make the context ask again, and the
// login that is going on is not over. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-expired-other-issuer", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string other = checkENV("IDP_TOKEN_OTHER_ISSUER");

    wait_for_secondary_login(first);

    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, other.c_str()));
    CHECK(authState.count == events);
    CHECK(authState.success == logins);

    // the controller is asked whether that token is what it waits for, and it is not (it knows no signer of that
    // issuer): the wait goes on
    run(UNTIL(false), 2000);
    CHECK(authState.count == events);
    CHECK(authState.success == logins);
    CHECK(load_error != ZITI_OK);
}

// The login the context waits for is not the one that is going on any more: the auth method starts over (its refresh
// token is gone) and the controller asks for something else, a TOTP. A token of the secondary signer that arrives then
// belongs to that login: the SDK must not take it as the end of the wait, with the session token it had. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-expired-login-restarted", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string next = checkENV("IDP_TOKEN_NEXT");

    wait_for_secondary_login(first);

    // as the auth method reports it
    ziti_auth_query_mfa totp = ZITI_MFA;
    totp.enrolled = true;
    ztx_auth_state_cb(ztx, ZitiAuthStatePartiallyAuthenticated, &totp);
    REQUIRE(authState.action == ziti_auth_prompt_totp);

    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, next.c_str()));
    CHECK(authState.success == logins);
    CHECK(load_error != ZITI_OK);
}
