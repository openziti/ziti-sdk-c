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
#include <tlsuv/tlsuv.h>
#include <ziti/ziti.h>
#include <ziti/zitilib.h>

#include "fixtures.h"
#include "oidc.h"
#include "test-data.h"
#include "totp.h"
#include "ziti/ziti_log.h"

// the SDK's own callback for the state of the authentication, which the auth method calls
extern "C" void ztx_auth_state_cb(void *ctx, ziti_auth_state state, const void *data);

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

// The identity logs in with its cert, and its auth policy requires a token from an ext-jwt-signer as
// secondary auth: test_auth.py sets up the policy and passes the tokens as IDP_TOKEN (and IDP_TOKEN_NEXT).
class SecondaryExtJwt : public ZitiTestCase {
protected:
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

// A token of another issuer is not the one that is waited for: it must not make the context ask again, and the
// login that is going on is not over. GH-1159
TEST_CASE_METHOD(SecondaryExtJwt, "oidc-secondary-ext-jwt-expired-other-issuer", "[integ][oidc-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string other = checkENV("IDP_TOKEN_OTHER_ISSUER");

    wait_for_secondary_login(first);

    REQUIRE_ZITI_OK(ziti_ext_auth_token(ztx, other.c_str()));
    CHECK(authState.count == events);
    CHECK(authState.success == logins);
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
