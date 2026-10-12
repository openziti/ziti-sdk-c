// Copyright (c) 2019-2026.  NetFoundry Inc
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

#include "fixtures.h"

#include <iostream>
#include <ziti/ziti.h>
#include <ziti_ctrl.h>
#include "credentials.h"
#include <utils.h>

#include "test-data.h"

static const char *const SERVICE_NAME = TEST_SERVICE;

// Reads as "not a ziti controller". The `.invalid` TLD is reserved by RFC 6761
// and is guaranteed never to resolve, so the dial always fails.
static const char *const INVALID_CTRL_URL = "https://not.a.ziti.controller.invalid";

using namespace std;
using namespace Catch::Matchers;


TEST_CASE("invalid_controller", "[controller][GH-44]") {
    ziti_controller ctrl;
    uv_loop_t *loop = uv_default_loop();
    resp_capture<ziti_version*> version;

    PREP(ziti);
    model_list endpoints = {nullptr};
    model_list_append(&endpoints, (void*)INVALID_CTRL_URL);
    TRY(ziti, ziti_ctrl_init(loop, &ctrl, &endpoints, nullptr));
    model_list_clear(&endpoints, nullptr);

    WHEN("get version") {
        ziti_ctrl_get_version(&ctrl, resp_cb, &version);
        uv_run(loop, UV_RUN_DEFAULT);

        THEN("callback with proper error") {
            REQUIRE(version.error.err != 0);
            REQUIRE_THAT(version.error.code, Equals("CONTROLLER_UNAVAILABLE"));
        }
    }

    CATCH(ziti) {
        FAIL("unexpected error");
    }

    ziti_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
}

TEST_CASE("controller_test","[integ]") {
    const char *conf = TEST_CLIENT;

    ziti_config config{};
    tls_credentials creds{};
    tls_context *tls = nullptr;
    ziti_controller ctrl{};
    uv_loop_t *loop = uv_default_loop();

    REQUIRE(ziti_load_config(&config, conf) == ZITI_OK);
    REQUIRE(load_tls(&config, &tls, &creds) == ZITI_OK);
    REQUIRE(ziti_ctrl_init(loop, &ctrl, &config.controllers, tls) == ZITI_OK);
    ziti_ctrl_set_legacy(&ctrl, true);

    resp_capture<ziti_version*> version;
    resp_capture<ziti_api_session*> session;
    resp_capture<ziti_service*> service;

    WHEN("get version and login") {
        auto v = ctrl_get(ctrl, ziti_ctrl_get_version);
        REQUIRE(v != nullptr);

        auto v1 = (const char*)model_map_get(&v->api_versions->edge, "v1");
        CHECK(v1 != nullptr);

        auto auth = new_legacy_auth(loop, config.controller_url, tls, true);
        auto token = auth_login(auth, loop);
        CHECK(!token.empty());
        auth->free(auth);
    }

    WHEN("try to get services before login") {
        REQUIRE_THROWS(ctrl_get1(ctrl, ziti_ctrl_get_service, SERVICE_NAME));
    }

    WHEN("try to login and get non-existing service") {
        ziti_auth_method_t *auth = new_legacy_auth(loop, config.controller_url, tls, true);
        auto api_sesh = auth_login(auth, loop);
        ziti_ctrl_set_token(&ctrl, api_sesh.c_str());
        auto s = ctrl_get1(ctrl, ziti_ctrl_get_service, "this-service-should-not-exist");
        THEN("should NOT get non-existent service") {
            CHECK(s == nullptr);
        }
    }

    WHEN("try to login, get service, and session") {
        ziti_auth_method_t *auth = new_legacy_auth(loop, config.controller_url, tls, true);
        auto token = auth_login(auth, loop);
        ziti_ctrl_set_token(&ctrl, token.c_str());

        auto services = ctrl_get(ctrl, ziti_ctrl_get_services);
        ziti_service *s = services[0];

        THEN("should get service") {
            REQUIRE(s != nullptr);
        }AND_THEN("should get api_session") {
            auto ns = ctrl_get2(ctrl, ziti_ctrl_create_session, (const char *) s->id, *s->permissions[0]);
            REQUIRE(ns != nullptr);
            REQUIRE(ns->token != nullptr);
            free_ziti_session_ptr(ns);
            free_ziti_service_array(&services);
        }

        auth->stop(auth);
        auth->free(auth);
    }

    free_ziti_version(version.resp);
    free_ziti_api_session(session.resp);

    ziti_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
    tls->free_ctx(tls);
    free_ziti_config(&config);
}

TEST_CASE("ztx-legacy-auth", "[integ]") {
    const char *zid = TEST_CLIENT;

    ziti_config cfg;
    REQUIRE(ziti_load_config(&cfg, zid) == ZITI_OK);

    ziti_context ztx;
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);

    struct test_context_s {
        int event;
        std::string data;
    } test_context = {
        .event = 0,
    };


    ziti_options opts = {};
    opts.app_ctx = &test_context;
    opts.events = ZitiContextEvent;
    opts.event_cb = [](ziti_context ztx, const ziti_event_t *event){
            printf("got event: %d => %s \n", event->type, event->ctx.err);
            auto test_ctx = (test_context_s*)ziti_app_ctx(ztx);
            test_ctx->event = event->type;
        };

    ziti_context_set_options(ztx, &opts);

    auto l = uv_loop_new();
    ziti_context_run(ztx, l);

    while (test_context.event == 0) {
        uv_run(l, UV_RUN_ONCE);
    }

    ziti_shutdown(ztx);
    uv_run(l, UV_RUN_DEFAULT);

    free_ziti_config(&cfg);
}

// The identity logs in with its cert, and its auth policy requires a token from an ext-jwt-signer as
// secondary auth: test_auth.py sets up the policy and passes the tokens as IDP_TOKEN (and IDP_TOKEN_NEXT).
//
// ziti_context picks the legacy method only for a controller without OIDC, which the test controller
// is not. The controller serves /authenticate all the same, so these drive the method itself.
class LegacySecondaryAuth : public LoopTestCase {
protected:
    struct auth_result {
        ziti_auth_method_t *auth{};
        const std::string *token{};  // set when the callback is to give it to the method
        bool ext_jwt_requested{false};
        std::string api_session;
        std::string error;
    } result;

    ziti_config config{};
    tls_credentials creds{};
    tls_context *tls{};
    ziti_auth_method_t *auth{};

    // not in the constructor: the destructor of an object whose constructor threw does not run
    void init() {
        REQUIRE(ziti_load_config(&config, TEST_CLIENT) == ZITI_OK);
        REQUIRE(load_tls(&config, &tls, &creds) == ZITI_OK);
        auth = new_legacy_auth(loop(), config.controller_url, tls, true);
        result.auth = auth;
    }

    void start() {
        auth->start(auth, [](void *ctx, ziti_auth_state state, const void *data) {
            auto *r = static_cast<auth_result *>(ctx);
            switch (state) {
                case ZitiAuthStatePartiallyAuthenticated: {
                    auto *query = static_cast<const ziti_auth_query_mfa *>(data);
                    r->ext_jwt_requested = query->type_id == ziti_auth_query_type_EXT_JWT;
                    if (r->ext_jwt_requested && r->token) {
                        r->auth->set_ext_jwt(r->auth, r->token->c_str());
                    }
                    break;
                }
                case ZitiAuthStateFullyAuthenticated:
                    r->api_session = static_cast<const char *>(data);
                    break;
                case ZitiAuthStateUnauthenticated:
                case ZitiAuthImpossibleToAuthenticate:
                    r->error = static_cast<const ziti_error *>(data)->message;
                    break;
                default:
                    break;
            }
        }, &result);
    }

    ~LegacySecondaryAuth() {
        if (auth) {
            auth->stop(auth);
            auth->free(auth);
        }
        zt_x509_drop(&creds);
        if (tls) {
            tls->free_ctx(tls);
        }
        free_ziti_config(&config);
    }
};

// GH-919
TEST_CASE_METHOD(LegacySecondaryAuth, "legacy-secondary-ext-jwt", "[integ][legacy-secondary]") {
    std::string idp_token = checkENV("IDP_TOKEN");
    // the token comes from the external login, usually after the auth callback has returned, but an app
    // may also answer the auth event with it right away, or already hold it from an earlier login
    enum Delivery { AfterCallback, FromCallback, BeforeLogin };
    auto delivery = GENERATE(AfterCallback, FromCallback, BeforeLogin);
    INFO("token delivery: " << delivery);

    init();
    if (delivery == FromCallback) {
        result.token = &idp_token;
    }
    if (delivery == BeforeLogin) {
        REQUIRE(auth->set_ext_jwt(auth, idp_token.c_str()) == ZITI_OK);
    }
    start();

    if (delivery != BeforeLogin) {
        // the cert is enough for a session, but not for a full one
        REQUIRE(run(UNTIL(result.ext_jwt_requested || !result.error.empty() || !result.api_session.empty())));
        INFO("error: " << result.error);
        REQUIRE(result.ext_jwt_requested);
        if (delivery == AfterCallback) {
            CHECK(result.api_session.empty());
            REQUIRE(auth->set_ext_jwt(auth, idp_token.c_str()) == ZITI_OK);
        }
    }

    REQUIRE(run(UNTIL(!result.api_session.empty() || !result.error.empty())));
    INFO("error: " << result.error);
    CHECK(result.error.empty());
    REQUIRE_FALSE(result.api_session.empty());
    if (delivery == BeforeLogin) {
        // the authentication request carried the token: the controller had nothing to ask for
        CHECK_FALSE(result.ext_jwt_requested);
    }

    // a refresh of the session carries the token as well: without it the controller asks for it again
    result.ext_jwt_requested = false;
    REQUIRE(auth->force_refresh(auth) == 0);
    CHECK_FALSE(run(UNTIL(result.ext_jwt_requested || !result.error.empty()), 2000));
    CHECK(result.error.empty());
}

// The token the identity logged in with expires, but the external login has refreshed it by then: the
// controller wants the new one on the requests, the old one is a rejection. GH-1158
TEST_CASE_METHOD(LegacySecondaryAuth, "legacy-secondary-ext-jwt-rotation", "[integ][legacy-secondary]") {
    std::string first = checkENV("IDP_TOKEN");  // short-lived
    std::string next = checkENV("IDP_TOKEN_NEXT");

    init();
    start();

    REQUIRE(run(UNTIL(result.ext_jwt_requested || !result.error.empty() || !result.api_session.empty())));
    INFO("error: " << result.error);
    REQUIRE(result.ext_jwt_requested);
    REQUIRE(auth->set_ext_jwt(auth, first.c_str()) == ZITI_OK);
    REQUIRE(run(UNTIL(!result.api_session.empty() || !result.error.empty())));
    REQUIRE_FALSE(result.api_session.empty());

    REQUIRE(auth->set_ext_jwt(auth, next.c_str()) == ZITI_OK);

    auto expiration = jwt_expiration(first);
    REQUIRE(run(UNTIL(time(nullptr) > expiration + 1), 15000));

    // the refresh of the session is what tells the controller which token the identity has now
    result.ext_jwt_requested = false;
    REQUIRE(auth->force_refresh(auth) == 0);
    CHECK_FALSE(run(UNTIL(result.ext_jwt_requested || !result.error.empty()), 2000));
    CHECK(result.error.empty());
}
