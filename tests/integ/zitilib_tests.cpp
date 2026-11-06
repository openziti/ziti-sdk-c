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


#include <catch2/catch_all.hpp>

#include <memory>

#include "fixtures.h"
#include <ziti/zitilib.h>


TEST_CASE_METHOD(ZitilibTestCase, "zitilib: init", "[zitilib]") {
    auto error = Ziti_last_error();
    INFO("error: " << error << ": " << ziti_errorstr(error));
    REQUIRE(error == ZITI_OK);
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load context", "[zitilib]") {
    auto params = GENERATE(
        std::pair((const char*)nullptr, ZITI_INVALID_CONFIG),
        std::pair("invalid", ZITI_CONFIG_NOT_FOUND),
        std::pair(getenv("test_client"), ZITI_OK)
        );

    WHEN("context: " << (params.first ? params.first : "(null)")) {
        ziti_handle_t ztx{};
        auto error = Ziti_load_context(&ztx, params.first);
        INFO("error[" << (params.first ? params.first : "(null)") << "]: " << error << "/" << ziti_errorstr(error));
        CHECK(error == params.second);
        CHECK(Ziti_last_error() == params.second);
        if (params.second == ZITI_OK) {
            CHECK(ztx != ZITI_INVALID_HANDLE);
        } else {
            CHECK(ztx == ZITI_INVALID_HANDLE);
        }
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load after shutdown", "[zitilib]") {
    Ziti_lib_shutdown();
    ziti_handle_t ztx{};
    auto cfg = checkENV("test_client");
    WHEN("with timeout") {
        auto error = Ziti_load_context_with_timeout(&ztx, cfg, 1000);
        INFO("error: " << error << "/" << ziti_errorstr(error));
        CHECK(error == ZITI_INVALID_STATE);
        CHECK(Ziti_last_error() == ZITI_INVALID_STATE);
    }
    WHEN("without timeout") {
        auto error = Ziti_load_context(&ztx, cfg);
        INFO("error: " << error << "/" << ziti_errorstr(error));
        CHECK(error == ZITI_INVALID_STATE);
        CHECK(Ziti_last_error() == ZITI_INVALID_STATE);
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load context with timeout", "[zitilib]") {
    auto params = GENERATE(
        std::tuple((const char*)nullptr, -1, ZITI_INVALID_CONFIG),
        std::tuple("invalid", -1, ZITI_CONFIG_NOT_FOUND),
        std::tuple(getenv("test_client"), 2000, ZITI_OK),
        std::tuple(getenv("test_client"), 1, ZITI_TIMEOUT)
        );

    WHEN("context[" << (std::get<0>(params) ? std::get<0>(params) : "(null)")
                    << "] with timeout[" << std::get<1>(params) << "]") {
        ziti_handle_t ztx{};
        auto error = Ziti_load_context_with_timeout(&ztx, std::get<0>(params), std::get<1>(params));
        INFO("error: " << error << "/" << ziti_errorstr(error));
        CHECK(error == std::get<2>(params));
        CHECK(Ziti_last_error() == std::get<2>(params));
        if (std::get<2>(params) == ZITI_OK) {
            CHECK(ztx != ZITI_INVALID_HANDLE);
        } else {
            CHECK(ztx == ZITI_INVALID_HANDLE);
        }
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: enroll with idp and login with token reject missing arguments", "[zitilib]") {
    char *id = nullptr;
    unsigned long len = 0;
    const char *url = "https://127.0.0.1:1"; // never contacted: the arguments are checked first

    CHECK(Ziti_enroll_with_idp(nullptr, ziti_enroll_token, "token", &id, &len) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_with_idp("", ziti_enroll_token, "token", &id, &len) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_with_idp(url, ziti_enroll_token, "token", nullptr, &len) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_with_idp(url, ziti_enroll_token, "token", &id, nullptr) == ZITI_INVALID_STATE);

    CHECK(Ziti_login_with_token(ZITI_INVALID_HANDLE, "token") == ZITI_INVALID_STATE);
    auto ztx = loadContext(checkENV("test_client"));
    CHECK(Ziti_login_with_token(ztx, nullptr) == ZITI_INVALID_STATE);
}

// What an app that holds an external token does (a CI job with the OIDC token of its workflow, e.g. a Python
// hook through the zitilib bindings): no signer to select, no browser to open. The signer that trusts the
// token's issuer enrolls to a token, so the first use of the token creates the identity.
// Env, set by the pytest that has the token: IDP_TOKEN, NETWORK_JWT (the controller is not publicly trusted,
// so the network JWT stands for it).
TEST_CASE_METHOD(ZitilibTestCase, "zl-enroll-token-login", "[integ][zl-token]") {
    std::string token = checkENV("IDP_TOKEN");
    std::string network_jwt = checkENV("NETWORK_JWT");

    char *cfg = nullptr;
    unsigned long cfg_len = 0;
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, token.c_str(), &cfg, &cfg_len);
    std::unique_ptr<char, decltype(&free)> id_json(cfg, free);
    INFO("enroll: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);
    REQUIRE(cfg_len > 0);

    // enrolled to a token: the identity has no cert, the token is its login
    ziti_handle_t ztx = ZITI_INVALID_HANDLE;
    rc = Ziti_load_context(&ztx, id_json.get());
    INFO("load: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_EXTERNAL_LOGIN_REQUIRED);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);

    // a token that cannot be used is turned down at once, and the context keeps waiting for a login
    CHECK(Ziti_login_with_token(ztx, "not a jwt") == ZITI_JWT_INVALID);

    // the SDK copies the token: the app may discard its string once the call returns
    std::string login_token = token;
    rc = Ziti_login_with_token(ztx, login_token.c_str());
    INFO("login: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);
    login_token.assign(login_token.size(), 'x');

    rc = Ziti_wait_for_auth(ztx, 30000);
    INFO("wait for auth: " << rc << "/" << ziti_errorstr(rc));
    CHECK(rc == ZITI_OK);
}

// The same app, with a signer that enrolls to a cert: the controller signs a CSR for the token, and the
// identity it gets can log in on its own, without the token. Same env as zl-enroll-token-login.
TEST_CASE_METHOD(ZitilibTestCase, "zl-enroll-cert-login", "[integ][zl-token]") {
    std::string token = checkENV("IDP_TOKEN");
    std::string network_jwt = checkENV("NETWORK_JWT");

    char *cfg = nullptr;
    unsigned long cfg_len = 0;
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_cert, token.c_str(), &cfg, &cfg_len);
    std::unique_ptr<char, decltype(&free)> id_json(cfg, free);
    INFO("enroll: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);
    REQUIRE(cfg_len > 0);

    ziti_config id{};
    REQUIRE(ziti_load_config(&id, id_json.get()) == ZITI_OK);
    CHECK(id.id.cert != nullptr);
    CHECK(id.id.key != nullptr);
    free_ziti_config(&id);

    // the cert is the login: no external login is asked for
    ziti_handle_t ztx = ZITI_INVALID_HANDLE;
    rc = Ziti_load_context(&ztx, id_json.get());
    INFO("load: " << rc << "/" << ziti_errorstr(rc));
    CHECK(rc == ZITI_OK);
    CHECK(ztx != ZITI_INVALID_HANDLE);
}

// The network JWT stands for the controller, and in mode none there is no idp: the result is the bootstrap config.
TEST_CASE_METHOD(ZitilibTestCase, "zl-enroll-none-bootstrap", "[integ][zl-token]") {
    std::string network_jwt = checkENV("NETWORK_JWT");

    char *cfg = nullptr;
    unsigned long cfg_len = 0;
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_none, nullptr, &cfg, &cfg_len);
    std::unique_ptr<char, decltype(&free)> id_json(cfg, free);
    INFO("enroll: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);

    ziti_config bootstrap{};
    REQUIRE(ziti_load_config(&bootstrap, id_json.get()) == ZITI_OK);
    CHECK(bootstrap.controller_url != nullptr);
    CHECK(bootstrap.id.ca != nullptr);
    CHECK(bootstrap.id.cert == nullptr);
    free_ziti_config(&bootstrap);
}

// An idp that is not a token is a signer name: the controller has no such signer, so the enrollment is turned
// down at once instead of waiting for a login (the pytest has a signer on the controller, so there is a list
// to look the name up in).
TEST_CASE_METHOD(ZitilibTestCase, "zl-enroll-unknown-signer", "[integ][zl-token]") {
    std::string network_jwt = checkENV("NETWORK_JWT");

    char *cfg = nullptr;
    unsigned long cfg_len = 0;
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, "no-such-signer", &cfg, &cfg_len);
    std::unique_ptr<char, decltype(&free)> id_json(cfg, free);
    INFO("enroll: " << rc << "/" << ziti_errorstr(rc));
    CHECK(rc == ZITI_INVALID_STATE);
    CHECK(id_json.get() == nullptr);
}
