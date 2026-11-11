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

#include <chrono>
#include <cstdio>
#include <fstream>
#include <future>
#include <memory>
#include <string>
#include <thread>

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

    ziti_enroll_handle_t pending = 42;

    CHECK(Ziti_enroll_with_idp(nullptr, ziti_enroll_token, "token", &pending, &id, &len) == ZITI_INVALID_STATE);
    CHECK(pending == ZITI_INVALID_HANDLE); // never left as it was
    CHECK(Ziti_enroll_with_idp("", ziti_enroll_token, "token", nullptr, &id, &len) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_with_idp(url, ziti_enroll_token, "token", nullptr, nullptr, &len) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_with_idp(url, ziti_enroll_token, "token", nullptr, &id, nullptr) == ZITI_INVALID_STATE);

    // no such pending enrollment
    CHECK(Ziti_enroll_login_url(ZITI_INVALID_HANDLE) == nullptr);
    CHECK(Ziti_enroll_continue(ZITI_INVALID_HANDLE, 10, &id, &len) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_continue(7, 10, nullptr, &len) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_cancel(ZITI_INVALID_HANDLE) == ZITI_INVALID_STATE);

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
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, token.c_str(), nullptr, &cfg, &cfg_len);
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
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_cert, token.c_str(), nullptr, &cfg, &cfg_len);
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
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_none, nullptr, nullptr, &cfg, &cfg_len);
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
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, "no-such-signer", nullptr, &cfg, &cfg_len);
    std::unique_ptr<char, decltype(&free)> id_json(cfg, free);
    INFO("enroll: " << rc << "/" << ziti_errorstr(rc));
    CHECK(rc == ZITI_INVALID_STATE);
    CHECK(id_json.get() == nullptr);
}

// A login with a signer is interactive: the call hands back a handle, the url the user has to open is asked
// for, and Ziti_enroll_continue waits for the result. The pytest plays the browser: it reads the url from
// LOGIN_URL_FILE, logs in at the idp and delivers the redirect to the SDK's local listener.
// Env: NETWORK_JWT, IDP_SIGNER (its name), LOGIN_URL_FILE.
TEST_CASE_METHOD(ZitilibTestCase, "zl-enroll-interactive", "[integ][zl-token]") {
    std::string network_jwt = checkENV("NETWORK_JWT");
    std::string signer = checkENV("IDP_SIGNER");
    std::string url_file = checkENV("LOGIN_URL_FILE");

    char *cfg = nullptr;
    unsigned long cfg_len = 0;
    ziti_enroll_handle_t pending = ZITI_INVALID_HANDLE;
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, signer.c_str(), &pending, &cfg, &cfg_len);
    INFO("enroll: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_EXTERNAL_LOGIN_REQUIRED);
    REQUIRE(pending != ZITI_INVALID_HANDLE);
    CHECK(cfg == nullptr);

    // the SDK keeps the url until the enrollment is resolved: the same string every time, nothing to free
    const char *url = Ziti_enroll_login_url(pending);
    REQUIRE(url != nullptr);
    CHECK(Ziti_enroll_login_url(pending) == url);
    std::string login_url = url;
    CHECK(login_url.rfind("http", 0) == 0);

    // the file shows up whole: the other side reads it as soon as it is there
    std::string tmp = url_file + ".tmp";
    {
        std::ofstream(tmp) << login_url;
    }
    REQUIRE(std::rename(tmp.c_str(), url_file.c_str()) == 0);

    rc = Ziti_enroll_continue(pending, 30000, &cfg, &cfg_len);
    std::unique_ptr<char, decltype(&free)> id_json(cfg, free);
    INFO("continue: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);

    // enrolled to a token: no cert, the token is the login
    ziti_config id{};
    REQUIRE(ziti_load_config(&id, id_json.get()) == ZITI_OK);
    CHECK(id.id.cert == nullptr);
    free_ziti_config(&id);

    // the handle is spent
    char *again = nullptr;
    unsigned long again_len = 0;
    CHECK(Ziti_enroll_continue(pending, 10, &again, &again_len) == ZITI_INVALID_STATE);
}

// A pending enrollment can be waited for with a timeout and abandoned, and there is one at a time.
// Env: NETWORK_JWT, IDP_SIGNER.
TEST_CASE_METHOD(ZitilibTestCase, "zl-enroll-interactive-cancel", "[integ][zl-token]") {
    std::string network_jwt = checkENV("NETWORK_JWT");
    std::string signer = checkENV("IDP_SIGNER");

    char *cfg = nullptr;
    unsigned long cfg_len = 0;

    // a login needs somewhere to put the handle
    CHECK(Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, signer.c_str(), nullptr, &cfg, &cfg_len)
          == ZITI_INVALID_STATE);

    ziti_enroll_handle_t first = ZITI_INVALID_HANDLE;
    REQUIRE(Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, signer.c_str(), &first, &cfg, &cfg_len)
            == ZITI_EXTERNAL_LOGIN_REQUIRED);
    REQUIRE(first != ZITI_INVALID_HANDLE);

    // the user does not log in: the wait ends with the timeout, and the enrollment is still pending
    CHECK(Ziti_enroll_continue(first, 200, &cfg, &cfg_len) == ZITI_TIMEOUT);
    CHECK(Ziti_enroll_login_url(first) != nullptr);

    // one at a time
    ziti_enroll_handle_t second = 7;
    CHECK(Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, signer.c_str(), &second, &cfg, &cfg_len)
          == ZITI_INVALID_STATE);
    CHECK(second == ZITI_INVALID_HANDLE);

    CHECK(Ziti_enroll_cancel(first) == ZITI_OK);
    CHECK(Ziti_enroll_cancel(first) == ZITI_INVALID_STATE);
    CHECK(Ziti_enroll_continue(first, 10, &cfg, &cfg_len) == ZITI_INVALID_STATE);

    // the place is free again
    REQUIRE(Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_token, signer.c_str(), &second, &cfg, &cfg_len)
            == ZITI_EXTERNAL_LOGIN_REQUIRED);
    CHECK(Ziti_enroll_cancel(second) == ZITI_OK);
}

namespace {
struct LoginExternalResult {
    std::string url;
    int err = 0;
};

// Ziti_login_external has no timeout of its own, so a call that never returns would hold the whole suite until
// run_catch_test gives up: the call runs on a thread this case does not wait for.
std::future<LoginExternalResult> loginExternalAsync(ziti_handle_t ztx, const std::string &signer) {
    auto result = std::make_shared<std::promise<LoginExternalResult>>();
    auto future = result->get_future();
    std::thread([result, ztx, signer] {
        LoginExternalResult r;
        char *url = Ziti_login_external(ztx, signer.c_str());
        r.err = Ziti_last_error(); // the last error belongs to the calling thread
        if (url != nullptr) {
            r.url = url;
            free(url);
        }
        result->set_value(std::move(r));
    }).detach();
    return future;
}

void requireSignerListed(ziti_handle_t ztx, const std::string &signer) {
    const char *const *signers = Ziti_get_ext_signers(ztx);
    REQUIRE(signers != nullptr);
    bool listed = false;
    for (int i = 0; signers[i] != nullptr; i++) {
        listed = listed || signer == signers[i];
    }
    REQUIRE(listed);
}

// What an app with only the controller's address and CA (the bootstrap config) has: no login of its own, so the
// context asks for an external one and lists the signers to pick from.
ziti_handle_t loadBootstrapContext(const std::string &network_jwt, const std::string &signer) {
    char *cfg = nullptr;
    unsigned long cfg_len = 0;
    int rc = Ziti_enroll_with_idp(network_jwt.c_str(), ziti_enroll_none, nullptr, nullptr, &cfg, &cfg_len);
    std::unique_ptr<char, decltype(&free)> bootstrap(cfg, free);
    INFO("bootstrap: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_OK);

    ziti_handle_t ztx = ZITI_INVALID_HANDLE;
    rc = Ziti_load_context(&ztx, bootstrap.get());
    INFO("load: " << rc << "/" << ziti_errorstr(rc));
    REQUIRE(rc == ZITI_EXTERNAL_LOGIN_REQUIRED);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);

    requireSignerListed(ztx, signer);
    return ztx;
}
}

// The app picks one of the signers the context lists, and the call gives it the url the user has to open.
// The pytest plays the browser: it reads the url from LOGIN_URL_FILE, logs in at the idp and delivers the
// redirect to the SDK's local listener, which lets Ziti_wait_for_auth finish.
// Env: NETWORK_JWT, IDP_SIGNER (its name), LOGIN_URL_FILE.
TEST_CASE_METHOD(ZitilibTestCase, "zl-login-external", "[integ][zl-login]") {
    std::string network_jwt = checkENV("NETWORK_JWT");
    std::string signer = checkENV("IDP_SIGNER");
    std::string url_file = checkENV("LOGIN_URL_FILE");

    ziti_handle_t ztx = loadBootstrapContext(network_jwt, signer);

    auto login = loginExternalAsync(ztx, signer);
    REQUIRE(login.wait_for(std::chrono::seconds(20)) == std::future_status::ready);
    LoginExternalResult r = login.get();
    INFO("login external: " << r.err << "/" << ziti_errorstr(r.err));
    REQUIRE(!r.url.empty());
    CHECK(r.url.rfind("http", 0) == 0);

    // the file shows up whole: the other side reads it as soon as it is there
    std::string tmp = url_file + ".tmp";
    {
        std::ofstream(tmp) << r.url;
    }
    REQUIRE(std::rename(tmp.c_str(), url_file.c_str()) == 0);

    int rc = Ziti_wait_for_auth(ztx, 30000);
    INFO("wait for auth: " << rc << "/" << ziti_errorstr(rc));
    CHECK(rc == ZITI_OK);
}

// The idp does not answer (it refuses the connection, or takes it and says nothing): the SDK cannot get the url
// the user is to open, and the call has to say so instead of waiting for it. The 20 s the call gets is longer
// than the SDK waits for an idp. Env: NETWORK_JWT, IDP_SIGNER (the name of a signer whose idp is down).
TEST_CASE_METHOD(ZitilibTestCase, "zl-login-external-idp-down", "[integ][zl-login]") {
    std::string network_jwt = checkENV("NETWORK_JWT");
    std::string signer = checkENV("IDP_SIGNER");

    ziti_handle_t ztx = loadBootstrapContext(network_jwt, signer);

    auto login = loginExternalAsync(ztx, signer);
    REQUIRE(login.wait_for(std::chrono::seconds(20)) == std::future_status::ready);
    LoginExternalResult r = login.get();
    INFO("login external: " << r.err << "/" << ziti_errorstr(r.err));
    CHECK(r.url.empty());
    CHECK(r.err == ZITI_AUTHENTICATION_FAILED);
}

// A login that is waiting for the idp holds the context: a second one is turned down at once, and it does not
// take the idp client away from the first, which still gets its answer.
// Env: NETWORK_JWT, IDP_SIGNER (the name of a signer whose idp takes the connection and says nothing).
TEST_CASE_METHOD(ZitilibTestCase, "zl-login-external-concurrent", "[integ][zl-login]") {
    std::string network_jwt = checkENV("NETWORK_JWT");
    std::string signer = checkENV("IDP_SIGNER");

    ziti_handle_t ztx = loadBootstrapContext(network_jwt, signer);

    // the idp says nothing, so the first call is still waiting for it a second later
    auto first = loginExternalAsync(ztx, signer);
    REQUIRE(first.wait_for(std::chrono::seconds(1)) == std::future_status::timeout);

    auto second = loginExternalAsync(ztx, signer);
    REQUIRE(second.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    LoginExternalResult r2 = second.get();
    INFO("second login external: " << r2.err << "/" << ziti_errorstr(r2.err));
    CHECK(r2.url.empty());
    CHECK(r2.err == ZITI_INVALID_STATE);

    REQUIRE(first.wait_for(std::chrono::seconds(20)) == std::future_status::ready);
    LoginExternalResult r1 = first.get();
    INFO("first login external: " << r1.err << "/" << ziti_errorstr(r1.err));
    CHECK(r1.url.empty());
    CHECK(r1.err == ZITI_AUTHENTICATION_FAILED);
}

// Another call is waiting for the authentication of the context: it keeps its place, and the login is turned
// down. Env: NETWORK_JWT, IDP_SIGNER (the name of a signer).
TEST_CASE_METHOD(ZitilibTestCase, "zl-login-external-while-waiting", "[integ][zl-login]") {
    std::string network_jwt = checkENV("NETWORK_JWT");
    std::string signer = checkENV("IDP_SIGNER");

    ziti_handle_t ztx = loadBootstrapContext(network_jwt, signer);

    auto waiting = std::async(std::launch::async, [ztx] { return Ziti_wait_for_auth(ztx, 2000); });
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // it is waiting by now

    auto login = loginExternalAsync(ztx, signer);
    REQUIRE(login.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    LoginExternalResult r = login.get();
    INFO("login external: " << r.err << "/" << ziti_errorstr(r.err));
    CHECK(r.url.empty());
    CHECK(r.err == ZITI_INVALID_STATE);

    // nobody logs in
    CHECK(waiting.get() == ZITI_TIMEOUT);
}

// The context is logged in already, and the app starts a login with a signer whose idp is down: the call says
// so, as it does for a context that is not logged in.
// Env: test_client (an identity that logs in on its own), IDP_SIGNER (the name of a signer whose idp is down).
TEST_CASE_METHOD(ZitilibTestCase, "zl-login-external-authenticated-idp-down", "[integ][zl-login]") {
    std::string signer = checkENV("IDP_SIGNER");

    ziti_handle_t ztx = loadContext(checkENV("test_client"));
    requireSignerListed(ztx, signer);

    auto login = loginExternalAsync(ztx, signer);
    REQUIRE(login.wait_for(std::chrono::seconds(20)) == std::future_status::ready);
    LoginExternalResult r = login.get();
    INFO("login external: " << r.err << "/" << ziti_errorstr(r.err));
    CHECK(r.url.empty());
    CHECK(r.err == ZITI_AUTHENTICATION_FAILED);
}
