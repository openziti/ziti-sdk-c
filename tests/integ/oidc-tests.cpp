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

#include <botan/base32.h>
#include <botan/otp.h>
#include <catch2/catch_all.hpp>
#include <tlsuv/tlsuv.h>
#include <ziti/ziti.h>
#include <ziti/zitilib.h>

#include "fixtures.h"
#include "oidc.h"
#include "test-data.h"
#include "ziti/ziti_log.h"

class AuthTests: public LoopTestCase {};

TEST_CASE_METHOD(AuthTests, "oidc", "[auth]") {
    auto l = loop();
    ziti_config cfg{};
    DEFER {
            free_ziti_config(&cfg);
    };
    auto *cfg_str = checkENV("test_client");
    REQUIRE(ziti_load_config(&cfg, cfg_str) == ZITI_OK);
    auto tls = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
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
    auto key = Botan::base32_decode(secret);
    Botan::TOTP totp(key.data(), key.size());

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
        auto code = totp.generate_totp(ts);
        auto code_str = std::to_string(code);

        UNSCOPED_INFO("totp attempt: " << (i + 1));
        ziti_mfa_verify(ztx, code_str.c_str(), [](ziti_context ztx, int status, void *ctx){
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
