

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
#include <ziti/ziti.h>
#include <ziti/zitilib.h>
#include <ziti/ziti_log.h>

#include "credentials.h"
#include "ziti_ctrl.h"
#include <tlsuv/tlsuv.h>

#include "fixtures.h"

#include <expected>
#include <iostream>
#include <test-data.h>

#define MODEL(type) Model<type, free_ ## type>
template<class T, void (*D)(T*)>
class Model {
    T data{};
public:
    ~Model() {
        D(&data);
    }

    operator T*() {
        return &data;
    }

    T* operator->() {
        return &data;
    }
};

class CtrlTest: public LoopTestCase {
protected:
    MODEL(ziti_config) cfg;
    tls_context *tls = nullptr;
    tls_credentials creds{};
    ziti_controller ctrl{};

    CtrlTest() {
        ziti_log_init(loop(), 5, nullptr);
        auto c = test_client();
        REQUIRE_ZITI_OK(ziti_load_config(cfg, c));
        REQUIRE_ZITI_OK(load_tls(cfg, &tls, &creds));
        REQUIRE_ZITI_OK(ziti_ctrl_init(loop(), &ctrl, &cfg->controllers, tls));
    }

    ~CtrlTest() {
        ziti_ctrl_close(&ctrl);
        creds.cert->free(creds.cert);
        creds.key->free(creds.key);
        tls->free_ctx(tls);
    }

    static const char *test_client() {
        return checkENV("test_client");
    }

    template<class T>
    std::expected<T*, std::string> GET(
        void(*m)(ziti_controller *, void (*cb)(T*, const ziti_error *err, void *), void *)) {
        using result_type = std::expected<T*, std::string>;
        using result_type_opt = std::optional<result_type>;
        result_type_opt ret;
        m(&ctrl, [](T *val, const ziti_error *err, void *r) {
            auto res = static_cast<result_type_opt *>(r);
            if (err) *res = std::unexpected(err->message);
            else if (val == nullptr) *res = std::unexpected("null result");
            else *res = val;
        }, &ret);
        if (!run(UNTIL(ret.has_value()))) return std::unexpected("timeout");
        return ret.value();
    }

    template<class T>
    std::expected<T**, std::string> GET(
        void (*m)(ziti_controller *, void (*cb)(T**, const ziti_error *err, void *), void *)) {
        using result_type = std::expected<T**, std::string>;
        using result_type_opt = std::optional<result_type>;

        result_type_opt ret;
        m(&ctrl, [](T **val, const ziti_error *err, void *r) {
            auto res = static_cast<result_type_opt*>(r);
            if (err)  *res = std::unexpected(err->message);
            else if (val == nullptr) *res = std::unexpected("null result");
            else {
                *res = val;
            }
        }, &ret);
        if (!run(UNTIL(ret.has_value()))) {
            return std::unexpected("timeout");
        }
        return ret.value();
    }

    void check_capability(ziti_ctrl_cap cap) {
        auto result = GET(ziti_ctrl_get_version);
        CHECK(result.has_value());
        auto v = result.value();
        CHECK(v != nullptr);
        if (!ziti_ctrl_has_capability(&ctrl, cap)) {
            SKIP("capability[" << ziti_ctrl_caps.name(cap) << "] not supported");
        }
    }
};

TEST_CASE_METHOD(CtrlTest, "get-version", "[controller]") {
    auto result = GET(ziti_ctrl_get_version);
    CHECK(result.has_value());
    auto v = result.value();
    CHECK(v != nullptr);
}
template<typename T>
class ModelMapWrap {
    model_map *_m;
public:
    ModelMapWrap(model_map *m) : _m(m) {}
    ModelMapWrap(model_map &m) : _m(&m) {}
    T operator[](const char* key) {
        return static_cast<T>(model_map_get(_m, key));
    }
};

template<typename R>
R map_get(model_map &m, const char *key) {
    return static_cast<R>(model_map_get(&m, key));
}

TEST_CASE_METHOD(CtrlTest, "cltr-network-jwt", "[controller]") {
    auto result = GET(ziti_ctrl_get_network_jwt);
    CHECK(result.has_value());
    auto v = result.value();
    CHECK(v != nullptr);
    DEFER {
        free_ziti_network_jwt_array(&v);
    };

    ziti_enrollment_jwt_header header{};
    ziti_enrollment_jwt jwt{};
    char * sig = nullptr;
    DEFER {
        free_ziti_enrollment_jwt_header(&header);
        free_ziti_enrollment_jwt(&jwt);
        free(sig);
    };
    size_t siglen;
    REQUIRE_ZITI_OK(parse_enrollment_jwt(v[0]->token, &header, &jwt, &sig, &siglen));

    CHECK(header.alg == jwt_sig_method_RS256);
    CHECK(jwt.method == ziti_enrollment_method_network);
}

TEST_CASE_METHOD(CtrlTest, "authenticate", "[controller]") {
    check_capability(ziti_ctrl_cap_OIDC_AUTH);
    auto version = GET(ziti_ctrl_get_version);
    REQUIRE(version);
    auto p = map_get<api_path*>(version.value()->api_versions->oidc, "v1");
    auto auth = new_oidc_auth(loop(), p, tls);
    
}


TEST_CASE("ctrl-token-auth", "[integ]") {
    // auto l = uv_default_loop();
    //
    // ziti_config cfg;
    // REQUIRE(ziti_load_config(&cfg, TEST_CLIENT) == ZITI_OK);
    //
    // auto ctrlTLS = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
    //
    // ziti_controller ctrl = {};
    // REQUIRE(ziti_ctrl_init(l, &ctrl, cfg.controller_url, ctrlTLS) == ZITI_OK);
    //
    // ziti_version v = {0};
    // std::string err;
    // ziti_ctrl_get_version(&ctrl, [](const ziti_version *v, const ziti_error *err, void *ctx){
    //     std::cout << "in version cb" << std::endl;
    //     auto out = (ziti_version*)ctx;
    //     REQUIRE(v != NULL);
    //     *out = *v;
    //     free(v);
    //     }, &v);
    //
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // bool HA = ziti_has_capability(&v, ziti_ctrl_caps.HA_CONTROLLER);
    // bool OIDC = ziti_has_capability(&v, ziti_ctrl_caps.OIDC_AUTH);
    // if (!(HA && OIDC)) {
    //     SKIP("can not test without HA and OIDC");
    // }
    //
    // oidc_client_t oidc;
    // auto oidcTLS = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
    // tlsuv_private_key_t key;
    // tls_cert cert = nullptr;
    // oidcTLS->load_key(&key, cfg.id.key, strlen(cfg.id.key));
    // oidcTLS->load_cert(&cert, cfg.id.cert, strlen(cfg.id.cert));
    // oidcTLS->set_own_cert(oidcTLS, key, cert);
    // oidc_client_init(l, &oidc, cfg.controller_url, oidcTLS);
    //
    // oidc_client_configure(&oidc, nullptr);
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // std::string token;
    // oidc.data = &token;
    // oidc_client_start(&oidc, [](oidc_client_t *clt, int status, const char *token){
    //     CAPTURE(status);
    //     auto out = (std::string*)clt->data;
    //     *out = token;
    // });
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // REQUIRE(!token.empty());
    //
    // ziti_service service = {nullptr};
    // ziti_ctrl_set_token(&ctrl, token.c_str());
    // ziti_ctrl_get_service(&ctrl, TEST_SERVICE,
    //                       [](ziti_service *s, const ziti_error *err, void *ctx){
    //                           auto msg = err ? err->message : "";
    //                           INFO(msg);
    //                           REQUIRE(s != nullptr);
    //                           *(ziti_service*)ctx = *s;
    //                           free(s);
    //                       },
    //                       &service);
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // REQUIRE_THAT(service.name, Catch::Matchers::Equals(TEST_SERVICE));
    // oidc_client_close(&oidc, nullptr);
    // ziti_ctrl_close(&ctrl);
    //
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // oidcTLS->free_cert(&cert);
    //
    // oidcTLS->free_ctx(oidcTLS);
    // ctrlTLS->free_ctx(ctrlTLS);
    //
    // free_ziti_version(&v);
    // free_ziti_service(&service);
    // free_ziti_config(&cfg);
}