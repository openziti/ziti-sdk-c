

#include <catch2/catch_all.hpp>
#include <ziti/ziti.h>
#include "oidc.h"
#include "ziti/ziti_log.h"
#include "ziti_ctrl.h"
#include <tlsuv/tlsuv.h>

#include <test-data.h>
#include <iostream>
#include <zt_internal.h>

TEST_CASE("cltr-network-jwt", "[integ]") {
    auto l = uv_default_loop();

    ziti_config cfg{};
    ziti_controller ctrl{};
    REQUIRE(ziti_load_config(&cfg, TEST_CLIENT) == ZITI_OK);

    auto tls = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
    ziti_ctrl_init(l, &ctrl, &cfg.controllers, tls);

    struct res {
        std::string err;
        ziti_network_jwt_array arr;
    } result;

    ziti_ctrl_get_network_jwt(&ctrl, [](ziti_network_jwt_array arr, const ziti_error *err, void *ctx) {
        auto r = static_cast<res *>(ctx);
        if (err) {
            r->err += err->message;
        } else {
            r->arr = arr;
        }

    }, &result);

    uv_run(l, UV_RUN_DEFAULT);

    CHECK(result.err == "");
    CHECK(result.arr != nullptr);
    CHECK(result.arr[0] != nullptr);
    CHECK_THAT(result.arr[0]->name, Catch::Matchers::Equals("default"));

    ziti_enrollment_jwt_header header{};
    ziti_enrollment_jwt jwt{};
    enroll_cfg ecfg {
        .raw_jwt = (char*)result.arr[0]->token
    };
    load_jwt_content(&ecfg, &header, &jwt);

    CHECK(header.alg == jwt_sig_method_RS256);
    CHECK(jwt.method == ziti_enrollment_method_network);

    free_ziti_enrollment_jwt_header(&header);
    free_ziti_enrollment_jwt(&jwt);

    ziti_ctrl_close(&ctrl);
    tls->free_ctx(tls);
    free_ziti_network_jwt_array(&result.arr);
    free_ziti_config(&cfg);
    free(ecfg.jwt_signing_input);
    free(ecfg.jwt_sig);
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