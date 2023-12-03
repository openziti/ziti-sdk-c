//
// 	Copyright NetFoundry Inc.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

#include <catch2/catch_all.hpp>
#include <ziti/zitilib.h>
#include <ziti/ziti.h>
#include "oidc.h"
#include "ziti/ziti_log.h"
#include <tlsuv/tlsuv.h>

#include <test-data.h>

TEST_CASE("ha-oidc", "[integ]") {
    auto l = uv_loop_new();
    ziti_log_init(l, 4, NULL);
    ziti_config cfg;
    REQUIRE(ziti_load_config(&cfg, TEST_CLIENT) == ZITI_OK);
    auto tls = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
    tls_cert cert;
    tlsuv_private_key_t key;
    tls->load_cert(&cert, cfg.id.cert, strlen(cfg.id.cert));
    tls->load_key(&key, cfg.id.key, strlen(cfg.id.key));
    tls->set_own_cert(tls, key, cert);

    oidc_client_t oidcClient;
    oidc_client_init(l, &oidcClient, cfg.controller_url, tls);
    bool called = false;
    oidcClient.data = &called;

    oidc_client_configure(&oidcClient, [](oidc_client_t *clt, int status, const char *err) {
        CHECK(status == 0);
        CHECK(err == nullptr);
        *(bool *) clt->data = true;
    });

    uv_run(l, UV_RUN_DEFAULT);

    CHECK(called);
    CHECK(oidcClient.config != NULL);

    std::string token;
    oidcClient.data = &token;
    oidc_client_start(&oidcClient, [](oidc_client_t *clt, int status, const char *token) {
        auto out = (std::string *) clt->data;
        REQUIRE(status == 0);
        *out = token;
    });

    uv_run(l, UV_RUN_DEFAULT);

    REQUIRE(!token.empty());

    std::string old = token;
    token.clear();

    oidc_client_refresh(&oidcClient);
    uv_run(l, UV_RUN_DEFAULT);

    REQUIRE(!token.empty());
    REQUIRE(token != old);

    bool closed = false;
    oidcClient.data = &closed;
    oidc_client_close(&oidcClient, [](oidc_client_t *clt){
        *(bool*)clt->data = true;
    });

    uv_run(l, UV_RUN_DEFAULT);
    REQUIRE(closed);

//    key->free(key);
    tls->free_cert(&cert);
    tls->free_ctx(tls);

    free_ziti_config(&cfg);

    uv_loop_close(l);
    free(l);
}