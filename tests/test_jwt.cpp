/*
Copyright 2020 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "catch2/catch.hpp"
#include <string.h>
// #include <iostream>
#include <zt_internal.h>
#include <utils.h>
#include <mbedtls/x509_csr.h>
#include "internal_model.h"

static char* url64to64(const char* in, size_t ilen, size_t *olen) {
    size_t size = ((ilen - 1)/4 + 1) * 4;
    assert(size >= ilen);
    assert(size - ilen <= 3);

    char *out = (char*)malloc(size);
    size_t i;
    for(i = 0; i < ilen; i++) {
        switch (in[i]) {
            case '_': out[i] = '/'; break;
            case '-': out[i] = '+';break;
            default: out[i] = in[i];
        }
    }

    while(i < size) {
        out[i++] = '=';
    }
    *olen = size;
    return out;
}


TEST_CASE("load_jwt","[integ]") {

    char *conf = getenv("ZITI_SDK_JWT_FILE");
    if (conf == nullptr) {
        FAIL("ZITI_SDK_JWT_FILE environment variable is not set");
        return;
    }

    struct enroll_cfg_s *ecfg = (struct enroll_cfg_s *)calloc(1, sizeof(enroll_cfg));
    ziti_enrollment_jwt_header *zejh = NULL;
    ziti_enrollment_jwt *zej = NULL;

    load_jwt(conf, ecfg, &zejh, &zej);

    REQUIRE_THAT(zejh->alg, Catch::Matchers::Equals("RS256"));

    REQUIRE_THAT(zej->controller, Catch::Matchers::Equals("https://demo.ziti.netfoundry.io:1080"));
    REQUIRE_THAT(zej->method, Catch::Matchers::Equals("ott"));
    REQUIRE_THAT(zej->subject, Catch::Matchers::Equals("c17291f4-37fe-4cdb-9f57-3eb757b648f5"));
    REQUIRE_THAT(zej->token, Catch::Matchers::Equals("f581d770-fffc-11e9-a81a-000d3a1b4b17"));

}

TEST_CASE("test generate csr", "[engine]") {
    tls_context *tls = default_tls_context(nullptr, 0);

    tls_private_key pk;
    CHECK(tls->api->generate_key(&pk) == 0);
    REQUIRE(pk != nullptr);

    char *keypem;
    std::size_t keypemlen;
    REQUIRE(tls->api->write_key_to_pem(pk, &keypem, &keypemlen) == 0);
    printf("key pem =\n%.*s\n", (int) keypemlen, keypem);
    free(keypem);

    uint8_t *pem;
    std::size_t pemlen;
    REQUIRE(tls->api->generate_csr_to_pem(pk, (char **) &pem, &pemlen,
                                          "C", "US",
                                          "ST", "NY",
                                          "O", "OpenZiti",
                                          "OU", "Developers",
                                          "DC", "https://demo4.ziti"
                                                "CN", "this is test",
                                          nullptr) == 0);
    printf("csr pem =\n%.*s\n", (int) pemlen, pem);

    mbedtls_x509_csr csr;
    mbedtls_x509_csr_init(&csr);
    REQUIRE(mbedtls_x509_csr_parse(&csr, pem, pemlen) == 0);
    free(pem);
    tls->api->free_key(&pk);
    tls->api->free_ctx(tls);
    mbedtls_x509_csr_free(&csr);
}
