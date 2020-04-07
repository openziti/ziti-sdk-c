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
#include "../deps/mjson/mjson.h"
#include <zt_internal.h>
#include <utils.h>
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

TEST_CASE("parse jwt", "[jwt]") {
    const char* jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbSI6Im90dCIsImV4cCI6MTU3MzQxMTc1MiwiaXNzIjoiaHR0cHM6Ly9"
                      "kZW1vLnppdGkubmV0Zm91bmRyeS5pbzoxMDgwIiwianRpIjoiZjU4MWQ3NzAtZmZmYy0xMWU5LWE4MWEtMDAwZDNhMWI0YjE"
                      "3Iiwic3ViIjoiYzE3MjkxZjQtMzdmZS00Y2RiLTlmNTctM2ViNzU3YjY0OGY1In0.ErW3EugeDxT6CKNU03mMncgXQ6QfOzL"
                      "tOgvMav6ucCUduGmycgCDk3H39WxiBzvT6WE19zkYXeQroZ1PcYN4QUUeUjlqctp2pZyqHhbAQnw0URITjbhcBmqogTg634n"
                      "CJoamTlmwDnlxU6LAI2l3Q0U7e90KW98ll7xbPI6e6pO3puznS2DLsEjOUp__ZdXdpw8F4F5QlsZxk2yPJpRT0Ou7eWakua-"
                      "d1ZxoKPhowXM2skC-uw4QB2-exCLSAD6pmdZSdNEoDkQuyBy8h9wbi5caAFmlzJnT-WoYhE7Ile25JG_rsXTiIIUspcckvNX"
                      "JefocWaB3ff0mNkXlQsAH3Q";

    const char *dot1 = strchr(jwt, '.');
    const char *dot2 = strchr(dot1 + 1, '.');
    const char *end = jwt + strlen(jwt);

    size_t header64len;
    char *header64 = url64to64(jwt, dot1 - jwt, &header64len);

    size_t head_len = (header64len / 4) * 3;

    char *head = (char*)malloc(head_len);
    char header[1024], body[1024];

    size_t body64len;
    char *body64 = url64to64(dot1 + 1, dot2 - dot1 - 1, &body64len);

    int rc = mjson_base64_dec(header64, header64len, head, head_len);

    printf("header = %*.*s, rc = %d\n", rc, rc, head, rc);

    char algo[32];
    rc = mjson_get_string(header, rc, "$.alg", algo, sizeof(algo));

    rc = mjson_base64_dec(body64, body64len, body, sizeof(body));
    printf("body = %*.*s, rc = %d\n", rc, rc, body, rc);

    ziti_enrollment_jwt *ze;
    parse_ziti_enrollment_jwt_ptr(&ze, body, rc);
    dump_ziti_enrollment_jwt(ze, 0);

    printf("ze->controller is: %s\n", ze->controller);

    REQUIRE_THAT(ze->controller, Catch::Matchers::Equals("https://demo.ziti.netfoundry.io:1080"));
    REQUIRE_THAT(ze->method, Catch::Matchers::Equals("ott"));
    REQUIRE_THAT(ze->subject, Catch::Matchers::Equals("c17291f4-37fe-4cdb-9f57-3eb757b648f5"));
    REQUIRE_THAT(ze->token, Catch::Matchers::Equals("f581d770-fffc-11e9-a81a-000d3a1b4b17"));

    size_t sig64len;
    char *sig64 = url64to64(dot2 + 1, end - dot2 - 1, &sig64len);

    size_t siglen = sig64len / 4 * 3;
    char *sig = (char*)malloc(siglen);

    rc = mjson_base64_dec(sig64, sig64len, sig, siglen);

    printf("sig64[%ld] = %*.*s siglen = %ld rc = %d\n", sig64len, (int)sig64len, (int)sig64len, sig64, siglen, rc);

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
