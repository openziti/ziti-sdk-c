// Copyright (c) 2023.  NetFoundry Inc.
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

#include "catch2/catch_test_macros.hpp"
#include "catch2/matchers/catch_matchers_string.hpp"
#include <cstring>
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


TEST_CASE("load_jwt","[model]") {

    const char *jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUwYzZhZTkxYzE0YzljOTViOGMwYTUyMzY4NmEzNzF"
                      "jOGY1MGUxNDAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2ZkMjAwZmQzLWEyZDk"
                      "tNDU3Zi1iYzBiLWY5YjhlZTdkMjg5OC5wcm9kdWN0aW9uLm5ldGZvdW5kcnkuaW86NDQzIi"
                      "wic3ViIjoiQVo1allCLTBGIiwiYXVkIjpbIiJdLCJleHAiOjE3MDQ2NjE2OTUsImp0aSI6I"
                      "jA5Mjk3NDc5LTQ4OTQtNDBhMC1iYjQyLTkwMzBkNGJkZDA1YSIsImVtIjoib3R0In0.M8bE"
                      "8bz9DvgYG6AERBXv597g5vK6tkhFBT_bBZeiL6s8hFkft-6YLNAz6pR13y0SD7di4afcXmf"
                      "BdqILF7pPiX8qaSC7bfHyrBfa0iLtNmkxensJqQul2sTLtiqa8_hlLen8y000_kaXKqdzsk"
                      "2X5QcyRLh1C_5AUkyWrzIPQ7JUIlpzIE1yo4Ac0jfB7TF36he9eY1ap_ruST8I4iWA6Nlid"
                      "1zMDw2ET0ANTbm5Gu5KBaGQ_Sc7ZDjC_LRAOeO4lH5_XhxpT-0ehHqsJxP2YwR8OIppkYUm"
                      "OtNr2uRdLNjMdHNWtpF7A3igNMyqZMfv1eOnEV9GsqT56kM34qozCKF3VCJrRZo63feehKY"
                      "sMdm_HHcDUPm4GiBp2z9zc1xiJeZVrSXzpOecULq8o3163XvTE8uF-chJGMFa5O3dYQxbzj"
                      "6YlrHQol8C5FQjZwyO88-jR8ZlEANNYMQNVzE0ZdC-YAW-0aXRyv9XdoYuKY2Ba9YJ-wqrp"
                      "5yr0QxpWjpJAPj7VAvBDb91HYXFA4VpvbLeCuhgJSchMK0w_RDGdd5Td-27DIQOIMaf17Hy"
                      "5iYxWOfCa0G_2zDMxMCTuxmQksMata0uaEdf6bE_Uj4ZfWd3oY7ExINm_oXjhG7lcZvzd9y"
                      "EgJuxV98N7JfQwVkGynSEiivjd2hvRuUYnJXxszI";


    enroll_cfg_s ecfg{};
    ecfg.raw_jwt = (char*)jwt;
    ziti_enrollment_jwt_header zejh{};
    ziti_enrollment_jwt zej{};

    load_jwt_content(&ecfg, &zejh, &zej);

    CHECK(zejh.alg == jwt_sig_method_RS256);

    CHECK_THAT(zej.controller, Catch::Matchers::Equals("https://fd200fd3-a2d9-457f-bc0b-f9b8ee7d2898.production.netfoundry.io:443"));
    CHECK(zej.method == ziti_enrollment_methods.ott);
    CHECK_THAT(zej.subject, Catch::Matchers::Equals("AZ5jYB-0F"));
    CHECK_THAT(zej.token, Catch::Matchers::Equals("09297479-4894-40a0-bb42-9030d4bdd05a"));

    free_ziti_enrollment_jwt(&zej);
    free_ziti_enrollment_jwt_header(&zejh);
}
