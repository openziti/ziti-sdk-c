// Copyright (c) 2023-2026.  NetFoundry Inc
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

#include "catch2/catch_test_macros.hpp"
#include "catch2/matchers/catch_matchers_string.hpp"
#include <catch2/generators/catch_generators.hpp>
#include <cstring>
#include "internal_model.h"
#include <jwt.h>
#include "credentials.h"

extern "C" int parse_enrollment_jwt(
    const char *token, ziti_enrollment_jwt_header *zejh, ziti_enrollment_jwt *zej,
    char **sig, size_t *sig_len);

static const char jwt[] =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUwYzZhZTkxYzE0YzljOTViOGMwYTUyMzY4NmEzNzF"
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

TEST_CASE("load_jwt","[model]") {

    ziti_enrollment_jwt_header zejh{};
    ziti_enrollment_jwt zej{};

    size_t siglen;
    char * sig;
    parse_enrollment_jwt(jwt, &zejh, &zej, &sig, &siglen);

    CHECK(zejh.alg == jwt_sig_method_RS256);

    CHECK_THAT(zej.controller, Catch::Matchers::Equals("https://fd200fd3-a2d9-457f-bc0b-f9b8ee7d2898.production.netfoundry.io:443"));
    CHECK(zej.method == ziti_enrollment_methods.ott);
    CHECK_THAT(zej.subject, Catch::Matchers::Equals("AZ5jYB-0F"));
    CHECK_THAT(zej.token, Catch::Matchers::Equals("09297479-4894-40a0-bb42-9030d4bdd05a"));

    free(sig);
    free_ziti_enrollment_jwt(&zej);
    free_ziti_enrollment_jwt_header(&zejh);
}

TEST_CASE("zt_jwt_parse","[model]") {
    zt_jwt jwt_struct{};
    int rc = zt_jwt_parse(jwt, &jwt_struct);
    CHECK(rc == 0);
    CHECK_THAT(cstr_str(&jwt_struct.issuer),
               Catch::Matchers::Equals("https://fd200fd3-a2d9-457f-bc0b-f9b8ee7d2898.production.netfoundry.io:443"));
    CHECK(jwt_struct.expiration == 1704661695);
    CHECK_THAT(json_object_get_string(json_object_object_get(jwt_struct.claims, "sub")), Catch::Matchers::Equals("AZ5jYB-0F"));
    CHECK_THAT(json_object_get_string(json_object_object_get(jwt_struct.claims, "jti")), Catch::Matchers::Equals("09297479-4894-40a0-bb42-9030d4bdd05a"));

    zt_jwt_drop(&jwt_struct);
}

TEST_CASE("zt_jwt_parse negative", "[model]") {
    auto tc = GENERATE(table<const char*, const char*>({
        // structure errors
        {"empty string",           ""},
        {"no dots",                "eyJhbGciOiJSUzI1NiJ9"},
        {"only one dot",           "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0"},
        {"dots only",              "..."},
        {"empty segments",         ".."},

        // header decode/parse errors
        {"invalid base64 header",  "!!!invalid!!!.cGF5bG9hZA.c2ln"},
        {"header not json",        "bm90IGpzb24.cGF5bG9hZA.c2ln"},             // "not json"

        // payload decode/parse errors
        {"invalid base64 payload", "eyJhbGciOiJSUzI1NiJ9.!!!invalid!!!.c2ln"},
        {"payload not json",       "eyJhbGciOiJSUzI1NiJ9.bm90IGpzb24.c2ln"},  // "not json"
        {"payload is json array",  "eyJhbGciOiJSUzI1NiJ9.WzEsIDJd.c2ln"},     // [1, 2]
        {"empty json payload",     "eyJhbGciOiJSUzI1NiJ9.e30.c2ln"},           // {}

        // iss claim errors
        {"missing iss claim",      "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2ln"},         // {"sub":"test"}
        {"iss not a string",       "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOjEyM30.c2ln"},              // {"iss":123}
        {"iss is null",            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiBudWxsfQ.c2ln"},            // {"iss": null}
        {"iss is boolean",         "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiB0cnVlfQ.c2ln"},            // {"iss": true}
        {"iss is array",           "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiBbImEiXX0.c2ln"},           // {"iss": ["a"]}
        {"iss is object",          "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiB7fX0.c2ln"},               // {"iss": {}}

        // exp claim errors
        {"exp not an int",         "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoibm90YW5pbnQifQ.c2ln"},  // {"iss":"test","exp":"notanint"}
        {"exp is boolean",         "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiAidGVzdCIsICJleHAiOiB0cnVlfQ.c2ln"},       // {"iss":"test","exp":true}
        {"exp is float",           "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiAidGVzdCIsICJleHAiOiAxLjV9.c2ln"},         // {"iss":"test","exp":1.5}
    }));

    DYNAMIC_SECTION(std::get<0>(tc)) {
        zt_jwt jwt_struct{};
        int rc = zt_jwt_parse(std::get<1>(tc), &jwt_struct);
        CHECK(rc != 0);
    }
}

TEST_CASE("zt_jwt_parse valid", "[model]") {
    struct valid_case {
        const char *label;
        const char *input;
        const char *expected_iss;
        uint64_t expected_exp;
    };
    auto tc = GENERATE(values<valid_case>({
        // {"iss":"https://example.com","exp":1704661695}
        {"with exp",
         "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxNzA0NjYxNjk1fQ.c2ln",
         "https://example.com", 1704661695},
        // {"iss":"https://example.com"}
        {"without exp",
         "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.c2ln",
         "https://example.com", 0},
        // json-c represents JSON null as NULL pointer, parser treats it as absent exp
        // {"iss":"test","exp":null}
        {"exp is null",
         "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiAidGVzdCIsICJleHAiOiBudWxsfQ.c2ln",
         "test", 0},
        // parser doesn't validate header structure, only that it's valid JSON
        // header: [1, 2], payload: {"iss":"test"}
        {"header is json array",
         "WzEsIDJd.eyJpc3MiOiJ0ZXN0In0.c2ln",
         "test", 0},
    }));

    DYNAMIC_SECTION(tc.label) {
        zt_jwt jwt_struct{};
        int rc = zt_jwt_parse(tc.input, &jwt_struct);
        CHECK(rc == 0);
        CHECK_THAT(cstr_str(&jwt_struct.issuer), Catch::Matchers::Equals(tc.expected_iss));
        CHECK(jwt_struct.expiration == tc.expected_exp);
        zt_jwt_drop(&jwt_struct);
    }
}

TEST_CASE("zt_jwt_parse extra dots", "[model]") {
    zt_jwt jwt_struct{};
    // header.payload.sig.extra — extra segment; verify no crash
    int rc = zt_jwt_parse("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.c2ln.ZXh0cmE", &jwt_struct);
    (void)rc;
    zt_jwt_drop(&jwt_struct);
}

TEST_CASE("jwt cred", "[model]") {
    ziti_credential_t *cred = nullptr;
    int rc = ziti_credential_from_jwt(jwt, &cred);
    CHECK(rc == 0);
    REQUIRE(cred != nullptr);
    CHECK(cred->type == ZITI_CRED_TYPE_JWT);
    CHECK(cstr_equals(&cred->jwt.issuer, "https://fd200fd3-a2d9-457f-bc0b-f9b8ee7d2898.production.netfoundry.io:443"));
    ziti_credential_drop(cred);
}
