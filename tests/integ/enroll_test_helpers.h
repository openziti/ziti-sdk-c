// Copyright (c) 2026. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ZITI_SDK_ENROLL_TEST_HELPERS_H
#define ZITI_SDK_ENROLL_TEST_HELPERS_H

#include <catch2/catch_all.hpp>
#include <ziti/ziti.h>
#include <tlsuv/tlsuv.h>
#include <json-c/json.h>
#include <sodium.h>
#include <ctime>
#include <string>

#include "fixtures.h"
#include "ziti_ctrl.h"
#include "zt_internal.h"
#include "utils.h"
#include "test-data.h"

// Build an RS256-signed JWT using the test signer key.
// Returns the compact JWT string (header.payload.signature).
static std::string sign_test_jwt(
        tls_context *tls,
        const char *key_path,
        const char *issuer,
        const char *subject,
        const char *audience,
        int64_t expires_in_seconds) {

    // load signing key
    char *key_pem = nullptr;
    size_t key_len = 0;
    REQUIRE(load_file(key_path, strlen(key_path), &key_pem, &key_len) == 0);

    tlsuv_private_key_t pk = nullptr;
    REQUIRE(tls->load_key(&pk, key_pem, key_len) == 0);
    free(key_pem);

    // read kid (cert fingerprint) for JWT header
    char *kid_buf = nullptr;
    size_t kid_len = 0;
    REQUIRE(load_file(TEST_JWT_SIGNER_KID, strlen(TEST_JWT_SIGNER_KID), &kid_buf, &kid_len) == 0);
    // trim trailing newline
    while (kid_len > 0 && (kid_buf[kid_len-1] == '\n' || kid_buf[kid_len-1] == '\r')) {
        kid_buf[--kid_len] = '\0';
    }

    // build header: {"alg":"RS256","typ":"JWT","kid":"<fingerprint>"}
    json_object *hdr = json_object_new_object();
    json_object_object_add(hdr, "alg", json_object_new_string("RS256"));
    json_object_object_add(hdr, "typ", json_object_new_string("JWT"));
    json_object_object_add(hdr, "kid", json_object_new_string(kid_buf));
    free(kid_buf);
    const char *hdr_str = json_object_to_json_string_ext(hdr, JSON_C_TO_STRING_PLAIN);

    // build payload
    auto now = (int64_t)time(nullptr);
    json_object *payload = json_object_new_object();
    json_object_object_add(payload, "iss", json_object_new_string(issuer));
    json_object_object_add(payload, "sub", json_object_new_string(subject));
    json_object_object_add(payload, "aud", json_object_new_string(audience));
    json_object_object_add(payload, "iat", json_object_new_int64(now));
    json_object_object_add(payload, "exp", json_object_new_int64(now + expires_in_seconds));
    const char *pay_str = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);

    // base64url-encode header and payload
    size_t hdr_b64_len = sodium_base64_ENCODED_LEN(strlen(hdr_str), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *hdr_b64 = (char *)malloc(hdr_b64_len);
    sodium_bin2base64(hdr_b64, hdr_b64_len,
                      (const unsigned char *)hdr_str, strlen(hdr_str),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    size_t pay_b64_len = sodium_base64_ENCODED_LEN(strlen(pay_str), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *pay_b64 = (char *)malloc(pay_b64_len);
    sodium_bin2base64(pay_b64, pay_b64_len,
                      (const unsigned char *)pay_str, strlen(pay_str),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    // form signing input: header.payload
    std::string signing_input = std::string(hdr_b64) + "." + std::string(pay_b64);

    // RS256 sign
    char sig[512];
    size_t sig_len = sizeof(sig);
    REQUIRE(pk->sign(pk, hash_SHA256,
                     signing_input.c_str(), signing_input.size(),
                     sig, &sig_len) == 0);

    // base64url-encode signature
    size_t sig_b64_len = sodium_base64_ENCODED_LEN(sig_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *sig_b64 = (char *)malloc(sig_b64_len);
    sodium_bin2base64(sig_b64, sig_b64_len,
                      (const unsigned char *)sig, sig_len,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    std::string jwt = signing_input + "." + std::string(sig_b64);

    free(hdr_b64);
    free(pay_b64);
    free(sig_b64);
    json_object_put(hdr);
    json_object_put(payload);
    pk->free(pk);

    return jwt;
}

// Generate a unique subject for each test invocation to avoid ALREADY_ENROLLED
static std::string unique_subject(const char *prefix) {
    return std::string(prefix) + "-" + std::to_string(time(nullptr));
}

struct enroll_token_ctx {
    bool called{false};
    ziti_enrollment_cert_resp *resp{nullptr};
    ziti_error error{};

    ~enroll_token_ctx() {
        free_ziti_error(&error);
        if (resp) {
            free_ziti_enrollment_cert_resp_ptr(resp);
        }
    }
};

static void enroll_token_cb(ziti_enrollment_cert_resp *r, const ziti_error *err, void *ctx) {
    auto *c = static_cast<enroll_token_ctx *>(ctx);
    c->called = true;
    c->resp = r;
    if (err) {
        c->error.err = err->err;
        c->error.http_code = err->http_code;
        if (err->message) c->error.message = strdup(err->message);
        if (err->code) c->error.code = strdup(err->code);
    }
}

// Helper: set up a controller connection using the test client's CA
struct ctrl_setup {
    ziti_config cfg{};
    tls_context *tls{nullptr};
    ziti_controller ctrl{};

    void init(uv_loop_t *loop) {
        REQUIRE(ziti_load_config(&cfg, TEST_CLIENT) == ZITI_OK);
        tls = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
        REQUIRE(ziti_ctrl_init(loop, &ctrl, &cfg.controllers, tls) == ZITI_OK);
    }

    ~ctrl_setup() {
        ziti_ctrl_close(&ctrl);
        if (tls) tls->free_ctx(tls);
        free_ziti_config(&cfg);
    }
};

#endif // ZITI_SDK_ENROLL_TEST_HELPERS_H
