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

#include "enroll_test_helpers.h"


TEST_CASE_METHOD(LoopTestCase, "enroll-token-happy-path", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    // generate local keypair + CSR
    tlsuv_private_key_t pk = nullptr;
    REQUIRE(cs.tls->generate_key(&pk) == 0);

    char *csr = nullptr;
    size_t csr_len = 0;
    REQUIRE(cs.tls->generate_csr_to_pem(pk, &csr, &csr_len,
                                         "O", "OpenZiti",
                                         "CN", "test-enroll-cert",
                                         NULL) == 0);

    auto sub = unique_subject("enroll-cert-happy");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), csr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    CHECK(ctx.error.err == 0);
    REQUIRE(ctx.resp != nullptr);
    CHECK(ctx.resp->client_cert_pem != nullptr);

    // verify the returned cert can be loaded
    if (ctx.resp->client_cert_pem) {
        tlsuv_certificate_t cert = nullptr;
        CHECK(cs.tls->load_cert(&cert, ctx.resp->client_cert_pem,
                                strlen(ctx.resp->client_cert_pem)) == 0);
        if (cert) cert->free(cert);
    }

    free(csr);
    pk->free(pk);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-then-mtls", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    // generate keypair + CSR
    tlsuv_private_key_t pk = nullptr;
    REQUIRE(cs.tls->generate_key(&pk) == 0);

    char *csr = nullptr;
    size_t csr_len = 0;
    REQUIRE(cs.tls->generate_csr_to_pem(pk, &csr, &csr_len,
                                         "O", "OpenZiti",
                                         "CN", "test-mtls-enroll",
                                         NULL) == 0);

    auto sub = unique_subject("enroll-cert-mtls");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), csr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    REQUIRE(ctx.error.err == 0);
    REQUIRE(ctx.resp != nullptr);
    REQUIRE(ctx.resp->client_cert_pem != nullptr);

    // build a new TLS context with the returned cert + our key
    const char *ca = ctx.resp->cas_pem ? ctx.resp->cas_pem : cs.cfg.id.ca;
    auto mtls_tls = default_tls_context(ca, strlen(ca));

    tlsuv_certificate_t cert = nullptr;
    REQUIRE(mtls_tls->load_cert(&cert, ctx.resp->client_cert_pem,
                                strlen(ctx.resp->client_cert_pem)) == 0);
    REQUIRE(mtls_tls->set_own_cert(mtls_tls, pk, cert) == 0);
    pk = nullptr; // ownership transferred

    // connect to controller with the new cert and verify we can authenticate
    ziti_controller mtls_ctrl{};
    REQUIRE(ziti_ctrl_init(loop(), &mtls_ctrl, &cs.cfg.controllers, mtls_tls) == ZITI_OK);

    auto ver = ctrl_get(mtls_ctrl, ziti_ctrl_get_version);
    CHECK(ver != nullptr);

    ziti_ctrl_close(&mtls_ctrl);
    mtls_tls->free_ctx(mtls_tls);
    free(csr);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-no-csr", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("enroll-token-only");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    // signer only has enrollToCert, not enrollToToken - no CSR should be rejected
    CHECK(ctx.error.err != 0);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-already-enrolled", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    // generate a CSR for enrollment
    tlsuv_private_key_t pk = nullptr;
    REQUIRE(cs.tls->generate_key(&pk) == 0);
    char *csr = nullptr;
    size_t csr_len = 0;
    REQUIRE(cs.tls->generate_csr_to_pem(pk, &csr, &csr_len,
                                         "O", "OpenZiti",
                                         "CN", "test-dup-enroll",
                                         NULL) == 0);

    auto sub = unique_subject("enroll-dup");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    // first enrollment should succeed
    enroll_token_ctx ctx1;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), csr, enroll_token_cb, &ctx1);
    uv_run(loop(), UV_RUN_DEFAULT);
    REQUIRE(ctx1.called);
    REQUIRE(ctx1.error.err == 0);

    // second enrollment with same sub should fail
    auto jwt2 = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                              TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                              TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx2;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt2.c_str(), csr, enroll_token_cb, &ctx2);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx2.called);
    CHECK(ctx2.error.err != 0);

    free(csr);
    pk->free(pk);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-expired-jwt", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("enroll-expired");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, -60); // expired 60s ago

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    CHECK(ctx.error.err != 0);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-wrong-issuer", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("enroll-bad-iss");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             "https://unknown-issuer.example.com", sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    CHECK(ctx.error.err != 0);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-wrong-key", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    // generate a throwaway key not registered with the controller
    tlsuv_private_key_t bad_pk = nullptr;
    REQUIRE(cs.tls->generate_key(&bad_pk) == 0);
    char *bad_key_pem = nullptr;
    size_t bad_key_len = 0;
    REQUIRE(bad_pk->to_pem(bad_pk, &bad_key_pem, &bad_key_len) == 0);

    // sign JWT with the unregistered key (can't use sign_test_jwt since
    // it loads from file - build the JWT inline)
    char *kid_buf = nullptr;
    size_t kid_len = 0;
    REQUIRE(load_file(TEST_JWT_SIGNER_KID, strlen(TEST_JWT_SIGNER_KID), &kid_buf, &kid_len) == 0);
    while (kid_len > 0 && (kid_buf[kid_len-1] == '\n' || kid_buf[kid_len-1] == '\r')) {
        kid_buf[--kid_len] = '\0';
    }

    json_object *hdr = json_object_new_object();
    json_object_object_add(hdr, "alg", json_object_new_string("RS256"));
    json_object_object_add(hdr, "typ", json_object_new_string("JWT"));
    json_object_object_add(hdr, "kid", json_object_new_string(kid_buf));
    free(kid_buf);
    const char *hdr_str = json_object_to_json_string_ext(hdr, JSON_C_TO_STRING_PLAIN);

    auto now = (int64_t)time(nullptr);
    auto sub = unique_subject("enroll-bad-key");
    json_object *payload = json_object_new_object();
    json_object_object_add(payload, "iss", json_object_new_string(TEST_JWT_SIGNER_ISSUER));
    json_object_object_add(payload, "sub", json_object_new_string(sub.c_str()));
    json_object_object_add(payload, "aud", json_object_new_string(TEST_JWT_SIGNER_AUDIENCE));
    json_object_object_add(payload, "iat", json_object_new_int64(now));
    json_object_object_add(payload, "exp", json_object_new_int64(now + 300));
    const char *pay_str = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);

    size_t hdr_b64_len = sodium_base64_ENCODED_LEN(strlen(hdr_str), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *hdr_b64 = (char *)malloc(hdr_b64_len);
    sodium_bin2base64(hdr_b64, hdr_b64_len, (const unsigned char *)hdr_str, strlen(hdr_str),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    size_t pay_b64_len = sodium_base64_ENCODED_LEN(strlen(pay_str), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *pay_b64 = (char *)malloc(pay_b64_len);
    sodium_bin2base64(pay_b64, pay_b64_len, (const unsigned char *)pay_str, strlen(pay_str),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    std::string signing_input = std::string(hdr_b64) + "." + std::string(pay_b64);

    char sig[512];
    size_t sig_len = sizeof(sig);
    REQUIRE(bad_pk->sign(bad_pk, hash_SHA256,
                         signing_input.c_str(), signing_input.size(),
                         sig, &sig_len) == 0);

    size_t sig_b64_len = sodium_base64_ENCODED_LEN(sig_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *sig_b64 = (char *)malloc(sig_b64_len);
    sodium_bin2base64(sig_b64, sig_b64_len, (const unsigned char *)sig, sig_len,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    std::string jwt = signing_input + "." + std::string(sig_b64);

    free(hdr_b64);
    free(pay_b64);
    free(sig_b64);
    json_object_put(hdr);
    json_object_put(payload);
    free(bad_key_pem);
    bad_pk->free(bad_pk);

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    CHECK(ctx.error.err != 0);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-wrong-audience", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("enroll-bad-aud");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             "wrong-audience", 300);

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    CHECK(ctx.error.err != 0);
}


// TODO: add full ziti_context lifecycle test for enrollToCert
// Needs to handle the async context lifecycle and config event timing
// correctly. The Phase 1 tests above verify the controller API directly.
