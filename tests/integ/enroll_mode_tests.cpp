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
#include "auth_method.h"


// === Happy Path Tests ===

TEST_CASE_METHOD(LoopTestCase, "enroll-cert-then-list-services", "[integ][enroll-mode]") {
    ctrl_setup cs;
    cs.init(loop());

    // generate keypair + CSR
    tlsuv_private_key_t pk = nullptr;
    REQUIRE(cs.tls->generate_key(&pk) == 0);

    char *csr = nullptr;
    size_t csr_len = 0;
    REQUIRE(cs.tls->generate_csr_to_pem(pk, &csr, &csr_len,
                                         "O", "OpenZiti",
                                         "CN", "test-cert-svc",
                                         NULL) == 0);

    auto sub = unique_subject("cert-svc");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    // enroll with CSR
    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), csr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    REQUIRE(ctx.error.err == 0);
    REQUIRE(ctx.resp != nullptr);
    REQUIRE(ctx.resp->client_cert_pem != nullptr);

    // build mTLS context with enrolled cert
    const char *ca = ctx.resp->cas_pem ? ctx.resp->cas_pem : cs.cfg.id.ca;
    auto mtls_tls = default_tls_context(ca, strlen(ca));

    tlsuv_certificate_t cert = nullptr;
    REQUIRE(mtls_tls->load_cert(&cert, ctx.resp->client_cert_pem,
                                strlen(ctx.resp->client_cert_pem)) == 0);
    REQUIRE(mtls_tls->set_own_cert(mtls_tls, pk, cert) == 0);
    pk = nullptr; // ownership transferred

    // connect and authenticate with the new cert
    ziti_controller mtls_ctrl{};
    REQUIRE(ziti_ctrl_init(loop(), &mtls_ctrl, &cs.cfg.controllers, mtls_tls) == ZITI_OK);

    auto *auth = new_legacy_auth(loop(), cs.cfg.controller_url, mtls_tls, true);
    auto token = auth_login(auth, loop());
    REQUIRE(!token.empty());
    ziti_ctrl_set_token(&mtls_ctrl, token.c_str());

    // list services - verify the identity is functional
    auto services = ctrl_get(mtls_ctrl, ziti_ctrl_get_services);
    // services may be empty (no role attributes on auto-created identity) but should not error

    if (services) {
        free_ziti_service_array(&services);
    }

    auth->stop(auth);
    auth->free(auth);
    ziti_ctrl_close(&mtls_ctrl);
    mtls_tls->free_ctx(mtls_tls);
    free(csr);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-then-list-services", "[integ][enroll-mode]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("token-svc");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_TOKEN_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    // enroll without CSR (enrollToToken)
    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    REQUIRE(ctx.error.err == 0);
    // no cert returned for token enrollment
    if (ctx.resp) {
        CHECK(ctx.resp->client_cert_pem == nullptr);
    }

    // authenticate with JWT bearer token
    ziti_ctrl_set_ext_token(&cs.ctrl, jwt.c_str());

    // verify identity exists
    auto identity = ctrl_get(cs.ctrl, ziti_ctrl_current_identity);
    REQUIRE(identity != nullptr);
    free_ziti_identity_data_ptr(identity);

    // list services
    auto services = ctrl_get(cs.ctrl, ziti_ctrl_get_services);
    if (services) {
        free_ziti_service_array(&services);
    }
}


TEST_CASE_METHOD(LoopTestCase, "enroll-none-precreated-list-services", "[integ][enroll-mode]") {
    ctrl_setup cs;
    cs.init(loop());

    // sign JWT with subject matching the pre-created identity
    // the pre-created identity uses external ID matching, so subject = identity name
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, "test-precreated",
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    // no enrollment call - just set JWT as bearer
    ziti_ctrl_set_ext_token(&cs.ctrl, jwt.c_str());

    // verify identity
    auto identity = ctrl_get(cs.ctrl, ziti_ctrl_current_identity);
    REQUIRE(identity != nullptr);
    CHECK(std::string(identity->name) == "test-precreated");
    free_ziti_identity_data_ptr(identity);

    // list services - should include test-service (identity has client attribute)
    auto services = ctrl_get(cs.ctrl, ziti_ctrl_get_services);
    REQUIRE(services != nullptr);

    bool found_service = false;
    for (int i = 0; services[i] != nullptr; i++) {
        if (std::string(services[i]->name) == TEST_SERVICE) {
            found_service = true;
        }
    }
    CHECK(found_service);

    free_ziti_service_array(&services);
}


// === Non-Happy Path Tests ===

TEST_CASE_METHOD(LoopTestCase, "enroll-token-already-enrolled", "[integ][enroll-mode]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("token-dup");
    auto jwt1 = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                              TEST_JWT_TOKEN_SIGNER_ISSUER, sub.c_str(),
                              TEST_JWT_SIGNER_AUDIENCE, 300);

    // first enrollment should succeed
    enroll_token_ctx ctx1;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt1.c_str(), nullptr, enroll_token_cb, &ctx1);
    uv_run(loop(), UV_RUN_DEFAULT);
    REQUIRE(ctx1.called);
    REQUIRE(ctx1.error.err == 0);

    // second enrollment with same sub should fail
    auto jwt2 = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                              TEST_JWT_TOKEN_SIGNER_ISSUER, sub.c_str(),
                              TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx2;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt2.c_str(), nullptr, enroll_token_cb, &ctx2);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx2.called);
    CHECK(ctx2.error.err != 0);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-cert-with-token-only-signer", "[integ][enroll-mode]") {
    ctrl_setup cs;
    cs.init(loop());

    // generate CSR
    tlsuv_private_key_t pk = nullptr;
    REQUIRE(cs.tls->generate_key(&pk) == 0);

    char *csr = nullptr;
    size_t csr_len = 0;
    REQUIRE(cs.tls->generate_csr_to_pem(pk, &csr, &csr_len,
                                         "O", "OpenZiti",
                                         "CN", "test-wrong-signer",
                                         NULL) == 0);

    auto sub = unique_subject("cert-wrong");
    // use the token-only signer issuer with a CSR - should be rejected
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_TOKEN_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), csr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    CHECK(ctx.error.err != 0);

    free(csr);
    pk->free(pk);
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-expired-jwt", "[integ][enroll-mode]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("token-expired");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_TOKEN_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, -60); // expired

    enroll_token_ctx ctx;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx.called);
    CHECK(ctx.error.err != 0);
}
