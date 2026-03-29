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

    // build header: {"alg":"RS256","typ":"JWT"}
    json_object *hdr = json_object_new_object();
    json_object_object_add(hdr, "alg", json_object_new_string("RS256"));
    json_object_object_add(hdr, "typ", json_object_new_string("JWT"));
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
    ziti_create_api_cert_resp *resp{nullptr};
    ziti_error error{};

    ~enroll_token_ctx() {
        free_ziti_error(&error);
        if (resp) {
            free_ziti_create_api_cert_resp_ptr(resp);
        }
    }
};

static void enroll_token_cb(ziti_create_api_cert_resp *r, const ziti_error *err, void *ctx) {
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
    CHECK(ctx.error.err == 0);
    // no CSR sent, so no client cert expected
    if (ctx.resp) {
        CHECK(ctx.resp->client_cert_pem == nullptr);
    }
}


TEST_CASE_METHOD(LoopTestCase, "enroll-token-already-enrolled", "[integ][enroll-token]") {
    ctrl_setup cs;
    cs.init(loop());

    auto sub = unique_subject("enroll-dup");
    auto jwt = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    // first enrollment should succeed
    enroll_token_ctx ctx1;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt.c_str(), nullptr, enroll_token_cb, &ctx1);
    uv_run(loop(), UV_RUN_DEFAULT);
    REQUIRE(ctx1.called);
    REQUIRE(ctx1.error.err == 0);

    // second enrollment with same sub should fail
    auto jwt2 = sign_test_jwt(cs.tls, TEST_JWT_SIGNER_KEY,
                              TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                              TEST_JWT_SIGNER_AUDIENCE, 300);

    enroll_token_ctx ctx2;
    ziti_ctrl_enroll_token(&cs.ctrl, jwt2.c_str(), nullptr, enroll_token_cb, &ctx2);
    uv_run(loop(), UV_RUN_DEFAULT);

    REQUIRE(ctx2.called);
    CHECK(ctx2.error.err != 0);
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
    json_object *hdr = json_object_new_object();
    json_object_object_add(hdr, "alg", json_object_new_string("RS256"));
    json_object_object_add(hdr, "typ", json_object_new_string("JWT"));
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


// Full ziti_context lifecycle tests

struct ztx_enroll_ctx {
    bool auth_select{false};
    bool config_received{false};
    bool auth_failed{false};
    std::string signer_name;
    std::string cert_pem;
    std::string key_pem;
    std::string jwt;
    tls_context *tls{nullptr};

    static void event_cb(ziti_context ztx, const ziti_event_t *event) {
        auto *ctx = static_cast<ztx_enroll_ctx *>(ziti_app_ctx(ztx));

        switch (event->type) {
            case ZitiAuthEvent:
                if (event->auth.action == ziti_auth_select_external) {
                    // signer list arrived - pick ours and feed the JWT
                    ctx->auth_select = true;
                    for (int i = 0; event->auth.providers && event->auth.providers[i]; i++) {
                        if (event->auth.providers[i]->can_cert_enroll) {
                            ctx->signer_name = event->auth.providers[i]->name;
                            ziti_use_ext_jwt_signer(ztx, ctx->signer_name.c_str());
                            ziti_ext_auth_token(ztx, ctx->jwt.c_str());
                            return;
                        }
                    }
                } else if (event->auth.action == ziti_auth_login_external) {
                    // OIDC ready but we bypass browser - feed JWT directly
                    ziti_ext_auth_token(ztx, ctx->jwt.c_str());
                } else if (event->auth.action == ziti_auth_cannot_continue) {
                    ctx->auth_failed = true;
                }
                break;

            case ZitiConfigEvent:
                if (event->cfg.config) {
                    if (event->cfg.config->id.cert)
                        ctx->cert_pem = event->cfg.config->id.cert;
                    if (event->cfg.config->id.key)
                        ctx->key_pem = event->cfg.config->id.key;
                    ctx->config_received = true;
                }
                // shut down after receiving config
                ziti_shutdown(ztx);
                break;

            case ZitiContextEvent:
                if (event->ctx.ctrl_status != ZITI_OK && event->ctx.ctrl_status != ZITI_PARTIALLY_AUTHENTICATED) {
                    ctx->auth_failed = true;
                }
                break;

            default:
                break;
        }
    }
};


TEST_CASE("ztx-enroll-to-cert", "[integ][enroll-token]") {
    // load existing config just to get controller URL and CA
    ziti_config base_cfg{};
    REQUIRE(ziti_load_config(&base_cfg, TEST_CLIENT) == ZITI_OK);

    // build a config with no cert/key
    ziti_config cfg{};
    cfg.controller_url = base_cfg.controller_url;
    cfg.id.ca = base_cfg.id.ca;
    model_list_append(&cfg.controllers,
                      strdup((const char *)model_list_head(&base_cfg.controllers)));

    ziti_context ztx = nullptr;
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);

    // sign a JWT for this test
    auto tls = default_tls_context(base_cfg.id.ca, strlen(base_cfg.id.ca));
    auto sub = unique_subject("ztx-enroll-cert");
    auto jwt = sign_test_jwt(tls, TEST_JWT_SIGNER_KEY,
                             TEST_JWT_SIGNER_ISSUER, sub.c_str(),
                             TEST_JWT_SIGNER_AUDIENCE, 300);

    ztx_enroll_ctx ctx;
    ctx.jwt = jwt;
    ctx.tls = tls;

    ziti_options opts{};
    opts.app_ctx = &ctx;
    opts.events = ZitiAuthEvent | ZitiConfigEvent | ZitiContextEvent;
    opts.event_cb = ztx_enroll_ctx::event_cb;
    ziti_context_set_options(ztx, &opts);

    auto l = uv_loop_new();
    ziti_context_run(ztx, l);

    // run until config event or failure (with timeout)
    auto deadline = uv_hrtime() + (uint64_t)30e9; // 30s
    while (!ctx.config_received && !ctx.auth_failed && uv_hrtime() < deadline) {
        uv_run(l, UV_RUN_ONCE);
    }

    if (!ctx.config_received) {
        ziti_shutdown(ztx);
        uv_run(l, UV_RUN_DEFAULT);
    }

    CHECK(ctx.auth_select);
    REQUIRE(ctx.config_received);
    CHECK(!ctx.cert_pem.empty());
    CHECK(!ctx.key_pem.empty());

    // verify the cert is loadable
    tlsuv_certificate_t cert = nullptr;
    CHECK(tls->load_cert(&cert, ctx.cert_pem.c_str(), ctx.cert_pem.size()) == 0);
    if (cert) cert->free(cert);

    uv_run(l, UV_RUN_DEFAULT);
    uv_loop_close(l);
    free(l);
    tls->free_ctx(tls);
    free_ziti_config(&base_cfg);
}
