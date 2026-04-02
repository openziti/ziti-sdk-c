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


// === Lifecycle Tests (full ziti_context with OIDC via Keycloak) ===

static bool keycloak_available() {
    FILE *f = fopen(TEST_KEYCLOAK_AVAILABLE, "r");
    if (!f) return false;
    char buf[8];
    bool available = fgets(buf, sizeof(buf), f) && buf[0] == '1';
    fclose(f);
    return available;
}

// Get an access token from Keycloak via Resource Owner Password Credentials grant
static std::string get_keycloak_token() {
    std::string cmd = "curl -sf -X POST "
        "'" TEST_KEYCLOAK_URL "/realms/" TEST_KEYCLOAK_REALM "/protocol/openid-connect/token' "
        "-d 'grant_type=password"
        "&client_id=" TEST_KEYCLOAK_CLIENT_ID
        "&username=" TEST_KEYCLOAK_USERNAME
        "&password=" TEST_KEYCLOAK_PASSWORD
        "&scope=openid' 2>/dev/null";

    FILE *fp = popen(cmd.c_str(), "r");
    REQUIRE(fp != nullptr);

    char buf[8192];
    std::string result;
    while (fgets(buf, sizeof(buf), fp)) {
        result += buf;
    }
    int status = pclose(fp);
    REQUIRE(status == 0);

    // extract access_token from JSON response
    json_object *resp = json_tokener_parse(result.c_str());
    REQUIRE(resp != nullptr);

    json_object *token_obj = nullptr;
    REQUIRE(json_object_object_get_ex(resp, "access_token", &token_obj));
    std::string token = json_object_get_string(token_obj);
    json_object_put(resp);

    REQUIRE(!token.empty());
    return token;
}

// State for lifecycle test event handling
struct lifecycle_state {
    uv_loop_t *loop;
    std::string token;           // pre-obtained Keycloak token
    std::string signer_name;     // OIDC signer to select
    bool config_received{false};
    bool auth_ok{false};
    bool auth_failed{false};
    const ziti_config *saved_config{nullptr};
    std::string error_msg;
};

static void lifecycle_event_cb(ziti_context ztx, const ziti_event_t *ev) {
    auto *state = static_cast<lifecycle_state *>(ziti_app_ctx(ztx));

    if (ev->type == ZitiAuthEvent) {
        if (ev->auth.action == ziti_auth_select_external) {
            // select the OIDC signer and feed the pre-obtained token
            ziti_use_ext_jwt_signer(ztx, state->signer_name.c_str());
            ziti_ext_auth_token(ztx, state->token.c_str());
        } else if (ev->auth.action == ziti_auth_cannot_continue) {
            state->auth_failed = true;
            state->error_msg = ev->auth.error ? ev->auth.error : "unknown";
            ziti_shutdown(ztx);
        }
    } else if (ev->type == ZitiContextEvent) {
        if (ev->ctx.ctrl_status == ZITI_OK) {
            state->auth_ok = true;
            // for non-cert modes, auth success is the end goal
            if (!state->config_received) {
                ziti_shutdown(ztx);
            }
        } else if (ev->ctx.ctrl_status != ZITI_PARTIALLY_AUTHENTICATED) {
            state->auth_failed = true;
            state->error_msg = ev->ctx.err ? ev->ctx.err : "unknown";
            ziti_shutdown(ztx);
        }
    } else if (ev->type == ZitiConfigEvent) {
        state->saved_config = ev->cfg.config;
        state->config_received = true;
        if (ev->cfg.config->id.cert) {
            // cert mode: got the cert, we're done
            ziti_shutdown(ztx);
        }
    }
}

TEST_CASE_METHOD(LoopTestCase, "ztx-enroll-cert-lifecycle", "[integ][enroll-mode][lifecycle]") {
    if (!keycloak_available()) { SKIP("Keycloak not available"); }
    auto kc_token = get_keycloak_token();

    // load CA from test client config
    ziti_config client_cfg{};
    REQUIRE(ziti_load_config(&client_cfg, TEST_CLIENT) == ZITI_OK);

    // build bootstrap config (CA + controller URL only, no cert/key)
    ziti_config bootstrap_cfg{};
    bootstrap_cfg.id.ca = strdup(client_cfg.id.ca);
    model_list_append(&bootstrap_cfg.controllers, strdup(client_cfg.controller_url));

    ziti_context ztx = nullptr;
    REQUIRE(ziti_context_init(&ztx, &bootstrap_cfg) == ZITI_OK);

    lifecycle_state state{};
    state.loop = loop();
    state.token = kc_token;
    state.signer_name = "test-oidc-signer";

    ziti_options opts{};
    opts.app_ctx = &state;
    opts.events = ZitiContextEvent | ZitiAuthEvent | ZitiConfigEvent;
    opts.event_cb = lifecycle_event_cb;
    opts.enroll_mode = ziti_enroll_cert;
    ziti_context_set_options(ztx, &opts);

    ziti_context_run(ztx, loop());

    // add a timeout to avoid hanging
    uv_timer_t timer;
    uv_timer_init(loop(), &timer);
    timer.data = loop();
    uv_timer_start(&timer, [](uv_timer_t *t) {
        uv_stop((uv_loop_t *)t->data);
    }, 30000, 0);

    uv_run(loop(), UV_RUN_DEFAULT);
    uv_timer_stop(&timer);
    uv_close((uv_handle_t *)&timer, nullptr);
    uv_run(loop(), UV_RUN_NOWAIT);

    INFO("error: " << state.error_msg);
    CHECK_FALSE(state.auth_failed);
    CHECK(state.config_received);
    // verify cert was received
    if (state.saved_config) {
        CHECK(state.saved_config->id.cert != nullptr);
        CHECK(state.saved_config->id.key != nullptr);
    }

    free((void *)bootstrap_cfg.id.ca);
    model_list_clear(&bootstrap_cfg.controllers, nullptr);
    free_ziti_config(&client_cfg);
}


TEST_CASE_METHOD(LoopTestCase, "ztx-enroll-token-lifecycle", "[integ][enroll-mode][lifecycle]") {
    if (!keycloak_available()) { SKIP("Keycloak not available"); }
    auto kc_token = get_keycloak_token();

    ziti_config client_cfg{};
    REQUIRE(ziti_load_config(&client_cfg, TEST_CLIENT) == ZITI_OK);

    ziti_config bootstrap_cfg{};
    bootstrap_cfg.id.ca = strdup(client_cfg.id.ca);
    model_list_append(&bootstrap_cfg.controllers, strdup(client_cfg.controller_url));

    ziti_context ztx = nullptr;
    REQUIRE(ziti_context_init(&ztx, &bootstrap_cfg) == ZITI_OK);

    lifecycle_state state{};
    state.loop = loop();
    state.token = kc_token;
    state.signer_name = "test-oidc-signer";

    ziti_options opts2{};
    opts2.app_ctx = &state;
    opts2.events = ZitiContextEvent | ZitiAuthEvent | ZitiConfigEvent;
    opts2.event_cb = lifecycle_event_cb;
    opts2.enroll_mode = ziti_enroll_token;
    ziti_context_set_options(ztx, &opts2);

    ziti_context_run(ztx, loop());

    uv_timer_t timer;
    uv_timer_init(loop(), &timer);
    timer.data = loop();
    uv_timer_start(&timer, [](uv_timer_t *t) {
        uv_stop((uv_loop_t *)t->data);
    }, 30000, 0);

    uv_run(loop(), UV_RUN_DEFAULT);
    uv_timer_stop(&timer);
    uv_close((uv_handle_t *)&timer, nullptr);
    uv_run(loop(), UV_RUN_NOWAIT);

    INFO("error: " << state.error_msg);
    CHECK_FALSE(state.auth_failed);
    CHECK(state.auth_ok);

    free((void *)bootstrap_cfg.id.ca);
    model_list_clear(&bootstrap_cfg.controllers, nullptr);
    free_ziti_config(&client_cfg);
}


TEST_CASE_METHOD(LoopTestCase, "ztx-enroll-none-lifecycle", "[integ][enroll-mode][lifecycle]") {
    if (!keycloak_available()) { SKIP("Keycloak not available"); }
    auto kc_token = get_keycloak_token();

    ziti_config client_cfg{};
    REQUIRE(ziti_load_config(&client_cfg, TEST_CLIENT) == ZITI_OK);

    ziti_config bootstrap_cfg{};
    bootstrap_cfg.id.ca = strdup(client_cfg.id.ca);
    model_list_append(&bootstrap_cfg.controllers, strdup(client_cfg.controller_url));

    ziti_context ztx = nullptr;
    REQUIRE(ziti_context_init(&ztx, &bootstrap_cfg) == ZITI_OK);

    lifecycle_state state{};
    state.loop = loop();
    state.token = kc_token;
    state.signer_name = "test-oidc-signer";

    ziti_options opts3{};
    opts3.app_ctx = &state;
    opts3.events = ZitiContextEvent | ZitiAuthEvent | ZitiConfigEvent;
    opts3.event_cb = lifecycle_event_cb;
    opts3.enroll_mode = ziti_enroll_none;
    ziti_context_set_options(ztx, &opts3);

    ziti_context_run(ztx, loop());

    uv_timer_t timer;
    uv_timer_init(loop(), &timer);
    timer.data = loop();
    uv_timer_start(&timer, [](uv_timer_t *t) {
        uv_stop((uv_loop_t *)t->data);
    }, 30000, 0);

    uv_run(loop(), UV_RUN_DEFAULT);
    uv_timer_stop(&timer);
    uv_close((uv_handle_t *)&timer, nullptr);
    uv_run(loop(), UV_RUN_NOWAIT);

    INFO("error: " << state.error_msg);
    CHECK_FALSE(state.auth_failed);
    CHECK(state.auth_ok);

    free((void *)bootstrap_cfg.id.ca);
    model_list_clear(&bootstrap_cfg.controllers, nullptr);
    free_ziti_config(&client_cfg);
}
