// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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

// Pure-C shim for the tests that need what zt_internal.h has: that header cannot be included from a
// C++ translation unit (see tests/integ/api_session_retry_test_helper.c for why).

#include "zt_internal.h"
#include "oidc.h"
#include "connect.h"
#include "posture.h"
#include "auth_queries.h"

// The OIDC client treats the failures of a login as temporary for a window (a minute), then reports them. Shortens the
// window of the context, and the one that is open already: the first failure may come before the test can call this.
int ztx_test_oidc_retry_window(ziti_context ztx, uint64_t window_ms) {
    if (ztx->auth_method == NULL || ztx->auth_method->kind != OIDC) {
        return UV_EINVAL;
    }
    oidc_client_t *clt = container_of(ztx->auth_method, oidc_client_t, api);
    clt->auth_retry_window = window_ms;
    uint64_t latest = uv_now(ztx->loop) + window_ms;
    if (clt->auth_retry_until > latest) {
        clt->auth_retry_until = latest;
    }
    return 0;
}

// The retry of a login that waits for the end of its backoff does not come: stands for a backoff that is longer than the
// test. A request that is in flight arms the retry again when it fails, so a test that wants no retry calls this on every turn.
int ztx_test_oidc_cancel_retry(ziti_context ztx) {
    if (ztx->auth_method == NULL || ztx->auth_method->kind != OIDC) {
        return UV_EINVAL;
    }
    oidc_client_t *clt = container_of(ztx->auth_method, oidc_client_t, api);
    if (clt->timer == NULL) {
        return UV_EINVAL;
    }
    return uv_timer_stop(clt->timer);
}

// how many failures in a row the retry of the authentication has counted
int ztx_test_auth_retries(ziti_context ztx) {
    return ztx->auth_retries;
}

// the auth method reports that the api session is gone
void ztx_test_lose_session(ziti_context ztx) {
    ziti_error err = {.err = ZITI_AUTHENTICATION_FAILED, .message = "api session is gone"};
    ztx_auth_state_cb(ztx, ZitiAuthStateUnauthenticated, &err);
}

// the auth method reports that it has started to authenticate
void ztx_test_restart_auth(ziti_context ztx) {
    ztx_auth_state_cb(ztx, ZitiAuthStateAuthStarted, NULL);
}

// the auth method reports that it cannot authenticate, with the error of the failure (a libuv one when the network is away)
void ztx_test_auth_impossible(ziti_context ztx, int err) {
    ziti_error error = {.err = err, .message = "auth provider is not available"};
    ztx_auth_state_cb(ztx, ZitiAuthImpossibleToAuthenticate, &error);
}

// a re-bind of the listener is scheduled
bool ztx_test_rebind_pending(ziti_connection conn) {
    return conn->server.rebinder.expire_cb != NULL;
}

// A context that has no loop and no controller, with an auth method that only counts the codes it is given: for the
// control flow of ziti_mfa_auth(), which does not reach further than the auth method.
struct mfa_stub {
    ziti_auth_method_t method;
    int submits;
    int submit_rc;
    auth_mfa_cb pending;
    void (*verify_cb)(void *, const ziti_error *, void *);
    void *verify_ctx;
};

static int mfa_stub_submit(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb) {
    struct mfa_stub *stub = container_of(self, struct mfa_stub, method);
    stub->submits++;
    stub->pending = cb;
    return stub->submit_rc;
}

static int mfa_stub_verify(ziti_auth_method_t *self, const char *code,
                           void (*cb)(void *, const ziti_error *, void *), void *ctx) {
    struct mfa_stub *stub = container_of(self, struct mfa_stub, method);
    stub->submits++;
    stub->verify_cb = cb;
    stub->verify_ctx = ctx;
    return stub->submit_rc;
}

static int mfa_stub_refresh(ziti_auth_method_t *self) {
    return 0;
}

// `submit_rc`: what the auth method answers a code with, to ziti_mfa_auth() and to ziti_mfa_verify() (ZITI_OK: the
// code is taken, the answer comes with ztx_test_mfa_stub_report / ztx_test_mfa_stub_verify_report)
ziti_context ztx_test_mfa_stub_new(int submit_rc, bool oidc, bool fully_authenticated) {
    ziti_context ztx = calloc(1, sizeof(*ztx));
    struct mfa_stub *stub = calloc(1, sizeof(*stub));
    stub->method.kind = oidc ? OIDC : LEGACY;
    stub->method.submit_mfa = mfa_stub_submit;
    stub->method.verify_mfa = mfa_stub_verify;
    stub->method.force_refresh = mfa_stub_refresh;
    stub->submit_rc = submit_rc;
    ztx->auth_method = &stub->method;
    ztx->enabled = true;
    ztx->auth_state = fully_authenticated ? ZitiAuthStateFullyAuthenticated : ZitiAuthStateUnauthenticated;
    return ztx;
}

void ztx_test_mfa_stub_free(ziti_context ztx) {
    cstr_drop(&ztx->totp_code);
    free(container_of(ztx->auth_method, struct mfa_stub, method));
    free(ztx);
}

// what the auth method answers the next code with
void ztx_test_mfa_stub_set_rc(ziti_context ztx, int submit_rc) {
    container_of(ztx->auth_method, struct mfa_stub, method)->submit_rc = submit_rc;
}

// the auth method reports that the code of ziti_mfa_verify() was not accepted
void ztx_test_mfa_stub_verify_report_error(ziti_context ztx, int err) {
    struct mfa_stub *stub = container_of(ztx->auth_method, struct mfa_stub, method);
    ziti_error error = {.err = err, .http_code = 400, .code = "MFA_INVALID_TOKEN", .message = "stub"};
    stub->verify_cb(NULL, &error, stub->verify_ctx);
}

// the auth method reports that the code of ziti_mfa_verify() was accepted
void ztx_test_mfa_stub_verify_report_ok(ziti_context ztx) {
    struct mfa_stub *stub = container_of(ztx->auth_method, struct mfa_stub, method);
    stub->verify_cb(NULL, NULL, stub->verify_ctx);
}

int ztx_test_mfa_stub_submits(ziti_context ztx) {
    return container_of(ztx->auth_method, struct mfa_stub, method)->submits;
}

// the auth method reports how the code it took was received
void ztx_test_mfa_stub_report(ziti_context ztx, int status) {
    struct mfa_stub *stub = container_of(ztx->auth_method, struct mfa_stub, method);
    auth_mfa_cb cb = stub->pending;
    stub->pending = NULL;
    cb(ztx, status);
}

// ziti_mfa_auth() / ziti_mfa_verify() of an identity that logs in with OIDC and has no login waiting for a code, on a
// context that runs another auth method (the fake controllers authenticate the legacy way): the method only looks like
// the OIDC one while the call is on the stack, which is the part that looks at it.
static void as_oidc(ziti_context ztx, void (*fn)(ziti_context, const char *, ziti_mfa_cb, void *),
                    const char *code, ziti_mfa_cb cb, void *ctx) {
    ziti_auth_method_t *method = ztx->auth_method;
    enum AuthenticationMethod kind = method->kind;

    method->kind = OIDC;
    fn(ztx, code, cb, ctx);
    method->kind = kind;
}

void ztx_test_mfa_auth_without_login(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx) {
    as_oidc(ztx, ziti_mfa_auth, code, cb, ctx);
}

void ztx_test_mfa_verify_without_login(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx) {
    as_oidc(ztx, ziti_mfa_verify, code, cb, ctx);
}

// the TOTP code a login took and has not finished with, "" when none
const char *ztx_test_totp_code(ziti_context ztx) {
    return cstr_str(&ztx->totp_code);
}

// the auth method reports that the (re)authentication is complete, with a new api session token
void ztx_test_reauthenticated(ziti_context ztx) {
    ztx_auth_state_cb(ztx, ZitiAuthStateFullyAuthenticated, "fake-token-2");
}

// the TOTP token the posture state keeps for the routers, "" when there is none
const char *ztx_test_totp_token(ziti_context ztx) {
    return ztx->posture_checks ? cstr_str(&ztx->posture_checks->totp.token) : "";
}
