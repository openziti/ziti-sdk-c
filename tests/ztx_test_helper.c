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
