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
