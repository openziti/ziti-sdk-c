/*
Copyright (c) 2020 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef ZITI_SDK_AUTH_QUERIES_H
#define ZITI_SDK_AUTH_QUERIES_H

#include <uv.h>
#include "zt_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "zt_internal.h"
#include <utils.h>

typedef struct ziti_mfa_auth_ctx_s ziti_mfa_auth_ctx;

struct auth_queries {
    ziti_mfa_auth_ctx *outstanding_auth_query_ctx;
};

extern void ziti_auth_query_init(struct ziti_ctx *ztx);
extern void ziti_auth_query_free(struct auth_queries* aq);
extern void ziti_send_event(ziti_context ztx, const ziti_event_t *e);

// Exchanges a TOTP code for a TOTP token at the controller (OIDC api sessions) and hands the token to the posture
// responses for the routers. cb (may be NULL) gets ZITI_OK once the token is kept and its send is due, the controller's
// error otherwise (ZITI_MFA_INVALID_TOKEN, ZITI_MFA_NOT_ENROLLED, ...), ZITI_INVALID_STATE at once
// when the context is not fully authenticated.
extern void ztx_mfa_request_totp_token(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx);

// The api session that an OIDC login creates needs a TOTP token, and the controller gives one for a code. The login takes
// the code and the session comes later, so once the login has taken the code the context keeps a copy of it until the
// login is over: ztx_mfa_keep_code() when the login took it, ztx_mfa_drop_code() (wipes it) when the login turns it
// down or fails, ztx_mfa_token_for_login() when the context is fully authenticated: asks for the token, wipes the code.
extern void ztx_mfa_keep_code(ziti_context ztx, const char *code);
extern void ztx_mfa_drop_code(ziti_context ztx);
extern void ztx_mfa_token_for_login(ziti_context ztx);

#ifdef __cplusplus
}
#endif


#endif //ZITI_SDK_AUTH_QUERIES_H
