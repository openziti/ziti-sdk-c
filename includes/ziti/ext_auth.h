// Copyright (c) 2022-2024. NetFoundry Inc.
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

/**
 * @file ext_auth.h
 * @brief External JWT signers and external authentication.
 */

#ifndef ZITI_EXT_AUTH_H
#define ZITI_EXT_AUTH_H

#include "externs.h"
#include "handles.h"
#include "ziti_model.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ziti_ext_signers_cb)(ziti_context, int err, ziti_jwt_signer_array, void*);

/**
 * \brief Get a list of available external JWT signers.
 *
 * this list can be presented to the user to select provider
 * with which to continue authentication flow (via [ziti_use_ext_jwt_signer]).
 *
 * @param ztx ziti context
 * @param cb  callback for the result
 * @param ctx callback context
 * @return
 */
ZITI_FUNC
extern int ziti_get_ext_jwt_signers(ziti_context ztx, ziti_ext_signers_cb cb, void *ctx);

/**
 * \brief select external JWT signer to initiate OIDC authentication flow
 *
 * @param ztx ziti context
 * @param name name of JWT signer configured for the ziti network
 * @return
 */
ZITI_FUNC
extern int ziti_use_ext_jwt_signer(ziti_context ztx, const char *name);

/**
 * @brief Callback called by ziti_ext_auth to complete external authentication
 *
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param url the URL to open
 * @param ctx additional context to be passed into the original authentication call
 */
typedef void (*ziti_ext_auth_launch_cb)(ziti_context ztx, const char *url, void *ctx);

/**
 * @brief Name/value pair for additional ext-auth query parameters.
 */
typedef struct ziti_auth_query_param_s {
    const char *name;
    const char *value;
} ziti_auth_query_param;

/**
 * @brief Start authentication process with an external JWT signer.
 *
 * External signer must be selected via [ziti_use_ext_jwt_signer()] prior to calling this function.
 *
 * It is the application's responsibility to complete the authentication process by navigating user to
 * the URL provided in the [launch_cb] callback
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param launch_cb callback to complete authentication with the JWT provider
 * @param ctx additional context to be passed into the callback
 *
 * @see ziti_use_ext_jwt_signer()
 */
ZITI_FUNC
extern int ziti_ext_auth(ziti_context ztx, ziti_ext_auth_launch_cb launch_cb, void *ctx);

/**
 * @brief Set additional query parameters for external authentication.
 *
 * Parameters are appended to the authorize URL when the SDK starts the
 * OIDC flow with an external JWT signer. Call before ziti_ext_auth().
 *
 * @param ztx the handle to the Ziti Edge identity context
 * @param params array of name/value pairs (copied by the SDK)
 * @param count number of pairs in the array
 * @return #ZITI_OK or corresponding error
 */
ZITI_FUNC
extern int ziti_ext_auth_set_params(ziti_context ztx, const ziti_auth_query_param *params, int count);

/**
 * @brief Submit external authentication token
 *
 * This function is used to submit the token received from the external JWT signer
 * to complete authentication.
 *
 * This is an alternative to [ziti_ext_auth()] that allows application to manage the authentication flow.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param token the token received from the external JWT signer
 *
 * @return ZITI_OK, or ZITI_JWT_INVALID if the token cannot be parsed, has expired, or is the very token the
 *         controller has turned down and the context is waiting to replace: nothing is changed then,
 *         and the app is not asked for the login again
 *
 * @see ziti_ext_auth()
 */
ZITI_FUNC
extern int ziti_ext_auth_token(ziti_context ztx, const char *token);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_EXT_AUTH_H */
