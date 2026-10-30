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
 * @file mfa.h
 * @brief Multi-factor authentication (MFA): enrollment, verification, recovery codes and code submission.
 */

#ifndef ZITI_MFA_H
#define ZITI_MFA_H

#include <stdbool.h>

#include "externs.h"
#include "handles.h"
#include "ziti_model.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Whether the identity of the given context has completed MFA enrollment.
 *
 * This is what the controller reports for the identity: an enrollment that was started with
 * ziti_mfa_enroll() but not verified with ziti_mfa_verify() does not count. The context keeps the
 * answer up to date when ziti_mfa_verify() and ziti_mfa_remove() succeed.
 *
 * The state comes with the identity data that the context loads after it authenticates
 * (ziti_get_identity() returns non-NULL from then on), and is refreshed with it. Before the first load it is
 * not known and this returns false; after a re-authentication it is the last state loaded until the identity
 * data is loaded again.
 * @param ztx ziti context
 * @return true if MFA is enrolled for the identity
 */
ZITI_FUNC
extern bool ziti_is_mfa_enrolled(ziti_context ztx);

/**
 * @brief Callback called after ziti_mfa_enroll()
 *
 * This function is invoked after a call to ziti_mfa_enroll. It will contain either
 * a status error or an mfa_enrollment struct that will be free'ed after the call
 * back finishes.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status an error code or #ZITI_OK
 * @param mfa_enrollment contents of the mfa enrollment or NULL if status is an error
 * @param ctx additional context to be passed into #ziti_mfa_enroll_cb callback
 *
 */
typedef void (*ziti_mfa_enroll_cb)(ziti_context ztx, int status, ziti_mfa_enrollment *mfa_enrollment, void *ctx);

/**
 * @brief Generic callback called after various MFA functions
 *
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status an error code or #ZITI_OK
 * @param ctx additional context to be passed into the original mfa call
 */
typedef void (*ziti_mfa_cb)(ziti_context ztx, int status, void *ctx);

/**
 * @brief Callback called after ziti_mfa_get_recovery_codes() and ziti_mfa_new_recovery_codes()
 *
 * This function is invoked after a call to get or regenerate mfa recovery codes.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status an error code or #ZITI_OK
 * @param recovery_codes null terminated array of recovery codes
 * @param ctx additional context to be passed into to the original call
 *
 */
typedef void (*ziti_mfa_recovery_codes_cb)(ziti_context ztx, int status, const char **recovery_codes, void *ctx);

/**
 * @brief Attempts to initialize MFA enrollment
 *
 * Attempts to initialize enrollment. On success or failure the supplied enroll_cb
 * will be called with relevant status information. The supplied ztx must be have
 * passed a primary authentication mechanism (cert, updb, etc).
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param enroll_cb callback to receive MFA enrollment initialization status
 * @param ctx additional context to be passed into the enroll_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_enroll(ziti_context ztx, ziti_mfa_enroll_cb enroll_cb, void *ctx);

/**
 * @brief Attempts to remove MFA
 *
 * Attempts to remove MFA. On success or failure the supplied remove_cb
 * will be called with relevant status information. The supplied ztx must
 * be fully authenticated.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP or recovery code, may be empty string for MFA enrollments that have not completed via ziti_mfa_verify
 * @param remove_cb callback to receive MFA removal status
 * @param ctx additional context to be passed into the remove_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_remove(ziti_context ztx, const char *code, ziti_mfa_cb remove_cb, void *ctx);

/**
 * @brief Attempts to verify MFA enrollment
 *
 * Attempts to verify MFA enrollment. On success or failure the supplied verify_cb
 * will be called with relevant status information. The supplied ztx must
 * be authenticated. After verification, MFA enrollment is complete.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a valid TOTP code, must not be a recovery code
 * @param verify_cb callback to receive MFA verify status
 * @param ctx additional context to be passed into the verify_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_verify(ziti_context ztx, const char *code, ziti_mfa_cb verify_cb, void *ctx);


/**
 * @brief Attempts to retrieve the current recovery codes for the identity
 *
 * Attempts to retrieve the recovery codes for the current identity. On success or failure the supplied get_cb
 * will be called with relevant status information. The supplied ztx must be fully authenticated.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP code, may be empty string for MFA enrollments that have not completed vi ziti_mfa_verify
 * @param get_cb callback to receive the result status
 * @param ctx additional context to be passed into the get_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_get_recovery_codes(ziti_context ztx, const char *code, ziti_mfa_recovery_codes_cb get_cb, void *ctx);

/**
 * @brief Attempts to generate new recovery codes and retrieve the new recovery codes for MFA
 *
 * Attempts to generate new recovery codes. All previous codes will become invalid and replaced with the new
 * recovery codes. On success or failure the supplied get_cb will be called with relevant status information.
 * The supplied ztx must be fully authenticated.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP code
 * @param new_cb callback to receive the result status
 * @param ctx additional context to be passed into the get_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_new_recovery_codes(ziti_context ztx, char *code, ziti_mfa_recovery_codes_cb new_cb, void *ctx);

/**
 * @brief Attempt to submit an MFA code for evaluation
 *
 * Attempts submit an MFA code for evaluation. This should be done in response to
 * a `ZitiAuthEvent` with `ziti_auth_prompt_totp`, or when a `ZitiPostureStatusEvent` of
 * an MFA posture check (`ziti_posture_status_mfa_info`) says that no code was given
 * (`last_code_at` is 0) or that the code is expiring (`expiring`).
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success
 * via the `ziti_mfa_cb` provided.
 *
 * The code is accepted whenever the identity is authenticated, also when the controller is not asking for one
 * at the moment (a posture check that needs MFA came later, or its timeout ran out): with an OIDC
 * authentication the code is then exchanged for a TOTP token, which proves the MFA to the edge routers.
 * Errors reported through the callback include #ZITI_MFA_INVALID_TOKEN (the code was not accepted),
 * #ZITI_MFA_NOT_ENROLLED (the identity has no MFA enrollment), #ZITI_INVALID_STATE (the identity is
 * not authenticated, the controller is not asking for a code and takes none, or an earlier call is still
 * waiting for its result) and #ZITI_WTF (`code` is NULL).
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP code
 * @param auth_cb callback to receive the result status
 * @param ctx additional context to be passed into the callback
 */
ZITI_FUNC
extern void ziti_mfa_auth(ziti_context ztx, const char *code, ziti_mfa_cb auth_cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_MFA_H */
