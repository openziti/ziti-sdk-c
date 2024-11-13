// Copyright (c) 2024. NetFoundry Inc.
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

#ifndef ZITI_ENROLL_H
#define ZITI_ENROLL_H

#include <stdbool.h>
#include "ziti_model.h"

#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ziti_enroll_opts_s {
    const char *url;
    const char *token;
    const char *key;
    const char *cert;
    const char *name;
    bool use_keychain; // use keychain if generating new key
} ziti_enroll_opts;

/**
* @brief Callback called after ziti_enroll() is complete.
*
* This callback is invoked on the conclusion of the ziti_enroll() function. The result of the
* ziti_enroll() function may be an error condition so it is important to verify the provided
* status code in this callback.
*
* This callback also receives a Ziti identity json salvo if the enrollment was successful.
* This identity should be persisted into a file, and used in subsequent calls to ziti_load_config().
*
* @param cfg identity config object, NULL if enrollment fails for any reason
* @param status enrollment success or error code
* @param err_message description of error, or NULL if enrollment succeeded
* @param enroll_ctx additional context to be passed into #ziti_enroll_cb callback
*
* @see ziti_enroll(), ZITI_ERRORS
*/
typedef void (*ziti_enroll_cb)(const ziti_config *cfg, int status, const char *err_message, void *enroll_ctx);

/**
 * @brief Performs a Ziti enrollment.
 *
 * This function is used to enroll a Ziti Edge identity.
 * [enroll_cb] is called once enrollment process is complete unless the error is returned.
 *
 * @param opts enrollment options
 * @param loop event loop
 * @param enroll_cb callback to be called when enrollment is complete
 * @param enroll_ctx additional context to be passed into #ziti_enroll_cb callback

 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC extern int ziti_enroll(const ziti_enroll_opts *opts, uv_loop_t *loop,
                                 ziti_enroll_cb enroll_cb, void *enroll_ctx);


#ifdef __cplusplus
    }
#endif

#endif //ENROLL_H
