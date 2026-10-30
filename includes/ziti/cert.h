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
 * @file cert.h
 * @brief Client certificate and private key provisioning: enroll key callback and certificate extension.
 */

#ifndef ZITI_CERT_H
#define ZITI_CERT_H

#include <stddef.h>

#include "externs.h"
#include "handles.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Callback to provide a private key for enrollToCert enrollment.
 *
 * When set via ziti_set_enroll_key_cb(), this callback is invoked during
 * enrollToCert to let the caller provide a private key. The callback must
 * allocate and return a key string in *key. The SDK takes ownership and will
 * free it.
 *
 * The string is anything accepted as `id.key` of an identity config: a PEM,
 * `pem:<PEM>`, `file://<path>`, `keychain:<name>` or a `pkcs11:` URI. A
 * `keychain:` or `pkcs11:` reference lets the key stay in the platform keystore,
 * without the SDK ever holding its bytes. The key must exist when the callback
 * returns, so the callback is expected to create it. If the SDK cannot load it,
 * enrollment fails with ZITI_KEY_LOAD_FAILED.
 *
 * The string is stored in the identity config as `id.key`, and is what the
 * application persists with the rest of the config.
 *
 * If not set, the SDK generates a software key internally.
 *
 * @param ztx the Ziti context performing enrollment
 * @param key output: caller-allocated key string, a PEM or a key reference
 * @param ctx the context passed to ziti_set_enroll_key_cb()
 * @return ZITI_OK on success, or an error code
 */
typedef int (*ziti_enroll_key_cb)(ziti_context ztx, char **key, void *ctx);

/**
 * @brief Set a callback to provide a private key for enrollToCert enrollment.
 *
 * This allows callers (e.g., CZiti/ziti-sdk-swift) to generate and manage
 * private keys in a platform keychain rather than using SDK-generated software
 * keys. The callback may return a `keychain:` reference to such a key.
 * The SDK will generate the CSR and handle all enrollment networking.
 *
 * @param ztx the Ziti context
 * @param cb the callback, or NULL to use the default SDK key generation
 * @param ctx additional context passed to the callback
 */
ZITI_FUNC
extern void ziti_set_enroll_key_cb(ziti_context ztx, ziti_enroll_key_cb cb, void *ctx);

/**
 * @brief Extend Certificate Authenticator Callback
 *
 * This callback is invoked on the conclusion of ziti_extend_cert_authenticator(). The result of the function
 * may be an error condition so it is important to verify the status code in this callback. In the
 * event the certificate authenticator extension request cannot be completed an error will be returned otherwise
 * #ZITI_OK is expected.
 *
 * @see ziti_extend_cert_authenticator(), ZITI_ERRORS
 */
typedef void (*ziti_extend_cert_authenticator_cb)(ziti_context ztx, const char* cert_pem, int status, void *ctx);

/**
 * @brief Attempts extend the lifetime of a 1st party client certificate (issued by the Ziti Controller)
 *
 * Attempts to extend the current authenticator used for the ztx's authentication. If it is not a certificate
 * authenticator or it is not extendable, errors will be returned in subsequent events.
 *
 * Responses are provided via a `ziti_extend_cert_authenticator_cb` callback. On that callback, check the `error` field
 * for issues. If there are no errors persist the `new_client_cert_pem` and make a subsequent call to
 * `ziti_verify_extend_cert_authenticator` to enable use of the new client certificate.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param csr a CSR representing the request for a new client certificate
 * @param ctx additional context to be passed back to the call via cb
 * @param cb a callback for the result of the certificate extension request
 * @return returns #ZITI_OK on success, otherwise error
 */
ZITI_FUNC
extern int ziti_extend_cert_authenticator(ziti_context ztx, const char *csr_pem, ziti_extend_cert_authenticator_cb cb, void *ctx);

/**
 * @brief Verify Extend Certificate Authenticator Callback
 *
 * This callback is invoked on the conclusion of ziti_verify_extend_cert_authenticator(). The result of the function
 * may be an error condition so it is important to verify the status code in this callback. In the
 * event the certificate authenticator extension verification request cannot be completed an error will be returned
 * otherwise #ZITI_OK is expected. At the end of this callback's invocation, the new client certificate PEM
 * should be stored and set for use via `ziti_set_client_cert` on new connections and reconnections.
 *
 * @see ziti_extend_cert_authenticator(), ZITI_ERRORS
 */
typedef void (*ziti_verify_extend_cert_authenticator_cb)(ziti_context ztx, int status, void *ctx);

/**
 * @brief Called in response to a ziti_extend_cert_authenticator_cb to verify a new client certificate
 *
 * After calling `ziti_extend_cert_authenticator` a `ziti_extend_cert_authenticator_cb` callback will be invoked.
 * In order to have the new client cert provided in the event become active, the controller requires that the client
 * verify that it has received the new certificate. Calling this function will verify the certificate and cause the new
 * client certificate to become active, inactivating the old certificate. At the end of execution the provided callback
 * will be invoked with #ZITI_OK or an error.
 *
 * `ziti_set_client_cert` should be called shortly after on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param new_cert the new client certificate that will become active on successful verification, provided in the extension event
 * @param ctx additional context to be passed back in raised events
 * @return returns #ZITI_OK on success, otherwise error
 */
ZITI_FUNC
extern int ziti_verify_extend_cert_authenticator(ziti_context ztx, const char *new_cert, ziti_verify_extend_cert_authenticator_cb cb, void *ctx);

/**
 * @brief Updates the certificate context for the ZTX with a new client certificate and key.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param cert_buf a PEM formatted x509 certificate
 * @param cert_len the length of cert_buf
 * @param key_buf a PEM formatted x509 private key
 * @param key_len the length of key_buf
 * @return returns 0 on success
 */
ZITI_FUNC
extern int ziti_set_client_cert(ziti_context ztx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_CERT_H */
