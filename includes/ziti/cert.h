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
 * @brief Client certificate and private key provisioning: the enroll key callback and ziti_set_client_cert().
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
