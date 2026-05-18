// Copyright (c) 2026.  NetFoundry Inc
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.

//
//

#ifndef ZITI_SDK_CRYPTO_H
#define ZITI_SDK_CRYPTO_H

#include <sodium.h>
#include <stdbool.h>
#if _MSC_VER
#include <stdint.h>
typedef intptr_t ssize_t;
#else
#include <unistd.h>
#endif

#include <ziti/enums.h>

#define E2EE_MAX_HEADER_LEN 64
#define E2EE_MAX_MSG_OVERHEAD 32

typedef struct e2ee_pub_s {
    const uint8_t *key;
    size_t key_len;
} e2ee_pub_t;

// End-to-end encryption API
typedef struct e2ee {
    ziti_crypto_method method;
    // clone initial state: allows for multiple connections to be established
    // with the same key pair
    struct e2ee* (*clone)(struct e2ee *e2ee);

    e2ee_pub_t (*pub)(struct e2ee *e2ee);
    int (*init)(struct e2ee *e2ee, const uint8_t *peer_key, size_t peer_key_len, bool server);
    ssize_t (*get_header)(struct e2ee *e2ee, uint8_t header[E2EE_MAX_HEADER_LEN]);
    ssize_t (*encrypt)(struct e2ee *e2ee, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t ciphertext_len);
    ssize_t (*decrypt)(struct e2ee *e2ee, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext, size_t plaintext_len);
    void (*free)(struct e2ee *e2ee);
} e2ee_t;


#ifdef __cplusplus
extern "C" {
#endif

e2ee_t *create_e2ee(ziti_crypto_method);

const char *e2ee_method_id(ziti_crypto_method mode);

ziti_crypto_method e2ee_method_from_id(const char *id);

#ifdef __cplusplus
}
#endif
#endif // ZITI_SDK_CRYPTO_H
