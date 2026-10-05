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

#include "credentials.h"

#include <sodium.h>
#include <stdbool.h>
#if _MSC_VER
#include <stdint.h>
typedef intptr_t ssize_t;
#else
#include <unistd.h>
#endif

#include <ziti/enums.h>

#define E2EE_MAX_HEADER_LEN (16 * 1024)
// must cover the worst-case expansion of any supported method:
// TLS fragments at 16k and adds ~22 bytes of framing per record, so a
// MAX_CHAIN_LEN (31k) write costs 2 records worth of overhead
// also there could be some handshake data sitting in the output buffer
#define E2EE_MAX_MSG_OVERHEAD 1024

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
    // optional: false while the session cannot encrypt yet, e.g. a TLS 1.2 client waiting for the
    // server's Finished. NULL means always ready
    bool (*ready)(struct e2ee *e2ee);
    void (*free)(struct e2ee *e2ee);
} e2ee_t;


#ifdef __cplusplus
extern "C" {
#endif

e2ee_t *create_e2ee(ziti_crypto_method, bool server, tls_context *tls);

// Checks a tls e2ee server's first flight and logs what it negotiated. With fips set, only these pass:
//   TLS 1.3: TLS_AES_128/256_GCM, a P-256/P-384/P-521 key share
//   TLS 1.2: ECDHE-ECDSA/RSA with AES-128/256-GCM, extended master secret, a P-256/P-384/P-521 curve
// anything else fails (-1). Without fips only the log line is produced.
int tls_e2ee_check_server_flight(bool fips, const uint8_t *flight, size_t len);

const char *e2ee_method_id(ziti_crypto_method mode);

ziti_crypto_method e2ee_method_from_id(const char *id);

#ifdef __cplusplus
}
#endif
#endif // ZITI_SDK_CRYPTO_H
