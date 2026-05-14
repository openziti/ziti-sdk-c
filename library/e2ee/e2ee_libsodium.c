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

#include <sodium.h>
#include <string.h>

#include "crypto.h"
#include "ziti/ziti_log.h"

#if !defined(E2EE_MAX_HEADER_LEN) || E2EE_MAX_HEADER_LEN < crypto_secretstream_xchacha20poly1305_HEADERBYTES
#error "E2EE_MAX_HEADER_LEN must be defined and at least crypto_secretstream_xchacha20poly1305_HEADERBYTES"
#endif

#if !defined(E2EE_MAX_MSG_OVERHEAD) || E2EE_MAX_MSG_OVERHEAD < crypto_secretstream_xchacha20poly1305_ABYTES
#error "E2EE_MAX_MSG_OVERHEAD must be defined and at least crypto_secretstream_xchacha20poly1305_ABYTES"
#endif

/// libsodium e2ee_t implementation
struct libsodium_e2ee {
    e2ee_t e2ee;
    struct {
        uint8_t sk[crypto_kx_SECRETKEYBYTES];
        uint8_t pk[crypto_kx_PUBLICKEYBYTES];
    } kp;
    struct {
        uint8_t rx[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        uint8_t tx[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    } key_ex;
    crypto_secretstream_xchacha20poly1305_state encrypt_state;
    crypto_secretstream_xchacha20poly1305_state decrypt_state;
    bool header_received;
};

static e2ee_pub_t libsodium_pub(struct e2ee *e2ee) {
    struct libsodium_e2ee *e = (struct libsodium_e2ee*) e2ee;
    return (e2ee_pub_t){ .key = e->kp.pk, .key_len = sizeof(e->kp.pk) };
}

// if init failed, this crypto instance should be discarded
static int libsodium_init(struct e2ee *e2ee, const uint8_t *peer_key, size_t peer_key_len, bool server) {
    struct libsodium_e2ee *e = (struct libsodium_e2ee*) e2ee;
    if (peer_key_len != crypto_kx_PUBLICKEYBYTES) {
        return -1;
    }

    // already initialized
    if (!sodium_is_zero(e->key_ex.rx, sizeof(e->key_ex.rx)) || !sodium_is_zero(e->key_ex.tx, sizeof(e->key_ex.tx))) {
        return -1;
    }

    int rc = server ?
             crypto_kx_server_session_keys(e->key_ex.rx, e->key_ex.tx, e->kp.pk, e->kp.sk, peer_key) :
             crypto_kx_client_session_keys(e->key_ex.rx, e->key_ex.tx, e->kp.pk, e->kp.sk, peer_key);

    sodium_memzero(&e->kp.sk, sizeof(e->kp.sk));
    return rc == 0 ? 0 : -1;
}

static ssize_t libsodium_get_header(struct e2ee *e2ee, uint8_t header[E2EE_MAX_HEADER_LEN]) {
    struct libsodium_e2ee *e = (struct libsodium_e2ee*) e2ee;
    if (header == NULL) {
        return -1;
    }

    if (!sodium_is_zero((void*)&e->encrypt_state, sizeof(e->encrypt_state))) {
        return -1;
    }

    if (crypto_secretstream_xchacha20poly1305_init_push(&e->encrypt_state, header, e->key_ex.tx) != 0) {
        return -1;
    }
    return (ssize_t)crypto_secretstream_xchacha20poly1305_headerbytes();
}

static ssize_t libsodium_encrypt(e2ee_t *e2ee, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t ciphertext_len) {
    struct libsodium_e2ee *e = (struct libsodium_e2ee*) e2ee;
    if (ciphertext_len < plaintext_len + crypto_secretstream_xchacha20poly1305_abytes()) {
        return -1;
    }
    unsigned long long clen = ciphertext_len;
    int rc = crypto_secretstream_xchacha20poly1305_push(&e->encrypt_state, ciphertext, &clen,
                                                        plaintext, (unsigned long long)plaintext_len,
                                                        NULL, 0, 0);
    if (rc != 0) {
        return -1;
    }

    return (ssize_t)clen;
}

static ssize_t libsodium_decrypt(e2ee_t *e2ee, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext, size_t plaintext_len) {
    struct libsodium_e2ee *e = (struct libsodium_e2ee*) e2ee;
    if (!e->header_received) {
        if (ciphertext_len < crypto_secretstream_xchacha20poly1305_headerbytes()) {
            return -1;
        }
        if (crypto_secretstream_xchacha20poly1305_init_pull(&e->decrypt_state, ciphertext, e->key_ex.rx) != 0) {
            return -1;
        }

        e->header_received = true;
        // allow caller to pass in header + ciphertext together
        // incomplete ciphertext will return an error below
        ciphertext_len -= crypto_secretstream_xchacha20poly1305_headerbytes();
        ciphertext += crypto_secretstream_xchacha20poly1305_headerbytes();
        if (ciphertext_len == 0) {
            return 0;
        }
    }

    if (ciphertext_len < crypto_secretstream_xchacha20poly1305_abytes() ||
        plaintext_len < ciphertext_len - crypto_secretstream_xchacha20poly1305_abytes()) {
        return -1;
    }
    unsigned long long plen = plaintext_len;
    unsigned char tag; // ignored since we cannot send it via this API, and ziti connection signals EOF via other methods

    int rc = crypto_secretstream_xchacha20poly1305_pull(&e->decrypt_state, plaintext, &plen, &tag, ciphertext, (unsigned long long)ciphertext_len, NULL, 0);
    if (rc != 0) {
        return -1;
    }

    return (ssize_t)plen;
}

static struct e2ee* libsodium_clone(struct e2ee *e2ee) {
    struct libsodium_e2ee *e = (struct libsodium_e2ee*) e2ee;

    // programming error
    if (sodium_is_zero(e->kp.sk, sizeof(e->kp.sk))) {
        ZITI_LOG(ERROR, "cannot clone after init was called");
        abort();
    }

    struct libsodium_e2ee *clone = calloc(1, sizeof(struct libsodium_e2ee));
    if (clone == NULL) {
        ZITI_LOG(ERROR, "failed to allocate libsodium e2ee: out of memory");
        abort();
    }

    clone->e2ee = e->e2ee;
    memcpy(&clone->kp, &e->kp, sizeof(e->kp));
    return &clone->e2ee;
}

static void libsodium_free(e2ee_t *e2ee) {
    struct libsodium_e2ee *e = (struct libsodium_e2ee*) e2ee;
    sodium_memzero(e, sizeof(struct libsodium_e2ee));
    free(e);
}

static e2ee_t libsodium_e2ee_impl = {
    .clone = libsodium_clone,
    .pub = libsodium_pub,
    .init = libsodium_init,
    .get_header = libsodium_get_header,
    .encrypt = libsodium_encrypt,
    .decrypt = libsodium_decrypt,
    .free = libsodium_free,
};

struct libsodium_e2ee* new_libsodium_e2ee() {
    struct libsodium_e2ee *e = calloc(1, sizeof(struct libsodium_e2ee));
    if (e == NULL) {
        ZITI_LOG(ERROR, "failed to allocate libsodium e2ee: out of memory");
        abort();
    }
    int init_rc = crypto_kx_keypair(e->kp.pk, e->kp.sk);
    if (init_rc != 0) {
        ZITI_LOG(ERROR, "failed to initialize libsodium e2ee: crypto error");
        libsodium_free((e2ee_t *)e);
        abort();
    }
    e->e2ee = libsodium_e2ee_impl;
    return e;
}
