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


#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "crypto.h"
#include "ziti/ziti_log.h"


#if !defined(EVP_MAX_AEAD_TAG_LENGTH)
#define EVP_MAX_AEAD_TAG_LENGTH 16
#endif

#define AES_GCM_TAG_LEN EVP_MAX_AEAD_TAG_LENGTH
#define AES_GCM_NONCE_LEN 12
#define AES_GCM_NONCE_PREFIX_LEN 4

#if AES_GCM_NONCE_LEN > EVP_MAX_IV_LENGTH
#error "AES_GCM_NONCE_LEN is too large"
#endif

#if AES_GCM_NONCE_LEN > E2EE_MAX_HEADER_LEN
#error "AES_GCM_NONCE_LEN is too large"
#endif

struct aes_gcm_e2ee {
    e2ee_t e2ee;
    EVP_PKEY *pkey;
    uint8_t pub_key[65];
    size_t pub_key_len;

    EVP_CIPHER_CTX *tx;
    EVP_CIPHER_CTX *rx;

    uint8_t rx_key[32];
    uint8_t tx_key[32];
    uint8_t rx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    uint8_t tx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    uint64_t tx_counter;
    uint64_t rx_counter;
    bool header_sent;
};

static void build_nonce(uint8_t out[AES_GCM_NONCE_LEN], const uint8_t *initial, uint64_t counter) {
    memcpy(out, initial, AES_GCM_NONCE_PREFIX_LEN);
    int shift = 0;
    for (int i = AES_GCM_NONCE_LEN; i > AES_GCM_NONCE_PREFIX_LEN; i--) {
        out[i - 1] = (counter >> shift) & 0xff;
        shift += 8;
    }
}

static int derive_session_keys(struct aes_gcm_e2ee *e, const uint8_t *peer_key, size_t peer_key_len, bool server) {
    EVP_PKEY_CTX *derive_ctx = NULL;
    EVP_PKEY_CTX *hkdf_ctx = NULL;
    uint8_t shared_secret[32] = {0};
    size_t shared_secret_len = sizeof(shared_secret);
    // HKDF output per direction: AES-256 key (32 bytes) || GCM IV fixed_field (4 bytes)
    uint8_t derived[sizeof(e->rx_key) + sizeof(e->rx_iv_prefix)] = {0};
    size_t derived_len = sizeof(derived);
    int ret = -1;

    EVP_PKEY *peer_pub = EVP_PKEY_new();
    if (EVP_PKEY_copy_parameters(peer_pub, e->pkey) != 1) goto cleanup;
    if (EVP_PKEY_set1_encoded_public_key(peer_pub, peer_key, peer_key_len) != 1) goto cleanup;

    // ECDH derive
    derive_ctx = EVP_PKEY_CTX_new(e->pkey, NULL);
    if (derive_ctx == NULL) goto cleanup;

    if (EVP_PKEY_derive_init(derive_ctx) != 1) goto cleanup;
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pub) != 1) goto cleanup;
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_len) != 1) goto cleanup;

    // HKDF-SHA256 to derive (rx_key || rx_iv_prefix) and (tx_key || tx_iv_prefix).
    // Include role + both public keys in info so server and client derive complementary material.
    uint8_t info[1 + sizeof(e->pub_key) * 2]; // role_byte + my_pub + peer_pub
    info[0] = server ? 1 : 0;
    memcpy(info + 1, e->pub_key, e->pub_key_len);
    memcpy(info + 1 + e->pub_key_len, peer_key, peer_key_len);

    hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (hkdf_ctx == NULL) goto cleanup;
    if (EVP_PKEY_derive_init(hkdf_ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared_secret, (int)shared_secret_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, info, (int)sizeof(info)) <= 0) goto cleanup;
    if (EVP_PKEY_derive(hkdf_ctx, derived, &derived_len) <= 0) goto cleanup;
    memcpy(e->rx_key, derived, sizeof(e->rx_key));
    memcpy(e->rx_iv_prefix, derived + sizeof(e->rx_key), sizeof(e->rx_iv_prefix));

    // Derive tx material with different info (flip role byte, swap pub-key order)
    info[0] = server ? 0 : 1;
    memcpy(info + 1, peer_key, peer_key_len);
    memcpy(info + 1 + peer_key_len, e->pub_key, e->pub_key_len);
    EVP_PKEY_CTX_free(hkdf_ctx);
    hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (hkdf_ctx == NULL) goto cleanup;
    if (EVP_PKEY_derive_init(hkdf_ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared_secret, (int)shared_secret_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, info, (int)sizeof(info)) <= 0) goto cleanup;
    derived_len = sizeof(derived);
    if (EVP_PKEY_derive(hkdf_ctx, derived, &derived_len) <= 0) goto cleanup;
    memcpy(e->tx_key, derived, sizeof(e->tx_key));
    memcpy(e->tx_iv_prefix, derived + sizeof(e->tx_key), sizeof(e->tx_iv_prefix));

    ret = 0;

cleanup:
    if (ret != 0) {
        ZITI_LOG(ERROR, "Failed to derive session keys: %s", ERR_error_string(ERR_get_error(), NULL));
    }
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(derived, sizeof(derived));
    if (peer_pub) EVP_PKEY_free(peer_pub);
    if (hkdf_ctx) EVP_PKEY_CTX_free(hkdf_ctx);
    if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
    return ret;
}

static e2ee_pub_t aes_gcm_pub(struct e2ee *e2ee) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    e2ee_pub_t pub = {};
    pub.key = e->pub_key;
    pub.key_len = e->pub_key_len;
    return pub;
}

static int aes_gcm_init(struct e2ee *e2ee, const uint8_t *peer_key, size_t peer_key_len, bool server) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;

    if (peer_key_len != e->pub_key_len) {
        return -1;
    }

    // Already initialized
    if (!sodium_is_zero(e->rx_key, sizeof(e->rx_key)) || !sodium_is_zero(e->tx_key, sizeof(e->tx_key))) {
        return -1;
    }

    int ret = derive_session_keys(e, peer_key, peer_key_len, server);

    // Zero out secret key material regardless of outcome
    EVP_PKEY_free(e->pkey);
    e->pkey = NULL;

    if (ret != 0) {
        return -1;
    }

    e->tx_counter = 1;
    e->rx_counter = 1;

    e->tx = EVP_CIPHER_CTX_new();
    e->rx = EVP_CIPHER_CTX_new();
    if (e->tx == NULL || e->rx == NULL) {
        ZITI_LOG(ERROR, "Failed to allocate AES-GCM cipher contexts");
        return -1;
    }
    if (EVP_EncryptInit_ex(e->tx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(e->tx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(e->rx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(e->rx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN, NULL) != 1) {
        ZITI_LOG(ERROR, "Failed to initialize AES-GCM cipher contexts: %s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    return 0;
}

static ssize_t aes_gcm_get_header(struct e2ee *e2ee, uint8_t header[E2EE_MAX_HEADER_LEN]) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    if (header == NULL) {
        return -1;
    }
    if (e->header_sent) {
        return -1;
    }
    // IV prefix and counter origin are agreed during init via HKDF; nothing to send.
    e->header_sent = true;
    return 0;
}

static ssize_t aes_gcm_encrypt(e2ee_t *e2ee, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t ciphertext_len) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    size_t required = plaintext_len + AES_GCM_TAG_LEN;
    if (ciphertext_len < required) {
        return -1;
    }

    if (e->tx_counter == UINT64_MAX) {
        ZITI_LOG(ERROR, "AES-GCM encryption counter overflow");
        return -1;
    }

    int out_len = 0;
    int final_len = 0;

    uint8_t iv[AES_GCM_NONCE_LEN];
    build_nonce(iv, e->tx_iv_prefix, e->tx_counter);
    if (EVP_EncryptInit_ex(e->tx, NULL, NULL, e->tx_key, iv) != 1) goto err;
    if (EVP_EncryptUpdate(e->tx, ciphertext, &out_len, plaintext, (int)plaintext_len) != 1) goto err;
    if (EVP_EncryptFinal_ex(e->tx, ciphertext + out_len, &final_len) != 1) goto err;

    out_len += final_len;

    if (EVP_CIPHER_CTX_ctrl(e->tx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, ciphertext + out_len) != 1) goto err;
    out_len += AES_GCM_TAG_LEN;
    e->tx_counter++;

    return (ssize_t)out_len;

err:
    ZITI_LOG(ERROR, "aes-gcm encryption failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
}

static ssize_t aes_gcm_decrypt(e2ee_t *e2ee, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext, size_t plaintext_len) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;

    if (ciphertext_len <= AES_GCM_TAG_LEN) {
        return -1;
    }

    size_t ct_data_len = ciphertext_len - AES_GCM_TAG_LEN;
    if (plaintext_len < ct_data_len) {
        return -1;
    }

    if (e->rx_counter == UINT64_MAX) {
        ZITI_LOG(ERROR, "AES-GCM decryption counter overflow");
        return -1;
    }

    int out_len = 0;
    int final_len = 0;

    uint8_t iv[AES_GCM_NONCE_LEN];
    build_nonce(iv, e->rx_iv_prefix, e->rx_counter);
    if (EVP_DecryptInit_ex(e->rx, NULL, NULL, e->rx_key, iv) != 1) {
        goto err;
    }

    if (EVP_DecryptUpdate(e->rx, plaintext, &out_len, ciphertext, (int)ct_data_len) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(e->rx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (uint8_t *)ciphertext + ct_data_len) != 1) goto err;
    if (EVP_DecryptFinal_ex(e->rx, plaintext + out_len, &final_len) != 1) goto err;

    out_len += final_len;
    e->rx_counter++;
    return (ssize_t)out_len;

err:
    ZITI_LOG(WARN, "aes-gcm decryption failed: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
}

static struct e2ee *aes_gcm_clone(struct e2ee *e2ee) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;

    if (e->pkey == NULL) {
        ZITI_LOG(ERROR, "cannot clone aes-gcm e2ee after init was called");
        abort();
    }

    struct aes_gcm_e2ee *clone = (struct aes_gcm_e2ee*)calloc(1, sizeof(struct aes_gcm_e2ee));
    if (clone == NULL) {
        ZITI_LOG(ERROR, "failed to allocate aes-gcm e2ee: out of memory");
        abort();
    }

    clone->e2ee = e->e2ee;

    // Deep copy the keypair
    clone->pkey = EVP_PKEY_dup(e->pkey);
    if (clone->pkey == NULL) {
        ZITI_LOG(ERROR, "failed to duplicate aes-gcm keypair");
        free(clone);
        abort();
    }

    memcpy(clone->pub_key, e->pub_key, e->pub_key_len);
    clone->pub_key_len = e->pub_key_len;

    return &clone->e2ee;
}

static void aes_gcm_free(e2ee_t *e2ee) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    if (e->pkey) {
        EVP_PKEY_free(e->pkey);
    }
    if (e->tx) {
        EVP_CIPHER_CTX_free(e->tx);
    }
    if (e->rx) {
        EVP_CIPHER_CTX_free(e->rx);
    }
    OPENSSL_cleanse(e, sizeof(struct aes_gcm_e2ee));
    free(e);
}

static e2ee_t aes_gcm_e2ee_impl = {
    .method = ziti_crypto_aes_gcm,
    .clone = aes_gcm_clone,
    .pub = aes_gcm_pub,
    .init = aes_gcm_init,
    .get_header = aes_gcm_get_header,
    .encrypt = aes_gcm_encrypt,
    .decrypt = aes_gcm_decrypt,
    .free = aes_gcm_free,
};

struct aes_gcm_e2ee *new_aes_gcm_e2ee(void) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee*)calloc(1, sizeof(struct aes_gcm_e2ee));
    if (e == NULL) {
        ZITI_LOG(ERROR, "failed to allocate aes-gcm e2ee: out of memory");
        abort();
    }

    e->e2ee = aes_gcm_e2ee_impl;

    // Generate P-256 keypair
    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (gen_ctx == NULL || EVP_PKEY_keygen_init(gen_ctx) <= 0) {
        ZITI_LOG(ERROR, "failed to init P-256 keygen");
        EVP_PKEY_CTX_free(gen_ctx);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen_ctx, NID_X9_62_prime256v1) <= 0) {
        ZITI_LOG(ERROR, "failed to set P-256 curve");
        EVP_PKEY_CTX_free(gen_ctx);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }
    if (EVP_PKEY_keygen(gen_ctx, &e->pkey) <= 0) {
        ZITI_LOG(ERROR, "failed to generate P-256 keypair");
        EVP_PKEY_CTX_free(gen_ctx);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }
    EVP_PKEY_CTX_free(gen_ctx);

    if (EVP_PKEY_get_octet_string_param(e->pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, e->pub_key,
                                    sizeof(e->pub_key), &e->pub_key_len) != 1) {
        ZITI_LOG(ERROR, "failed to get public key from P-256 keypair");
        aes_gcm_free((e2ee_t *)e);
        abort();
    }

    return e;
}

