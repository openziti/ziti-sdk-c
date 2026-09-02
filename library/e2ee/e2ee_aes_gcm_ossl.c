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

#include <crypto.h>
#include "ziti/ziti_log.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>



#if !defined(EVP_MAX_AEAD_TAG_LENGTH)
#define EVP_MAX_AEAD_TAG_LENGTH 16
#endif

#define AES_GCM_TAG_LEN EVP_MAX_AEAD_TAG_LENGTH
#define AES_GCM_NONCE_LEN 12
#define AES_GCM_NONCE_PREFIX_LEN 4
#define AES_GCM_KEY_LEN 32
#define P256_PUB_KEY_LEN 65

#if AES_GCM_NONCE_LEN > EVP_MAX_IV_LENGTH
#error "AES_GCM_NONCE_LEN is too large"
#endif

#if AES_GCM_NONCE_LEN > E2EE_MAX_HEADER_LEN
#error "AES_GCM_NONCE_LEN is too large"
#endif

struct aes_gcm_e2ee {
    e2ee_t e2ee;
    EVP_PKEY *pkey;
    uint8_t pub_key[P256_PUB_KEY_LEN];
    size_t pub_key_len;

    EVP_CIPHER_CTX *tx;
    EVP_CIPHER_CTX *rx;

    uint8_t rx_key[AES_GCM_KEY_LEN];
    uint8_t tx_key[AES_GCM_KEY_LEN];
    uint8_t rx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    uint8_t tx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    // tx_counter mirrors the invocation field that the cipher context increments
    // internally -- it is not the authoritative value, it only lets encrypt
    // refuse to wrap where the module would wrap silently.
    uint64_t tx_counter;
    uint64_t rx_counter;
    bool header_sent;
};

// Crypto for this backend runs in its own library context, never the process
// default one: with the FIPS provider loaded where it is available, and otherwise
// with whatever the implicitly activated default provider offers. Either way the
// embedding application's OpenSSL configuration is left alone. Set up once by
// e2ee_ossl_init().
static CRYPTO_ONCE   ossl_init_once = CRYPTO_ONCE_STATIC_INIT;
static OSSL_LIB_CTX *e2ee_libctx;   // private context, shared by every instance
static EVP_CIPHER   *e2ee_cipher;   // AES-256-GCM, from e2ee_libctx
static EVP_MD       *e2ee_sha256;   // SHA256 for HKDF, from e2ee_libctx

// SP 800-38D 8.2.1 deterministic IV construction:
//
//   fixed field      = AES_GCM_NONCE_PREFIX_LEN bytes, HKDF-derived per session
//                      and per direction (tx and rx use different HKDF info)
//   invocation field = 64-bit big-endian counter, starts at 1, +1 per message
//
// For the tx direction this only seeds the cipher context: the module itself
// increments the trailing 8 bytes from there (OpenSSL's ctr64_inc), so the
// construction happens inside the crypto boundary. rx nonces are built here --
// SP 800-38D places no construction requirement on the receiving party.
//
// What carries the uniqueness guarantee is that the AES key is itself unique per
// session (a fresh P-256 ECDH per connection), so a (key, IV) pair cannot repeat
// as long as the counter is monotonic for the life of the key -- and it is:
// encrypt and decrypt refuse to proceed at UINT64_MAX rather than wrapping.
static void build_nonce(uint8_t out[AES_GCM_NONCE_LEN], const uint8_t *initial, uint64_t counter) {
    memcpy(out, initial, AES_GCM_NONCE_PREFIX_LEN);
    int shift = 0;
    for (int i = AES_GCM_NONCE_LEN; i > AES_GCM_NONCE_PREFIX_LEN; i--) {
        out[i - 1] = (counter >> shift) & 0xff;
        shift += 8;
    }
}

static void e2ee_ossl_init(void) {
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

    // A fresh library context has no default provider, so if the FIPS provider
    // loads it is the only source of algorithms.
    if (ctx != NULL &&
        OSSL_PROVIDER_load(ctx, "fips") != NULL &&
        EVP_set_default_properties(ctx, "fips=yes") == 1) {
        ZITI_LOG(INFO, "e2ee AES-GCM: using OpenSSL FIPS provider");
    } else {
        ZITI_LOG(INFO, "e2ee AES-GCM: failed to load OpenSSL FIPS provider");
        ERR_clear_error();
        // A failed load leaves the context with no providers *and* suppresses the
        // implicit default-provider activation, so every fetch from it would come
        // back NULL. Start over with a clean context instead.
        OSSL_LIB_CTX_free(ctx);
        ctx = OSSL_LIB_CTX_new();
    }

    e2ee_cipher = EVP_CIPHER_fetch(ctx, "AES-256-GCM", NULL);
    e2ee_sha256 = EVP_MD_fetch(ctx, "SHA256", NULL);
    e2ee_libctx = ctx;
}

// RFC 5869 HKDF-SHA256, extract-and-expand with no salt set (HMAC then treats it
// as SHA256_DIGEST_LENGTH zero bytes). Must stay bit-identical to what the Apple
// and BCrypt backends derive, or this stops interoperating with them.
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    int ret = -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(e2ee_libctx, "HKDF", NULL);
    if (ctx == NULL) return -1;

    if (EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, e2ee_sha256) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) > 0 &&
        EVP_PKEY_derive(ctx, out, &out_len) > 0) {
        ret = 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return ret;
}

// Import the peer's uncompressed P-256 point into the same library context as our
// own key. EVP_PKEY_new() has no library-context-aware variant, so the key is
// built with fromdata rather than copy_parameters + set1_encoded_public_key.
static EVP_PKEY *import_peer_key(const uint8_t *peer_key, size_t peer_key_len) {
    EVP_PKEY *peer_pub = NULL;
    char group[] = "prime256v1";
    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)peer_key, peer_key_len),
            OSSL_PARAM_construct_end()
    };

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(e2ee_libctx, "EC", NULL);
    if (ctx == NULL) return NULL;

    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &peer_pub, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(peer_pub);
        peer_pub = NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return peer_pub;
}

static int derive_session_keys(struct aes_gcm_e2ee *e, const uint8_t *peer_key, size_t peer_key_len, bool server) {
    EVP_PKEY_CTX *derive_ctx = NULL;
    uint8_t shared_secret[32] = {0};
    size_t shared_secret_len = sizeof(shared_secret);
    // HKDF output per direction: AES-256 key (32 bytes) || GCM IV fixed_field (4 bytes)
    uint8_t derived[sizeof(e->rx_key) + sizeof(e->rx_iv_prefix)] = {0};
    int ret = -1;

    EVP_PKEY *peer_pub = import_peer_key(peer_key, peer_key_len);
    if (peer_pub == NULL) goto cleanup;

    // ECDH derive
    derive_ctx = EVP_PKEY_CTX_new_from_pkey(e2ee_libctx, e->pkey, NULL);
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

    if (hkdf_sha256(shared_secret, shared_secret_len, info, sizeof(info), derived, sizeof(derived)) != 0) goto cleanup;
    memcpy(e->rx_key, derived, sizeof(e->rx_key));
    memcpy(e->rx_iv_prefix, derived + sizeof(e->rx_key), sizeof(e->rx_iv_prefix));

    // Derive tx material with different info (flip role byte, swap pub-key order)
    info[0] = server ? 0 : 1;
    memcpy(info + 1, peer_key, peer_key_len);
    memcpy(info + 1 + peer_key_len, e->pub_key, e->pub_key_len);
    if (hkdf_sha256(shared_secret, shared_secret_len, info, sizeof(info), derived, sizeof(derived)) != 0) goto cleanup;
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
    const uint8_t zero_key[AES_GCM_KEY_LEN] = {0};
    if (CRYPTO_memcmp(e->rx_key, zero_key, sizeof(zero_key)) != 0 ||
        CRYPTO_memcmp(e->tx_key, zero_key, sizeof(zero_key)) != 0) {
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
    if (EVP_EncryptInit_ex(e->tx, e2ee_cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(e->tx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(e->rx, e2ee_cipher, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(e->rx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_LEN, NULL) != 1) {
        ZITI_LOG(ERROR, "Failed to initialize AES-GCM cipher contexts: %s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Install the key and the first nonce now, and let the cipher increment the
    // invocation field from here on -- the key has to go in before SET_IV_FIXED,
    // since a later EncryptInit_ex with a key would clear the iv_gen state.
    uint8_t iv[AES_GCM_NONCE_LEN];
    build_nonce(iv, e->tx_iv_prefix, e->tx_counter);
    if (EVP_EncryptInit_ex(e->tx, NULL, NULL, e->tx_key, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(e->tx, EVP_CTRL_GCM_SET_IV_FIXED, -1, iv) != 1) {
        OPENSSL_cleanse(iv, sizeof(iv));
        ZITI_LOG(ERROR, "Failed to seed AES-GCM nonce: %s", ERR_error_string(ERR_get_error(), NULL));
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
    // The cipher holds the nonce and advances it; iv receives the one just used.
    // A failure below therefore consumes a nonce without emitting a frame, which
    // would leave the peer's rx_counter a step behind -- harmless only because
    // the caller tears the connection down on encryption failure and never
    // retries (see connect.c: ZITI_CRYPTO_FAIL).
    if (EVP_CIPHER_CTX_ctrl(e->tx, EVP_CTRL_GCM_IV_GEN, 0, iv) != 1) goto err;
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
    CRYPTO_THREAD_run_once(&ossl_init_once, e2ee_ossl_init);

    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee*)calloc(1, sizeof(struct aes_gcm_e2ee));
    if (e == NULL) {
        ZITI_LOG(ERROR, "failed to allocate aes-gcm e2ee: out of memory");
        abort();
    }

    e->e2ee = aes_gcm_e2ee_impl;

    // Generate P-256 keypair
    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(e2ee_libctx, "EC", NULL);
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

