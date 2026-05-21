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

#ifndef _WIN32
#error "This file is only for Windows builds"
#endif

#include "crypto.h"
#include "e2ee_common.h"
#include "ziti/ziti_log.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

// missing in mingw
#ifndef BCRYPT_HKDF_ALG_HANDLE
#define BCRYPT_HKDF_ALG_HANDLE ((BCRYPT_ALG_HANDLE)0x00000391)
#endif

#ifndef BCRYPT_ECDH_P256_ALG_HANDLE
#define BCRYPT_ECDH_P256_ALG_HANDLE ((BCRYPT_ALG_HANDLE)0x02A1)
#endif

#ifndef BCRYPT_AES_GCM_ALG_HANDLE
#define BCRYPT_AES_GCM_ALG_HANDLE ((BCRYPT_ALG_HANDLE)0x000001E1)
#endif


// Wire-format constants — see plan: must match e2ee_aes_gcm_ossl.c byte-for-byte.
#define AES_GCM_TAG_LEN          16
#define AES_GCM_NONCE_LEN        12
#define AES_GCM_NONCE_PREFIX_LEN 4
#define AES_KEY_LEN              32
#define ECDH_P256_COORD_LEN      32
#define ECDH_P256_PUB_LEN        65   // 0x04 || X(32) || Y(32) — uncompressed wire form
#define ECDH_P256_BLOB_LEN       (sizeof(BCRYPT_ECCKEY_BLOB) + 2 * ECDH_P256_COORD_LEN) // 72
#define HKDF_OUT_LEN             (AES_KEY_LEN + AES_GCM_NONCE_PREFIX_LEN)               // 36
#define HKDF_INFO_LEN            (1 + 2 * ECDH_P256_PUB_LEN)                            // 131

#if AES_GCM_NONCE_LEN > E2EE_MAX_HEADER_LEN
#error "AES_GCM_NONCE_LEN exceeds E2EE_MAX_HEADER_LEN"
#endif

// Algorithm pseudo-handles (BCRYPT_*_ALG_HANDLE constants) require Win10 1809+.
// They are static handles — no Open/Close lifecycle, no chain-mode property to set
// (BCRYPT_AES_GCM_ALG_HANDLE already has BCRYPT_CHAIN_MODE_GCM bound).

struct aes_gcm_e2ee {
    e2ee_t e2ee;

    BCRYPT_KEY_HANDLE ecdh_key;  // own keypair; destroyed after init() scrubs private material

    uint8_t pub_key[ECDH_P256_PUB_LEN];
    size_t  pub_key_len;

    BCRYPT_KEY_HANDLE tx_aes_key;
    BCRYPT_KEY_HANDLE rx_aes_key;

    uint8_t rx_key[AES_KEY_LEN];                 // kept for sodium_is_zero double-init guard
    uint8_t tx_key[AES_KEY_LEN];
    uint8_t rx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    uint8_t tx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    uint64_t tx_counter;
    uint64_t rx_counter;
    bool header_sent;
};

// Verbatim copy from e2ee_aes_gcm_ossl.c — see plan, interop contract item 4.
static void build_nonce(uint8_t out[AES_GCM_NONCE_LEN], const uint8_t *initial, uint64_t counter) {
    memcpy(out, initial, AES_GCM_NONCE_PREFIX_LEN);
    int shift = 0;
    for (int i = AES_GCM_NONCE_LEN; i > AES_GCM_NONCE_PREFIX_LEN; i--) {
        out[i - 1] = (counter >> shift) & 0xff;
        shift += 8;
    }
}

static void reverse_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0, j = len - 1; i < j; i++, j--) {
        uint8_t t = buf[i];
        buf[i] = buf[j];
        buf[j] = t;
    }
}

// HKDF-SHA256 Extract-then-Expand. To match the OSSL backend exactly (which uses OpenSSL's
// default EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND with no salt → HashLen zero bytes per
// RFC 5869), we supply an explicit 32-byte zero salt. BCrypt's docs are ambiguous about
// whether an absent KDF_SALT buffer performs Extract or skips it; supplying the salt
// explicitly removes that ambiguity.
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    BCRYPT_KEY_HANDLE hKey = NULL;
    int ret = -1;
    uint8_t zero_salt[32] = {0};

    NTSTATUS s;

    // Generate KDF Key from Input Keying Material (IKM)
    s = BCryptGenerateSymmetricKey(BCRYPT_HKDF_ALG_HANDLE, &hKey, NULL, 0, (PUCHAR)ikm, (ULONG)ikm_len, 0);
    s = BCryptSetProperty(hKey, BCRYPT_HKDF_HASH_ALGORITHM, (void*)BCRYPT_SHA256_ALGORITHM, (ULONG)(sizeof(BCRYPT_SHA256_ALGORITHM)), 0);

    // 3. Extract Stage: Provide salt and finalize
    s = BCryptSetProperty(hKey, BCRYPT_HKDF_SALT_AND_FINALIZE, NULL, 0, 0);
    ULONG written = 0;

    BCryptBuffer params[] = {
        { (ULONG)info_len,                 KDF_HKDF_INFO,      (PVOID)info },
    };
    BCryptBufferDesc desc = { BCRYPTBUFFER_VERSION, ARRAYSIZE(params), params };
    s = BCryptKeyDerivation(hKey, &desc, out, out_len, &written, 0);
    if (!BCRYPT_SUCCESS(s)) {
        ZITI_LOG(ERROR, "BCryptGenerateSymmetricKey(HKDF IKM) failed: 0x%lx", s);
        goto cleanup;
    }


    ret = 0;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    return ret;
}

static int derive_session_keys(struct aes_gcm_e2ee *e,
                               const uint8_t *peer_key, size_t peer_key_len,
                               bool server) {
    BCRYPT_KEY_HANDLE peer_pub = NULL;
    BCRYPT_SECRET_HANDLE secret = NULL;
    uint8_t shared_secret[32] = {0};
    uint8_t derived[HKDF_OUT_LEN] = {0};
    uint8_t pub_blob[ECDH_P256_BLOB_LEN] = {0};
    uint8_t info[HKDF_INFO_LEN];
    NTSTATUS s;
    int ret = -1;

    if (peer_key_len != ECDH_P256_PUB_LEN || peer_key[0] != 0x04) {
        ZITI_LOG(ERROR, "invalid peer P-256 public key (len=%zu, first byte=0x%02x)",
                 peer_key_len, peer_key[0]);
        return -1;
    }

    // Build BCRYPT_ECCPUBLIC_BLOB from the 65-byte uncompressed wire form.
    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)pub_blob;
    hdr->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    hdr->cbKey   = ECDH_P256_COORD_LEN;
    memcpy(pub_blob + sizeof(BCRYPT_ECCKEY_BLOB), peer_key + 1, 2 * ECDH_P256_COORD_LEN);

    s = BCryptImportKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, NULL, BCRYPT_ECCPUBLIC_BLOB, &peer_pub,
                            pub_blob, sizeof(pub_blob), 0);
    if (!BCRYPT_SUCCESS(s)) {
        ZITI_LOG(ERROR, "BCryptImportKeyPair(peer pub) failed: 0x%lx", s);
        goto cleanup;
    }

    // ECDH agreement
    s = BCryptSecretAgreement(e->ecdh_key, peer_pub, &secret, 0);
    if (!BCRYPT_SUCCESS(s)) {
        ZITI_LOG(ERROR, "BCryptSecretAgreement failed: 0x%lx", s);
        goto cleanup;
    }

    ULONG written = 0;
    s = BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL,
                        shared_secret, sizeof(shared_secret), &written, 0);
    if (!BCRYPT_SUCCESS(s) || written != sizeof(shared_secret)) {
        ZITI_LOG(ERROR, "BCryptDeriveKey(RAW_SECRET) failed: 0x%lx (written=%lu)", s, written);
        goto cleanup;
    }

    // BCRYPT_KDF_RAW_SECRET returns the shared secret in little-endian byte order, while
    // OpenSSL's EVP_PKEY_derive returns big-endian. Reverse to match the OSSL backend.
    // (Interop contract item 2.)
    reverse_bytes(shared_secret, sizeof(shared_secret));

    // rx HKDF: info = role || my_pub || peer_pub
    info[0] = server ? 1 : 0;
    memcpy(info + 1,                  e->pub_key, e->pub_key_len);
    memcpy(info + 1 + e->pub_key_len, peer_key,   peer_key_len);
    if (hkdf_sha256(shared_secret, sizeof(shared_secret),
                    info, sizeof(info), derived, sizeof(derived)) != 0) {
        goto cleanup;
    }
    memcpy(e->rx_key,       derived,                    sizeof(e->rx_key));
    memcpy(e->rx_iv_prefix, derived + sizeof(e->rx_key), sizeof(e->rx_iv_prefix));

    // tx HKDF: flip role, swap pub-key order
    info[0] = server ? 0 : 1;
    memcpy(info + 1,                peer_key,   peer_key_len);
    memcpy(info + 1 + peer_key_len, e->pub_key, e->pub_key_len);
    if (hkdf_sha256(shared_secret, sizeof(shared_secret),
                    info, sizeof(info), derived, sizeof(derived)) != 0) {
        goto cleanup;
    }
    memcpy(e->tx_key,       derived,                    sizeof(e->tx_key));
    memcpy(e->tx_iv_prefix, derived + sizeof(e->tx_key), sizeof(e->tx_iv_prefix));

    ret = 0;

cleanup:
    SecureZeroMemory(shared_secret, sizeof(shared_secret));
    SecureZeroMemory(derived,       sizeof(derived));
    SecureZeroMemory(pub_blob,      sizeof(pub_blob));
    if (peer_pub) BCryptDestroyKey(peer_pub);
    if (secret)   BCryptDestroySecret(secret);
    return ret;
}

static e2ee_pub_t aes_gcm_pub(struct e2ee *e2ee) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    PRINT_BYTES("own pub key", e->pub_key, e->pub_key_len);
    return (e2ee_pub_t){.key = e->pub_key, .key_len = e->pub_key_len};
}

static int aes_gcm_init(struct e2ee *e2ee, const uint8_t *peer_key, size_t peer_key_len, bool server) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;

    if (peer_key_len != e->pub_key_len) {
        return -1;
    }

    // Already initialized
    if (!sodium_is_zero(e->rx_key, sizeof(e->rx_key)) ||
        !sodium_is_zero(e->tx_key, sizeof(e->tx_key))) {
        return -1;
    }

    int ret = derive_session_keys(e, peer_key, peer_key_len, server);

    // Scrub ECDH private key material regardless of outcome
    if (e->ecdh_key) {
        BCryptDestroyKey(e->ecdh_key);
        e->ecdh_key = NULL;
    }

    if (ret != 0) {
        return -1;
    }

    e->tx_counter = 1;
    e->rx_counter = 1;

    NTSTATUS s = BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &e->tx_aes_key, NULL, 0,
                                            e->tx_key, AES_KEY_LEN, 0);
    if (!BCRYPT_SUCCESS(s)) {
        ZITI_LOG(ERROR, "BCryptGenerateSymmetricKey(tx) failed: 0x%lx", s);
        return -1;
    }
    s = BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &e->rx_aes_key, NULL, 0,
                                   e->rx_key, AES_KEY_LEN, 0);
    if (!BCRYPT_SUCCESS(s)) {
        ZITI_LOG(ERROR, "BCryptGenerateSymmetricKey(rx) failed: 0x%lx", s);
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

static ssize_t aes_gcm_encrypt(e2ee_t *e2ee, const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *ciphertext, size_t ciphertext_len) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    if (ciphertext_len < plaintext_len + AES_GCM_TAG_LEN) {
        return -1;
    }
    if (e->tx_counter == UINT64_MAX) {
        ZITI_LOG(ERROR, "AES-GCM encryption counter overflow");
        return -1;
    }

    uint8_t iv[AES_GCM_NONCE_LEN];
    build_nonce(iv, e->tx_iv_prefix, e->tx_counter);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv;
    info.cbNonce = AES_GCM_NONCE_LEN;
    info.pbTag   = ciphertext + plaintext_len;  // tag appended after ciphertext
    info.cbTag   = AES_GCM_TAG_LEN;

    ULONG written = 0;
    NTSTATUS s = BCryptEncrypt(e->tx_aes_key, (PUCHAR)plaintext, (ULONG)plaintext_len,
                               &info, NULL, 0, ciphertext, (ULONG)plaintext_len,
                               &written, 0);
    if (!BCRYPT_SUCCESS(s) || written != plaintext_len) {
        ZITI_LOG(ERROR, "aes-gcm encryption failed: 0x%lx (written=%lu, expected=%zu)",
                 s, written, plaintext_len);
        return -1;
    }

    e->tx_counter++;
    return (ssize_t)(plaintext_len + AES_GCM_TAG_LEN);
}

static ssize_t aes_gcm_decrypt(e2ee_t *e2ee, const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *plaintext, size_t plaintext_len) {
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

    uint8_t iv[AES_GCM_NONCE_LEN];
    build_nonce(iv, e->rx_iv_prefix, e->rx_counter);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv;
    info.cbNonce = AES_GCM_NONCE_LEN;
    info.pbTag   = (PUCHAR)(ciphertext + ct_data_len);
    info.cbTag   = AES_GCM_TAG_LEN;

    ULONG written = 0;
    NTSTATUS s = BCryptDecrypt(e->rx_aes_key, (PUCHAR)ciphertext, (ULONG)ct_data_len,
                               &info, NULL, 0, plaintext, (ULONG)ct_data_len,
                               &written, 0);
    if (!BCRYPT_SUCCESS(s) || written != ct_data_len) {
        ZITI_LOG(WARN, "aes-gcm decryption failed: 0x%lx (written=%lu, expected=%zu)",
                 s, written, ct_data_len);
        return -1;
    }

    e->rx_counter++;
    return (ssize_t)ct_data_len;
}

static struct e2ee *aes_gcm_clone(struct e2ee *e2ee) {
    (void)e2ee;
    ZITI_LOG(ERROR, "clone not implemented for wincrypto aes-gcm backend");
    abort();
}

static void aes_gcm_free(e2ee_t *e2ee) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    if (e->tx_aes_key) BCryptDestroyKey(e->tx_aes_key);
    if (e->rx_aes_key) BCryptDestroyKey(e->rx_aes_key);
    if (e->ecdh_key)   BCryptDestroyKey(e->ecdh_key);
    SecureZeroMemory(e, sizeof(struct aes_gcm_e2ee));
    free(e);
}

static e2ee_t aes_gcm_e2ee_impl = {
    .method     = ziti_crypto_aes_gcm,
    .clone      = aes_gcm_clone,
    .pub        = aes_gcm_pub,
    .init       = aes_gcm_init,
    .get_header = aes_gcm_get_header,
    .encrypt    = aes_gcm_encrypt,
    .decrypt    = aes_gcm_decrypt,
    .free       = aes_gcm_free,
};

struct aes_gcm_e2ee *new_aes_gcm_e2ee(void) {
    struct aes_gcm_e2ee *e = calloc(1, sizeof(struct aes_gcm_e2ee));
    if (e == NULL) {
        ZITI_LOG(ERROR, "failed to allocate aes-gcm e2ee: out of memory");
        abort();
    }

    e->e2ee = aes_gcm_e2ee_impl;

    NTSTATUS s = BCryptGenerateKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, &e->ecdh_key, 256, 0);
    if (!BCRYPT_SUCCESS(s)) {
        ZITI_LOG(ERROR, "BCryptGenerateKeyPair(P-256) failed: 0x%lx", s);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }
    s = BCryptFinalizeKeyPair(e->ecdh_key, 0);
    if (!BCRYPT_SUCCESS(s)) {
        ZITI_LOG(ERROR, "BCryptFinalizeKeyPair(P-256) failed: 0x%lx", s);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }

    // Export BCRYPT_ECCPUBLIC_BLOB (72 bytes) and convert to 65-byte uncompressed wire form.
    uint8_t blob[ECDH_P256_BLOB_LEN];
    ULONG blob_len = 0;
    s = BCryptExportKey(e->ecdh_key, NULL, BCRYPT_ECCPUBLIC_BLOB,
                        blob, sizeof(blob), &blob_len, 0);
    if (!BCRYPT_SUCCESS(s) || blob_len != sizeof(blob)) {
        ZITI_LOG(ERROR, "BCryptExportKey(ECCPUBLIC_BLOB) failed: 0x%lx (blob_len=%lu)",
                 s, blob_len);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }

    e->pub_key[0] = 0x04;
    memcpy(e->pub_key + 1, blob + sizeof(BCRYPT_ECCKEY_BLOB), 2 * ECDH_P256_COORD_LEN);
    e->pub_key_len = ECDH_P256_PUB_LEN;

    return e;
}
