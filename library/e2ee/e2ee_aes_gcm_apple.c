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

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonCrypto.h>

#include "crypto.h"
#include "ziti/ziti_log.h"

// AES-256-GCM comes from CryptoKit via the @_cdecl wrappers in e2ee_aes_gcm_cryptokit.swift.
// Apple exposes no raw AES-GCM to C -- `GCM` appears nowhere in the public CommonCrypto headers
// of any Apple SDK, and Security.framework offers only whole-scheme ECIES, which picks its own
// key and nonce -- so the Swift hop is what keeps this backend free of undocumented SPI.
#ifdef __cplusplus
// the unit tests #include this file inside a namespace to reach its statics
extern "C" {
#endif

extern int ziti_cryptokit_aes_gcm_seal(const uint8_t *key, size_t key_len,
                                       const uint8_t *nonce, size_t nonce_len,
                                       const uint8_t *plaintext, size_t pt_len,
                                       uint8_t *ciphertext,
                                       uint8_t *tag, size_t tag_len);

extern int ziti_cryptokit_aes_gcm_open(const uint8_t *key, size_t key_len,
                                       const uint8_t *nonce, size_t nonce_len,
                                       const uint8_t *ciphertext, size_t ct_len,
                                       const uint8_t *tag, size_t tag_len,
                                       uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#define AES_GCM_TAG_LEN 16
#define AES_GCM_NONCE_LEN 12
#define AES_GCM_NONCE_PREFIX_LEN 4

#define AES_GCM_KEY_LEN 32
#define P256_PUB_KEY_LEN 65

#if AES_GCM_NONCE_LEN > E2EE_MAX_HEADER_LEN
#error "AES_GCM_NONCE_LEN is too large"
#endif

#if AES_GCM_TAG_LEN > E2EE_MAX_MSG_OVERHEAD
#error "AES_GCM_TAG_LEN is too large"
#endif

struct aes_gcm_e2ee {
    e2ee_t e2ee;
    // released and cleared by init(): key material must not outlive the key exchange
    SecKeyRef privkey;
    uint8_t pub_key[P256_PUB_KEY_LEN];
    size_t pub_key_len;

    uint8_t rx_key[AES_GCM_KEY_LEN];
    uint8_t tx_key[AES_GCM_KEY_LEN];
    uint8_t rx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    uint8_t tx_iv_prefix[AES_GCM_NONCE_PREFIX_LEN];
    uint64_t tx_counter;
    uint64_t rx_counter;
    bool header_sent;
};

static void log_cf_error(const char *msg, CFErrorRef err) {
    if (err == NULL) {
        ZITI_LOG(ERROR, "%s", msg);
        return;
    }

    char buf[256] = "unknown error";
    CFStringRef desc = CFErrorCopyDescription(err);
    if (desc != NULL) {
        CFStringGetCString(desc, buf, sizeof(buf), kCFStringEncodingUTF8);
        CFRelease(desc);
    }
    ZITI_LOG(ERROR, "%s: %s", msg, buf);
}

static void build_nonce(uint8_t out[AES_GCM_NONCE_LEN], const uint8_t *initial, uint64_t counter) {
    memcpy(out, initial, AES_GCM_NONCE_PREFIX_LEN);
    int shift = 0;
    for (int i = AES_GCM_NONCE_LEN; i > AES_GCM_NONCE_PREFIX_LEN; i--) {
        out[i - 1] = (counter >> shift) & 0xff;
        shift += 8;
    }
}

// RFC 5869 HKDF-SHA256 with an empty salt, matching EVP_PKEY_HKDF with no salt set.
// An absent salt is defined as HashLen zero bytes; HMAC zero-pads its key to the block size,
// so that is identical to the zero-length key the extract step would otherwise use.
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    const uint8_t salt[CC_SHA256_DIGEST_LENGTH] = {0};
    uint8_t prk[CC_SHA256_DIGEST_LENGTH];
    uint8_t t[CC_SHA256_DIGEST_LENGTH];
    size_t t_len = 0;
    size_t done = 0;

    if (out_len > 255 * CC_SHA256_DIGEST_LENGTH) {
        return -1;
    }

    // extract
    CCHmac(kCCHmacAlgSHA256, salt, sizeof(salt), ikm, ikm_len, prk);

    // expand: T(n) = HMAC(PRK, T(n-1) || info || n)
    for (uint8_t counter = 1; done < out_len; counter++) {
        CCHmacContext ctx;
        CCHmacInit(&ctx, kCCHmacAlgSHA256, prk, sizeof(prk));
        CCHmacUpdate(&ctx, t, t_len);
        CCHmacUpdate(&ctx, info, info_len);
        CCHmacUpdate(&ctx, &counter, sizeof(counter));
        CCHmacFinal(&ctx, t);
        t_len = sizeof(t);

        size_t chunk = out_len - done < t_len ? out_len - done : t_len;
        memcpy(out + done, t, chunk);
        done += chunk;
    }

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(t, sizeof(t));
    return 0;
}

static SecKeyRef import_peer_key(const uint8_t *peer_key, size_t peer_key_len) {
    SecKeyRef peer = NULL;
    CFErrorRef err = NULL;
    const int bits = 256;

    CFNumberRef size = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits};
    const void *vals[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic, size};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 3,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFDataRef data = CFDataCreate(NULL, peer_key, (CFIndex) peer_key_len);

    peer = SecKeyCreateWithData(data, attrs, &err);
    if (peer == NULL) {
        log_cf_error("failed to import peer P-256 public key", err);
        if (err) CFRelease(err);
    }

    CFRelease(data);
    CFRelease(attrs);
    CFRelease(size);
    return peer;
}

static int derive_session_keys(struct aes_gcm_e2ee *e, const uint8_t *peer_key, size_t peer_key_len, bool server) {
    uint8_t shared_secret[AES_GCM_KEY_LEN] = {0};
    // HKDF output per direction: AES-256 key (32 bytes) || GCM IV fixed_field (4 bytes)
    uint8_t derived[sizeof(e->rx_key) + sizeof(e->rx_iv_prefix)] = {0};
    // role_byte + my_pub + peer_pub
    uint8_t info[1 + sizeof(e->pub_key) * 2];
    int ret = -1;

    SecKeyRef peer = import_peer_key(peer_key, peer_key_len);
    if (peer == NULL) {
        return -1;
    }

    CFErrorRef err = NULL;
    CFDictionaryRef params = CFDictionaryCreate(NULL, NULL, NULL, 0,
                                                &kCFTypeDictionaryKeyCallBacks,
                                                &kCFTypeDictionaryValueCallBacks);
    CFDataRef ss = SecKeyCopyKeyExchangeResult(e->privkey, kSecKeyAlgorithmECDHKeyExchangeStandard,
                                               peer, params, &err);
    CFRelease(params);
    CFRelease(peer);

    if (ss == NULL) {
        log_cf_error("ECDH key exchange failed", err);
        if (err) CFRelease(err);
        return -1;
    }
    if (CFDataGetLength(ss) != (CFIndex) sizeof(shared_secret)) {
        ZITI_LOG(ERROR, "unexpected ECDH shared secret length: %ld", (long) CFDataGetLength(ss));
        CFRelease(ss);
        return -1;
    }
    memcpy(shared_secret, CFDataGetBytePtr(ss), sizeof(shared_secret));
    CFRelease(ss);

    // Include role + both public keys in info so server and client derive complementary material.
    info[0] = server ? 1 : 0;
    memcpy(info + 1, e->pub_key, e->pub_key_len);
    memcpy(info + 1 + e->pub_key_len, peer_key, peer_key_len);
    if (hkdf_sha256(shared_secret, sizeof(shared_secret), info, sizeof(info),
                    derived, sizeof(derived)) != 0) {
        goto cleanup;
    }
    memcpy(e->rx_key, derived, sizeof(e->rx_key));
    memcpy(e->rx_iv_prefix, derived + sizeof(e->rx_key), sizeof(e->rx_iv_prefix));

    // Derive tx material with different info (flip role byte, swap pub-key order)
    info[0] = server ? 0 : 1;
    memcpy(info + 1, peer_key, peer_key_len);
    memcpy(info + 1 + peer_key_len, e->pub_key, e->pub_key_len);
    if (hkdf_sha256(shared_secret, sizeof(shared_secret), info, sizeof(info),
                    derived, sizeof(derived)) != 0) {
        goto cleanup;
    }
    memcpy(e->tx_key, derived, sizeof(e->tx_key));
    memcpy(e->tx_iv_prefix, derived + sizeof(e->tx_key), sizeof(e->tx_iv_prefix));

    ret = 0;

cleanup:
    if (ret != 0) {
        ZITI_LOG(ERROR, "Failed to derive session keys");
    }
    sodium_memzero(shared_secret, sizeof(shared_secret));
    sodium_memzero(derived, sizeof(derived));
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

    // Release secret key material regardless of outcome
    CFRelease(e->privkey);
    e->privkey = NULL;

    if (ret != 0) {
        return -1;
    }

    e->tx_counter = 1;
    e->rx_counter = 1;

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

    uint8_t iv[AES_GCM_NONCE_LEN];
    build_nonce(iv, e->tx_iv_prefix, e->tx_counter);

    if (ziti_cryptokit_aes_gcm_seal(e->tx_key, sizeof(e->tx_key),
                                    iv, sizeof(iv),
                                    plaintext, plaintext_len,
                                    ciphertext, ciphertext + plaintext_len,
                                    AES_GCM_TAG_LEN) != 0) {
        ZITI_LOG(ERROR, "aes-gcm encryption failed");
        return -1;
    }

    e->tx_counter++;
    return (ssize_t)required;
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

    uint8_t iv[AES_GCM_NONCE_LEN];
    build_nonce(iv, e->rx_iv_prefix, e->rx_counter);

    if (ziti_cryptokit_aes_gcm_open(e->rx_key, sizeof(e->rx_key),
                                    iv, sizeof(iv),
                                    ciphertext, ct_data_len,
                                    ciphertext + ct_data_len, AES_GCM_TAG_LEN,
                                    plaintext) != 0) {
        ZITI_LOG(WARN, "aes-gcm decryption failed");
        return -1;
    }

    e->rx_counter++;
    return (ssize_t)ct_data_len;
}

static struct e2ee *aes_gcm_clone(struct e2ee *e2ee) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;

    if (e->privkey == NULL) {
        ZITI_LOG(ERROR, "cannot clone aes-gcm e2ee after init was called");
        abort();
    }

    struct aes_gcm_e2ee *clone = (struct aes_gcm_e2ee*)calloc(1, sizeof(struct aes_gcm_e2ee));
    if (clone == NULL) {
        ZITI_LOG(ERROR, "failed to allocate aes-gcm e2ee: out of memory");
        abort();
    }

    clone->e2ee = e->e2ee;

    // SecKeyRef is immutable and only read until init(), so each clone can share it
    // behind its own reference: releasing one clone's handle cannot disturb a sibling.
    clone->privkey = (SecKeyRef) CFRetain(e->privkey);

    memcpy(clone->pub_key, e->pub_key, e->pub_key_len);
    clone->pub_key_len = e->pub_key_len;

    return &clone->e2ee;
}

static void aes_gcm_free(e2ee_t *e2ee) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee *)e2ee;
    if (e->privkey) {
        CFRelease(e->privkey);
    }
    sodium_memzero(e, sizeof(struct aes_gcm_e2ee));
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

// Generate a memory-only P-256 keypair. Never persisted: kSecAttrIsPermanent is
// explicitly false so nothing reaches the user's keychain.
static SecKeyRef generate_keypair(void) {
    const int bits = 256;
    CFNumberRef size = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    const void *keys[] = {kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrIsPermanent};
    const void *vals[] = {kSecAttrKeyTypeECSECPrimeRandom, size, kCFBooleanFalse};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 3,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);

    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(attrs, &err);
    if (key == NULL) {
        log_cf_error("failed to generate P-256 keypair", err);
        if (err) CFRelease(err);
    }

    CFRelease(attrs);
    CFRelease(size);
    return key;
}

struct aes_gcm_e2ee *new_aes_gcm_e2ee(void) {
    struct aes_gcm_e2ee *e = (struct aes_gcm_e2ee*)calloc(1, sizeof(struct aes_gcm_e2ee));
    if (e == NULL) {
        ZITI_LOG(ERROR, "failed to allocate aes-gcm e2ee: out of memory");
        abort();
    }

    e->e2ee = aes_gcm_e2ee_impl;

    e->privkey = generate_keypair();
    if (e->privkey == NULL) {
        aes_gcm_free((e2ee_t *)e);
        abort();
    }

    // export the public part as an uncompressed X9.63 point (0x04 || X || Y)
    SecKeyRef pub = SecKeyCopyPublicKey(e->privkey);
    if (pub == NULL) {
        ZITI_LOG(ERROR, "failed to get public key from P-256 keypair");
        aes_gcm_free((e2ee_t *)e);
        abort();
    }

    CFErrorRef err = NULL;
    CFDataRef data = SecKeyCopyExternalRepresentation(pub, &err);
    CFRelease(pub);
    if (data == NULL) {
        log_cf_error("failed to export P-256 public key", err);
        if (err) CFRelease(err);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }
    if (CFDataGetLength(data) != (CFIndex) sizeof(e->pub_key)) {
        ZITI_LOG(ERROR, "unexpected P-256 public key length: %ld", (long) CFDataGetLength(data));
        CFRelease(data);
        aes_gcm_free((e2ee_t *)e);
        abort();
    }
    memcpy(e->pub_key, CFDataGetBytePtr(data), sizeof(e->pub_key));
    e->pub_key_len = sizeof(e->pub_key);
    CFRelease(data);

    return e;
}