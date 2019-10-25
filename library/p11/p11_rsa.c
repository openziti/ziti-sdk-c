/*
Copyright 2019 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <utils.h>
#include "mbed_p11.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>

static int p11_rsa_can_do(mbedtls_pk_type_t type);

static int p11_rsa_sign(void *ctx, mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

static int p11_rsa_verify(void *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len);

static size_t p11_rsa_bitlen(const void *ctx);

static void p11_rsa_free(void *ctx);

static int get_md_prefix(mbedtls_md_type_t md, const char **prefix, size_t *len);

const mbedtls_pk_info_t p11_rsa_info = {
        MBEDTLS_PK_RSA,
        "RSA",
        p11_rsa_bitlen,
        p11_rsa_can_do,
        p11_rsa_verify,
        p11_rsa_sign,
#if defined(MBEDTLS_ECP_RESTARTABLE)
rsa_verify_rs_wrap,
rsa_sign_rs_wrap,
#endif
        NULL,
        NULL,
        NULL, //eckey_check_pair,   /* Compatible key structures */
        NULL, //rsa_alloc_wrap,
        p11_rsa_free,
#if defined(MBEDTLS_ECP_RESTARTABLE)
rsa_rs_alloc,
rsa_rs_free,
#endif
        NULL, //eckey_debug,        /* Compatible key structures */
};

int p11_load_rsa(mbedtls_pk_context *pk, struct mp11_key_ctx_s *p11key, mp11_context *p11) {
    pk->pk_info = &p11_rsa_info;
    pk->pk_ctx = p11key;
    p11key->ctx = p11;

    PREPCF(p11, non_zero, p11_strerror);

    // load public key
    CK_BYTE ec_param[512];
    memset(ec_param, 0, sizeof(ec_param));
    CK_BYTE ec_point[MBEDTLS_ECP_MAX_PT_LEN];

    CK_ATTRIBUTE pubattr[] = {
            {CKA_PUBLIC_EXPONENT, NULL, 0},
            {CKA_MODULUS,         NULL, 0},
    };

    TRY(p11, p11->funcs->C_GetAttributeValue(p11->session, p11key->pub_handle, pubattr, 2));
    pubattr[0].pValue = malloc(pubattr[0].ulValueLen);
    pubattr[1].pValue = malloc(pubattr[1].ulValueLen);
    TRY(p11, p11->funcs->C_GetAttributeValue(p11->session, p11key->pub_handle, pubattr, 2));

    NEWP(rsa, mbedtls_rsa_context);
    mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);
    mbedtls_mpi_read_binary(&rsa->N, pubattr[1].pValue, pubattr[1].ulValueLen);
    mbedtls_mpi_read_binary(&rsa->E, pubattr[0].pValue, pubattr[0].ulValueLen);

    rsa->len = mbedtls_mpi_size(&rsa->N);

    CK_MECHANISM_TYPE sign_mech = CKM_RSA_PKCS;
    CK_MECHANISM_INFO mech_info;
    CK_RV rv = p11->funcs->C_GetMechanismInfo(p11->slot_id, sign_mech, &mech_info);
    if (rv != CKR_OK) {
        sign_mech = CKM_RSA_PKCS;
        rv = p11->funcs->C_GetMechanismInfo(p11->slot_id, sign_mech, &mech_info);
    }
    TRY(p11, ("expected signing mechanism not found", rv));
    p11key->sign_mechanism = sign_mech;
    p11key->pub = rsa;

    CATCH(p11) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    return 0;
}

static int p11_rsa_can_do(mbedtls_pk_type_t type) {
    return (type == MBEDTLS_PK_ECDSA);
}

static int p11_rsa_sign(void *ctx, mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng) {
    PREPCF(p11, non_zero, p11_strerror);

    mp11_key_ctx *p11key = ctx;
    mp11_context *p11 = p11key->ctx;

    CK_MECHANISM mech = {
            p11key->sign_mechanism,
    };

    CK_BYTE rawsig[4096];
    CK_ULONG rawsig_len = sizeof(rawsig);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_alg);
    if (md_info == NULL) {
        return (MBEDTLS_ERR_RSA_BAD_INPUT_DATA);
    }


    hash_len = mbedtls_md_get_size(md_info);

    const char *oid = "";
    size_t oid_len = 0;
    int rc = get_md_prefix(md_alg, &oid, &oid_len);

    CK_BYTE *msg = malloc(hash_len + oid_len);
    memcpy(msg, oid, oid_len);
    memcpy(msg + oid_len, hash, hash_len);

    TRY(p11, p11->funcs->C_SignInit(p11->session, &mech, p11key->priv_handle));
    TRY(p11, p11->funcs->C_Sign(p11->session, msg, hash_len + oid_len, rawsig, &rawsig_len));

    memcpy(sig, rawsig, rawsig_len);
    *sig_len = rawsig_len;

    CATCH(p11) {
        return MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    }

    return 0;
}

static int p11_rsa_verify(void *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len) {
    mp11_key_ctx *p11key = ctx;
    PREPF(mbed, fmt_mbederr);

    TRY(mbed,
        mbedtls_rsa_rsassa_pkcs1_v15_verify(p11key->pub, NULL, NULL, MBEDTLS_RSA_PUBLIC, md_alg, hash_len, hash, sig));
    CATCH(mbed) {
        return ERR(mbed);
    }

    return 0;
}

static void p11_rsa_free(void *ctx) {
    mp11_key_ctx *p11key = ctx;
    mbedtls_rsa_free(p11key->pub);
    free(p11key->pub);
    free(ctx);
}

static size_t p11_rsa_bitlen(const void *ctx) {
    mp11_key_ctx *p11key = (mp11_key_ctx *) ctx;
    return 8 * mbedtls_rsa_get_len(p11key->pub);
}

// pre-computed hash prefixes
// copied from golang/crypto/rsa/rsa.go
#define HASH_HEADERS(XX) \
XX(MBEDTLS_MD_MD5,       __bytes(0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10))\
XX(MBEDTLS_MD_SHA1,      __bytes(0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14))\
XX(MBEDTLS_MD_SHA224,    __bytes(0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c))\
XX(MBEDTLS_MD_SHA256,    __bytes(0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20))\
XX(MBEDTLS_MD_SHA384,    __bytes(0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30))\
XX(MBEDTLS_MD_SHA512,    __bytes(0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40))\
XX(MBEDTLS_MD_RIPEMD160, __bytes(0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14))

#define MD_PREFIX(id, pfx) static char prefix_##id[] = {pfx};
#define __bytes(...) __VA_ARGS__

HASH_HEADERS(MD_PREFIX)

static int get_md_prefix(mbedtls_md_type_t md, const char **prefix, size_t *len) {
#define MD_CASE(id, _) case id: { *prefix = prefix_##id; *len = sizeof(prefix_##id); } break;
    switch (md) {
        HASH_HEADERS(MD_CASE)

        default:
            return 1;
    }

    return 0;
}