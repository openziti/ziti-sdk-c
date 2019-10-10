//
// Created by eugene on 7/2/19.
//

#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <utils.h>
#include "mbed_p11.h"
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>

static int p11_ecdsa_can_do(mbedtls_pk_type_t type);

static int p11_ecdsa_sign(void *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          unsigned char *sig, size_t *sig_len,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng);

static int p11_ecdsa_verify(void *ctx, mbedtls_md_type_t md_alg,
                            const unsigned char *hash, size_t hash_len,
                            const unsigned char *sig, size_t sig_len);

static size_t p11_ecdsa_bitlen(const void *ctx);
static void p11_ecdsa_free(void *ctx);

static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s,
                                   unsigned char *sig, size_t *slen);

const mbedtls_pk_info_t p11_ecdsa_info = {
        MBEDTLS_PK_ECDSA,
        "ECDSA",
        p11_ecdsa_bitlen,
        p11_ecdsa_can_do,
        p11_ecdsa_verify,
        p11_ecdsa_sign,
#if defined(MBEDTLS_ECP_RESTARTABLE)
ecdsa_verify_rs_wrap,
ecdsa_sign_rs_wrap,
#endif
        NULL,
        NULL,
        NULL, //eckey_check_pair,   /* Compatible key structures */
        NULL, //ecdsa_alloc_wrap,
        p11_ecdsa_free,
#if defined(MBEDTLS_ECP_RESTARTABLE)
ecdsa_rs_alloc,
ecdsa_rs_free,
#endif
        NULL, //eckey_debug,        /* Compatible key structures */
};

int p11_load_ecdsa(mbedtls_pk_context *pk, struct mp11_key_ctx_s *p11key, mp11_context *p11) {
    pk->pk_info = &p11_ecdsa_info;
    pk->pk_ctx = p11key;
    p11key->ctx = p11;

    PREPCF(p11, non_zero, p11_strerror);

    // load public key
    CK_BYTE ec_param[32];
    memset(ec_param, 0, sizeof(ec_param));
    CK_BYTE ec_point[MBEDTLS_ECP_MAX_PT_LEN];

    CK_ATTRIBUTE pubattr[] = {
            {CKA_EC_PARAMS, ec_param, sizeof(ec_param)},
            {CKA_EC_POINT,  ec_point, MBEDTLS_ECP_MAX_PT_LEN},
    };

    TRY(p11, p11->funcs->C_GetAttributeValue(p11->session, p11key->pub_handle, pubattr, 2));

    mbedtls_asn1_buf oid;
    unsigned char *p = ec_param;
    oid.p = ec_param;
    mbedtls_asn1_get_tag(&oid.p, p + pubattr[0].ulValueLen, &oid.len, MBEDTLS_ASN1_OID);

    mbedtls_ecp_group_id grp_id = 0;
    mbedtls_oid_get_ec_grp(&oid, &grp_id);

    NEWP(ecdsa, mbedtls_ecdsa_context);
    mbedtls_ecp_keypair_init(ecdsa);
    mbedtls_ecp_group_load(&ecdsa->grp, grp_id);

    p = ec_point;
    size_t point_len;
    mbedtls_asn1_get_tag(&p, p + pubattr[1].ulValueLen, &point_len, MBEDTLS_ASN1_OCTET_STRING);

    mbedtls_ecp_point_read_binary(&ecdsa->grp, &ecdsa->Q, p, point_len);
    p11key->pub = ecdsa;

    CK_MECHANISM_TYPE sign_mech;
    switch (ecdsa->grp.pbits) {
        case 512:
            sign_mech = CKM_ECDSA_SHA512;
            break;
        case 384:
            sign_mech = CKM_ECDSA_SHA384;
            break;
        case 256:
            sign_mech = CKM_ECDSA_SHA256;
            break;
        case 224:
            sign_mech = CKM_ECDSA_SHA224;
            break;
        default:
            sign_mech = CKM_ECDSA_SHA1;
    }

    CK_MECHANISM_INFO mech_info;
    CK_RV rv = p11->funcs->C_GetMechanismInfo(p11->slot_id, sign_mech, &mech_info);
    if (rv != CKR_OK) {
        sign_mech = CKM_ECDSA;
        rv = p11->funcs->C_GetMechanismInfo(p11->slot_id, sign_mech, &mech_info);
    }
    TRY(p11, ("expected signing mechanism not found", rv));
    p11key->sign_mechanism = sign_mech;


    CATCH(p11) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    return 0;
}

static int p11_ecdsa_can_do(mbedtls_pk_type_t type) {
    return (type == MBEDTLS_PK_ECDSA);
}

static int p11_ecdsa_sign(void *ctx, mbedtls_md_type_t md_alg,
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

    CK_BYTE rawsig[MBEDTLS_ECP_MAX_PT_LEN];
    CK_ULONG rawsig_len = sizeof(rawsig);

    TRY(p11, p11->funcs->C_SignInit(p11->session, &mech, p11key->priv_handle));
    TRY(p11, p11->funcs->C_Sign(p11->session, hash, hash_len, rawsig, &rawsig_len));

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    CK_ULONG coordlen = rawsig_len / 2;
    mbedtls_mpi_read_binary(&r, rawsig, coordlen);
    mbedtls_mpi_read_binary(&s, rawsig + coordlen, coordlen);

    CATCH(p11) {
        return MBEDTLS_ERR_ECP_HW_ACCEL_FAILED;
    }

    ecdsa_signature_to_asn1(&r, &s, sig, sig_len);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return 0;
}

static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s,
                                   unsigned char *sig, size_t *slen) {
    int ret;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    memcpy(sig, p, len);
    *slen = len;

    return (0);
}

static int p11_ecdsa_verify(void *ctx, mbedtls_md_type_t md_alg,
                            const unsigned char *hash, size_t hash_len,
                            const unsigned char *sig, size_t sig_len) {
    mp11_key_ctx *p11key = ctx;
    PREPF(mbed, fmt_mbederr);


    TRY(mbed, mbedtls_ecdsa_read_signature(p11key->pub, hash, hash_len, sig, sig_len));
    CATCH(mbed) {
        return ERR(mbed);
    }

    return 0;
}

static void p11_ecdsa_free(void *ctx) {
    mp11_key_ctx *p11key = ctx;
    mbedtls_ecp_keypair_free(p11key->pub);
    free(p11key->pub);
    free(ctx);
}

static size_t p11_ecdsa_bitlen(const void *ctx) {
    mp11_key_ctx *p11key = (mp11_key_ctx *) ctx;
    return (((mbedtls_ecdsa_context *) p11key->pub)->grp.pbits);
}