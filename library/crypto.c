/*
Copyright 2019-2020 NetFoundry, Inc.

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

#include <ziti/ziti.h>
#include "zt_internal.h"
#include "utils.h"


#define DFL_EC_CURVE            mbedtls_ecp_curve_list()->grp_id

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                MBEDTLS_PK_ECKEY
#define DFL_RSA_KEYSIZE         4096
#define DFL_FILENAME            "keyfile.key"
#define DFL_FORMAT              FORMAT_PEM
#define DFL_USE_DEV_RANDOM      0


struct options
{
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    int ec_curve;               /* curve identifier for EC keys         */
    const char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
    int use_dev_random;         /* use /dev/random as entropy source    */
} opt;


int gen_key(mbedtls_pk_context *pk_context) {

    int ret = 1;
    char buf[1024];
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    // Set some sane values
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    opt.type                = DFL_TYPE;
    opt.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt.ec_curve            = MBEDTLS_ECP_DP_SECP256R1;
    opt.filename            = DFL_FILENAME;
    opt.format              = DFL_FORMAT;
    opt.use_dev_random      = DFL_USE_DEV_RANDOM;


    mbedtls_pk_init( pk_context );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( buf, 0, sizeof( buf ) );

    mbedtls_entropy_init( &entropy );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ctr_drbg_seed returned -0x%04x", -ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    // Generate the key
    if( ( ret = mbedtls_pk_setup( pk_context, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) opt.type ) ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_pk_setup returned -0x%04x", -ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    if( ( ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) opt.ec_curve, mbedtls_pk_ec( *pk_context ), mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ecp_gen_key returned -0x%04x", -ret);
        return ZITI_KEY_GENERATION_FAILED;        
    }

    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( *pk_context );
    // ZITI_LOG(DEBUG, "curve: %s", mbedtls_ecp_curve_info_from_grp_id( ecp->grp.id )->name );

    return ZITI_OK;
}

#define DFL_FILENAME            "keyfile.key"
#define DFL_PASSWORD            NULL
#define DFL_DEBUG_LEVEL         0
#define DFL_OUTPUT_FILENAME     "cert.req"
#define DFL_SUBJECT_NAME        "C=US,O=NetFoundry,CN="
#define DFL_KEY_USAGE           0
#define DFL_FORCE_KEY_USAGE     0
#define DFL_NS_CERT_TYPE        0
#define DFL_FORCE_NS_CERT_TYPE  0
#define DFL_MD_ALG              MBEDTLS_MD_SHA256

struct csroptions
{
    const char *filename;       /* filename of the key file             */
    const char *password;       /* password for the key file            */
    int debug_level;            /* level of debugging                   */
    const char *output_file;    /* where to store the constructed key file  */
    const char *subject_name;   /* subject name for certificate request */
    unsigned char key_usage;    /* key usage flags                      */
    int force_key_usage;        /* Force adding the KeyUsage extension  */
    unsigned char ns_cert_type; /* NS cert type                         */
    int force_ns_cert_type;     /* Force adding NsCertType extension    */
    mbedtls_md_type_t md_alg;   /* Hash algorithm used for signature.   */
} csropt;


int gen_csr(enroll_cfg *cfg) {

    int ret = 1;
    mbedtls_pk_context key;
    mbedtls_ctr_drbg_context ctr_drbg;
    char buf[1024];
    mbedtls_entropy_context entropy;
    const char *pers = "gen_csr";

    // Set to sane values
    mbedtls_x509write_csr_init( &cfg->x509_csr_ctx );
    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( buf, 0, sizeof( buf ) );

    csropt.filename            = DFL_FILENAME;
    csropt.password            = DFL_PASSWORD;
    csropt.debug_level         = DFL_DEBUG_LEVEL;
    csropt.output_file         = DFL_OUTPUT_FILENAME;

    char subject_name[256];
    strcpy(subject_name, DFL_SUBJECT_NAME);
    strcat(subject_name, cfg->zej->subject);
    csropt.subject_name        = subject_name;

    csropt.key_usage           = DFL_KEY_USAGE;
    csropt.force_key_usage     = DFL_FORCE_KEY_USAGE;
    csropt.ns_cert_type        = MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT;
    csropt.force_ns_cert_type  = 1;
    csropt.md_alg              = MBEDTLS_MD_SHA256;

    mbedtls_x509write_csr_set_md_alg( &cfg->x509_csr_ctx, csropt.md_alg );

    mbedtls_x509write_csr_set_key_usage( &cfg->x509_csr_ctx, csropt.key_usage );

    mbedtls_x509write_csr_set_ns_cert_type( &cfg->x509_csr_ctx, csropt.ns_cert_type );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ctr_drbg_seed returned %d", ret);
        return ZITI_CSR_GENERATION_FAILED;
    }

    if( ( ret = mbedtls_x509write_csr_set_subject_name( &cfg->x509_csr_ctx, csropt.subject_name ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_x509write_csr_set_subject_name returned %d", ret);
        return ZITI_CSR_GENERATION_FAILED;
    }

    mbedtls_x509write_csr_set_key( &cfg->x509_csr_ctx, &cfg->pk_context );

    memset( cfg->x509_csr_pem, 0, sizeof(cfg->x509_csr_pem) );

    if( ( ret = mbedtls_x509write_csr_pem( &cfg->x509_csr_ctx, cfg->x509_csr_pem, 4096, mbedtls_ctr_drbg_random, &ctr_drbg ) ) < 0 ) {
        ZITI_LOG(ERROR, "mbedtls_x509write_csr_pem returned %d", ret);
        return ZITI_CSR_GENERATION_FAILED;
    }

    return ZITI_OK;
}