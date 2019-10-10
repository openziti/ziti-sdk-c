//
// Created by eugene on 2/27/19.
//

#ifndef ZT_SDK_TLS_H
#define ZT_SDK_TLS_H

#include <mbedtls/ssl.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
/*
 * init global TLS stuff
 */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mbedtls_ssl_config config;
    mbedtls_pk_context key;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt cacert;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} nf_tls_context;

void tls_debug(void *ctx, int level,
               const char *file, int line,
               const char *str);

int load_key(mbedtls_pk_context *pk, const char *spec);

#ifdef __cplusplus
};
#endif

#endif //ZT_SDK_TLS_H
