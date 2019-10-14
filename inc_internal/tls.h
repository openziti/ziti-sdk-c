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
