/*
Copyright (c) 2019-2020 NetFoundry, Inc.

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


#ifndef ZITI_SDK_ENROLL_H
#define ZITI_SDK_ENROLL_H

#define MBEDTLS_PLATFORM_C
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_csr.h>
#include "ziti_model.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct enroll_cfg_s {

    nf_enroll_cb external_enroll_cb;

    ziti_enrollment_jwt_header *zejh;
    ziti_enrollment_jwt *zej;
    char *raw_jwt;
    char *jwt_signing_input;
    char *jwt_sig;
    size_t jwt_sig_len;

    char *CA;

    char *PrivateKey;
    mbedtls_pk_context pk_context;

    unsigned char x509_csr_pem[4096];
    mbedtls_x509write_csr x509_csr_ctx;
    
} enroll_cfg;


#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ENROLL_H
