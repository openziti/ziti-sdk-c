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

#include <stdlib.h>
#include <mbedtls/base64.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <http_parser.h>
#include "tls.h"
#include "utils.h"
#include "zt_internal.h"
#include "p11/mbed_p11.h"

#if _WIN32
#include <io.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")

#define strncasecmp _strnicmp
#else
#include <unistd.h>
#endif

// inspired by https://golang.org/src/crypto/x509/root_linux.go
// Possible certificate files; stop after finding one.
const char * const caFiles[] = {
        "/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
        "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem",                            // OpenSUSE
        "/etc/pki/tls/cacert.pem",                           // OpenELEC
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
        "/etc/ssl/cert.pem"                                  // macOS
};
#define NUM_CAFILES (sizeof(caFiles) / sizeof(char *))

void tls_debug(void *ctx, int level,
                      const char *file, int line,
                      const char *str)
{
    ((void) level);
    printf("%s:%04d: %s", file, line, str );
    fflush(  stdout );
}

int load_key(mbedtls_pk_context *pk, const char *spec) {

    PREPF(mbed, fmt_mbederr);

    struct http_parser_url url;
    http_parser_url_init(&url);
    http_parser_parse_url(spec, strlen(spec), 0, &url);


    if (strncasecmp("pem", spec + url.field_data[UF_SCHEMA].off, url.field_data[UF_SCHEMA].len) == 0) {

        TRY(mbed, mbedtls_pk_parse_key(pk, spec + 4, strlen(spec) - 3, NULL, 0));

    }
    else if (strncasecmp("der", spec + url.field_data[UF_SCHEMA].off, url.field_data[UF_SCHEMA].len) == 0) {
        if ((url.field_set & (1 << UF_OPAQ)) == 0) {
            return ZITI_WTF;
        }

        size_t len = url.field_data[UF_OPAQ].len;

        size_t derlen;
        unsigned char *der = malloc(len);
        TRY(mbed, mbedtls_base64_decode(der, len, &derlen, spec + url.field_data[UF_OPAQ].off, len));
        TRY(mbed, mbedtls_pk_parse_key(pk, der, derlen, NULL, 0));
        free(der);

    }
    else if (strncasecmp("file", spec + url.field_data[UF_SCHEMA].off, url.field_data[UF_SCHEMA].len) == 0) {
        if ((url.field_set & (1 << UF_PATH)) == 0) {
            ZITI_LOG(ERROR, "key spec error, file without a path");
            return ZITI_KEY_INVALID;
        }

        size_t path_len = url.field_data[UF_PATH].len;

        char *path = malloc(path_len + 1);
        snprintf(path, path_len + 1, "%*.*s", (int) path_len, (int) path_len, spec + url.field_data[UF_PATH].off);
        TRY(mbed, mbedtls_pk_parse_keyfile(pk, path, NULL));
    }
    else if (strncasecmp("pkcs11", spec + url.field_data[UF_SCHEMA].off, url.field_data[UF_SCHEMA].len) == 0) {
        char lib[1024];
        if (!get_url_data(spec, &url, UF_PATH, lib, sizeof(lib)) &&
            !get_url_data(spec, &url, UF_OPAQ, lib, sizeof(lib))) {
            ZITI_LOG(ERROR, "key spec error, pkcs11 requires driver library");
            return ZITI_KEY_INVALID;
        }

        char opts[1024];
        get_url_data(spec, &url, UF_QUERY, opts, sizeof(opts));

        TRY(mbed, mp11_load_key(pk, lib, opts));
    }
    else {
        return ZITI_KEY_SPEC_UNSUPPORTED;
    }

    CATCH(mbed) {
        return ZITI_KEY_INVALID;
    }

    return ZITI_OK;
}

#if _WIN32
int prep_ca_win(mbedtls_x509_crt* my_ca_chain) {
    HCERTSTORE       hCertStore;
    PCCERT_CONTEXT   pCertContext = NULL;

    if (!(hCertStore = CertOpenSystemStore(0, "ROOT")))
    {
        printf("The first system store did not open.");
        return -1;
    }
    while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) {
        mbedtls_x509_crt_parse(my_ca_chain, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
    }
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);
    return 0;
}
#endif

int tls_context_init(nf_config *config, nf_tls_context *tls) {
    PREPF(mbed, fmt_mbederr);
    mbedtls_ssl_config_init(&tls->config);
    mbedtls_ssl_conf_dbg(&tls->config, tls_debug, stdout);
    mbedtls_ssl_config_defaults( &tls->config,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT );
    mbedtls_ssl_conf_authmode( &tls->config, MBEDTLS_SSL_VERIFY_REQUIRED );
    mbedtls_x509_crt_init( &tls->cacert );
    mbedtls_x509_crt_init(&tls->cert);
    mbedtls_pk_init(&tls->key);
    mbedtls_ctr_drbg_init( &tls->ctr_drbg );
    mbedtls_entropy_init( &tls->entropy );

    // load key
    load_key(&tls->key, config->key);

    // load cert
    if (strncmp("file:", config->key, 5) == 0) {
        // load file
        //TRY(mbed, mbedtls_x509_crt_parse_file(&TLS_GLOBAL.cert, config->cert));
    } else if (strncmp("pem:", config->cert, 4) == 0) {
        // load inline PEM
        size_t certlen = strlen(config->cert) - 4;
        TRY(mbed, mbedtls_x509_crt_parse(&tls->cert, config->cert + 4, certlen + 1));
    }

    TRY(mbed, mbedtls_ssl_conf_own_cert(&tls->config, &tls->cert, &tls->key));

#if WIN32
    prep_ca_win(&tls->cacert);
#else
    // look for default CAs in conventional locations; load first one that is found.
    int i;
    for (i = 0; i < NUM_CAFILES; i++) {
        ZITI_LOG(DEBUG, "checking root CA path %s", caFiles[i]);
        if (access(caFiles[i], R_OK) != -1) {
            ZITI_LOG(INFO, "found root CA path %s", caFiles[i]);
            TRY(mbed, mbedtls_x509_crt_parse_file(&tls->cacert, caFiles[i]));
            break;
        }
    }

    if (i == NUM_CAFILES) {
        int caFiles_strlen = 0;
        for (i = 0; i < NUM_CAFILES; i++) {
            caFiles_strlen += strlen(caFiles[i]) + strlen(", ");
        }
        char *caFiles_str = (char *)malloc(caFiles_strlen * sizeof(char));
        for (i = 0; i < NUM_CAFILES; i++) {
            (void)strcat(caFiles_str, caFiles[i]);
            if (i < NUM_CAFILES-1) {
                (void)strcat(caFiles_str, ", ");
            }
        }
        ZITI_LOG(WARN, "default root CA store not found. looked in %s", caFiles_str);
        free(caFiles_str);
    }
#endif

    // load ca from nf config if present
    if (config->ca != NULL) {
        if (strncmp("file:", config->ca, 5) == 0) {
            // load file
            char* path = config->ca + strlen("file://");
            TRY(mbed, mbedtls_x509_crt_parse_file(&tls->cacert, path));
        }
        else if (strncmp("pem:", config->ca, 4) == 0) {
            // load inline PEM
            size_t calen = strlen(config->ca) - 4;
            TRY(mbed, mbedtls_x509_crt_parse(&tls->cacert, config->ca + 4, calen + 1));
        }
    }

    mbedtls_ssl_conf_ca_chain(&tls->config, &tls->cacert, NULL);

    unsigned char* seed = (unsigned char *) "this is entropy seed";
    TRY(mbed, mbedtls_ctr_drbg_seed( &tls->ctr_drbg, mbedtls_entropy_func, &tls->entropy,
                                     seed, strlen(seed)));
    mbedtls_ssl_conf_rng(&tls->config, mbedtls_ctr_drbg_random, &tls->ctr_drbg);

    CATCH(mbed) {
        return -1;
    }

    return 0;
}

int tls_context_free(nf_tls_context *tls) {
    mbedtls_x509_crt_free(&tls->cacert);
    mbedtls_x509_crt_free(&tls->cert);
    mbedtls_pk_free(&tls->key);
    mbedtls_ctr_drbg_free(&tls->ctr_drbg);
    mbedtls_entropy_free(&tls->entropy);
    mbedtls_ssl_config_free(&tls->config);
    return 0;
}