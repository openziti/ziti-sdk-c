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


#include <stdlib.h>
#include <string.h>

#include <ziti/ziti.h>
#include <uv.h>
#include "utils.h"
#include "zt_internal.h"
#include "ziti_enroll.h"
#include <http_parser.h>


#include <mbedtls/ssl.h>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#include "mbedtls/md.h"
#include <utils.h>

#define MJSON_API_ONLY
#include <mjson.h>

#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#elif _WIN32
#define MAXPATHLEN 260
#else
#define MAXPATHLEN 4096
#endif
#endif

#if _WIN32
#define strncasecmp _strnicmp
#endif




#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define OID_PKCS7_DATA OID_PKCS7 "\x02"
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x01"

int extract_well_known_certs(char *base64_encoded_pkcs7, void *req) {

    struct ziti_enroll_req *enroll_req = req;
    size_t der_len;
    unsigned char *p;
    unsigned char *end;
    mbedtls_x509_crt *cp;
    mbedtls_x509_crt certs={0};
    unsigned char *cert_buf;

    int rc = mbedtls_base64_decode( NULL, 0, &der_len, base64_encoded_pkcs7, strlen(base64_encoded_pkcs7)); // determine necessary buffer size
    char *base64_decoded_pkcs7 = calloc(1, der_len + 1);
    rc = mbedtls_base64_decode( base64_decoded_pkcs7, der_len, &der_len, base64_encoded_pkcs7, strlen(base64_encoded_pkcs7));

    unsigned char *der = (unsigned char*)base64_decoded_pkcs7;

    p = der;
    end = der + der_len;
    size_t len;

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    mbedtls_asn1_buf oid;
    oid.p = p;
    oid.len = len;
    if (!MBEDTLS_OID_CMP(OID_PKCS7_SIGNED_DATA, &oid)) {
        ZITI_LOG(ERROR, "invalid pkcs7 signed data");
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }
    p += len;

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    int ver;
    if( ( rc = mbedtls_asn1_get_int(&p, end, &ver) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    oid.p = p;
    oid.len = len;
    if (!MBEDTLS_OID_CMP(OID_PKCS7_DATA, &oid)) {
        ZITI_LOG(ERROR, "invalid pkcs7 data");
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }
    p += len;

    if( ( rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) ) != 0 ) {
        ZITI_LOG(ERROR, "ASN.1 parsing error: %d", rc);
        return ZITI_PKCS7_ASN1_PARSING_FAILED;
    }

    cert_buf = p;

    do {

        size_t cert_len;
        unsigned char *cbp = cert_buf;
        rc = mbedtls_asn1_get_tag(&cbp, end, &cert_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (rc != 0) break;
        cert_len += (cbp - cert_buf);
        rc = mbedtls_x509_crt_parse(&certs, cert_buf, cert_len);
        cert_buf += cert_len;

    } while (rc == 0);

    cp = &certs;
    struct wellknown_cert *last_wc = NULL;

    do {

        size_t len;
        mbedtls_base64_encode( NULL, 0, &len, cp->raw.p, cp->raw.len );  // determine size of buffer we need to allocate

        struct wellknown_cert *wc = calloc(1, sizeof(struct wellknown_cert));
        wc->cert = calloc(1, len + 1);

        size_t encode_len;
        mbedtls_base64_encode( wc->cert, len, &encode_len, cp->raw.p, cp->raw.len );

        if (NULL == last_wc) {
            LIST_INSERT_HEAD(&enroll_req->ecfg->wk_certs, wc, _next);
        } else {
            LIST_INSERT_AFTER(last_wc, wc, _next);
        }

        ZITI_LOG(DEBUG, "cert is: \n%s\n", wc->cert);

        last_wc = wc;

        char dn[1024];
        int dn_len = mbedtls_x509_dn_gets(dn, sizeof(dn), &cp->subject);
        ZITI_LOG(DEBUG, "subj: %.*s", dn_len, dn);
        dn_len = mbedtls_x509_dn_gets(dn, sizeof(dn), &cp->issuer);
        ZITI_LOG(DEBUG, "issr: %.*s", dn_len, dn);
        cp = cp->next;

    } while(cp != NULL);

    return ZITI_OK;
}


