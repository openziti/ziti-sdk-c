/*
Copyright (c) 2020 Netfoundry, Inc.

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

#include <cstring>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <utils.h>
#include "catch2/catch.hpp"
#include "zt_internal.h"
#include "ziti_enroll.h"


extern "C" {
int extract_well_known_certs(char *base64_encoded_pkcs7, void *req);
}


char *pkcs7_bundle =
        "MIIL8QYJKoZIhvcNAQcCoIIL4jCCC94CAQExADALBgkqhkiG9w0BBwGgggvEMIIF\n"
        "3zCCA8egAwIBAgIQBgjdXUgQ+nYu9WqjujdxCDANBgkqhkiG9w0BAQsFADB5MQsw\n"
        "CQYDVQQGEwJVUzESMBAGA1UEBxMJQ2hhcmxvdHRlMRMwEQYDVQQKEwpOZXRmb3Vu\n"
        "ZHJ5MRAwDgYDVQQLEwdBRFYtREVWMS8wLQYDVQQDEyZOZXRmb3VuZHJ5LCBJbmMu\n"
        "IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xOTA5MDMxODMzNThaFw0yMDA5MDIx\n"
        "ODM0NThaMHkxCzAJBgNVBAYTAlVTMRIwEAYDVQQHEwlDaGFybG90dGUxEzARBgNV\n"
        "BAoTCk5ldGZvdW5kcnkxEDAOBgNVBAsTB0FEVi1ERVYxLzAtBgNVBAMTJk5ldGZv\n"
        "dW5kcnksIEluYy4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0B\n"
        "AQEFAAOCAg8AMIICCgKCAgEAsve8aW8cqZivN5kUtppI0kmNpImpS3Ypc/l48PTd\n"
        "jH46Eetbdzl98NjdYXf/InYK0f7JO8/oKm+BhOssbkhr6TPdzywfl6RuQqpcX8p1\n"
        "7Zs1gTuE4qc7+8VLCAPMGrO7qb6N03fh/baLUhMurGeu2Xho2OhdyiJVcQhEOB0K\n"
        "oywKR7B/GqKc4GnKbHuvVog56b717ltkg7NQjmAiwmOPAng8+QcmJxeJsK5+7zNv\n"
        "kppxSIzEE/Nk0n55VIc0CoQdx323eXQbyOH9Oo8SdVPiiurvs40pEmgUGo/pd/5y\n"
        "ZU+ki67Y27CNuO32YdXro6zsIC3ueblyc7uIKc3OrnkEoMUJNsPN5ZLfMdW053kI\n"
        "hiibJrFCG0NEze8yYakHBsZ3DfrmN+fzq5IHBI4K277/hOknJvHIHaXqt4oPJVps\n"
        "IFtt8j8BlZUW29KZKLlzlQ1uGmD1Eixwk63bqaExHQ9aSXMQEbfHre79zUdPDoNM\n"
        "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";

char *cert1 = "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";
char *cert2 = "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";

#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define OID_PKCS7_DATA OID_PKCS7 "\x02"
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x01"

TEST_CASE("parse pkcs7") {
    int rc;
    PREP(p7);

    struct enroll_cfg_s *ecfg = NULL;
    ecfg = (struct enroll_cfg_s *)calloc(1, sizeof(enroll_cfg));

    struct nf_enroll_req *enroll_req = (struct nf_enroll_req *)calloc(1, sizeof(struct nf_enroll_req));
    enroll_req->ecfg = ecfg;

    if( ( rc = extract_well_known_certs( pkcs7_bundle, enroll_req ) ) != 0 ) {
        FAIL("invalid");
    }

    struct wellknown_cert *wc;
    char *ca = NULL;
    char *pem_ptr = NULL;
    int i = 0;

    LIST_FOREACH (wc, &enroll_req->ecfg->wk_certs, _next) {

        if (i == 0) {
            REQUIRE_THAT(wc->cert, Catch::Matchers::Equals(cert1));
        } else {
            REQUIRE_THAT(wc->cert, Catch::Matchers::Equals(cert2));
        }
        i++;
    }

    CATCH(p7);

}