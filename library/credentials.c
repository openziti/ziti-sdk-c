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

#include "jwt.h"
#include "credentials.h"
#include <ziti/errors.h>

#include <sodium/utils.h>

#ifdef _WIN32
    #define timegm _mkgmtime
#endif

void zt_jwt_drop(zt_jwt *jwt) {
    if (jwt == NULL) {
        return;
    }
    cstr_drop(&jwt->issuer);
    jwt->issuer = cstr_init();
    cstr_drop(&jwt->encoded);
    jwt->encoded = cstr_init();
    json_object_put(jwt->claims);
    json_object_put(jwt->header);
    jwt->claims = NULL;
    jwt->header = NULL;
    jwt->expiration = 0;
}

void zt_jwt_free(zt_jwt *jwt) {
    if (jwt == NULL) {
        return;
    }
    zt_jwt_drop(jwt);
    free(jwt);
}


int zt_jwt_parse(const char *jwt_str, zt_jwt *jwt) {
    assert(jwt);
    if (jwt_str == NULL || *jwt_str == '\0') {
        return -1;
    }

    int result = -1;

    size_t len;
    const char *b64_end;
    json_object *header = NULL;
    json_object *payload = NULL;
    json_object *iss = NULL,  *exp = NULL;
    enum json_tokener_error json_err;

    // buf holds decoded data
    size_t jwt_len = strlen(jwt_str);
    char *buf = (char*)calloc(1, jwt_len + 1);
    if (!buf) {
        goto error;
    }

    if (sodium_base642bin((uint8_t *)buf, jwt_len, jwt_str, jwt_len, NULL,
                          &len, &b64_end, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
        *b64_end != '.') {
        ZITI_LOG(TRACE, "failed to decode JWT header");
        goto error;
    }
    header = json_tokener_parse_verbose(buf, &json_err);
    if (!header) {
        goto error;
    }

    if (sodium_base642bin((uint8_t *)buf, jwt_len, (b64_end + 1), jwt_len - (b64_end + 1 - jwt_str),
                          NULL,
                          &len, &b64_end, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
        *b64_end != '.') {
        ZITI_LOG(TRACE, "failed to decode JWT claims");
        goto error;
    }
    payload = json_tokener_parse_verbose(buf, &json_err);
    if (!payload) {
        ZITI_LOG(TRACE, "failed to parse JWT claims: %s", json_tokener_error_desc(json_err));
        goto error;
    }

    iss = json_object_object_get(payload, "iss");
    if (!iss || !json_object_is_type(iss, json_type_string)) {
        goto error;
    }

    exp = json_object_object_get(payload, "exp");
    if (exp && !json_object_is_type(exp, json_type_int)) {
        goto error;
    }

    // all good, clear and populate jwt struct
    zt_jwt_drop(jwt);
    jwt->encoded = cstr_from(jwt_str);
    jwt->issuer = cstr_from(json_object_get_string(iss));
    jwt->expiration = exp ? json_object_get_int64(exp) : 0;
    jwt->claims = json_object_get(payload);
    jwt->header = json_object_get(header);
    result = 0;

error:
    json_object_put(header);
    json_object_put(payload);
    free(buf);
    return result;
}

int zt_credential_from_jwt(const char *jwt, ziti_credential_t *cred) {
    assert(jwt);
    assert(cred);

    memset(cred, 0, sizeof(ziti_credential_t));
    if (zt_jwt_parse(jwt, &cred->jwt) != 0) {
        return ZITI_JWT_INVALID;
    }
    cred->type = ZITI_CRED_TYPE_JWT;
    return 0;
}

int zt_credential_from_legacy(ziti_api_session *session, ziti_credential_t *cred) {
    assert(cred != NULL);
    assert(session != NULL);
    memset(cred, 0, sizeof(ziti_credential_t));
    cred->type = ZITI_CRED_LEGACY_SESSION;
    cred->expiration = session->expires.tv_sec;
    cred->session.token = cstr_from(session->token);
    cred->session.id = cstr_from(session->id);

    return 0;
}

int zt_credential_from_x509(tlsuv_private_key_t key, tlsuv_certificate_t cert, ziti_credential_t *cred) {
    assert(key != NULL);
    assert(cert != NULL);
    assert(cred != NULL);
    memset(cred, 0, sizeof(ziti_credential_t));
    cred->type = ZITI_CRED_TYPE_X509;

    struct tm exp;
    if (cert->get_expiration(cert, &exp) == 0) {
        time_t e = timegm(&exp);
        cred->expiration = e;
    }
    cred->x509.cert = cert;
    cred->x509.key = key;

    return 0;
}

void zt_credential_drop(ziti_credential_t *cred) {
    if (cred == NULL) {
        return;
    }
    switch (cred->type) {
    case ZITI_CRED_TYPE_X509:
        zt_x509_drop(&cred->x509);
        break;
    case ZITI_CRED_TYPE_JWT:
        zt_jwt_drop(&cred->jwt);
        break;
    case ZITI_CRED_LEGACY_SESSION:
        cstr_drop(&cred->session.token);
        cstr_drop(&cred->session.id);
        break;
    default:
        break;
    }
}

void zt_x509_drop(zt_x509 *x509) {
    if (x509->cert) x509->cert->free(x509->cert);
    if (x509->key) x509->key->free(x509->key);
    memset(x509, 0, sizeof(*x509));
}
