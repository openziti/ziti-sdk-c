// Copyright (c) 2026.  NetFoundry Inc
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.

//
//

#include "jwt.h"
#include "credentials.h"
#include <ziti/errors.h>

#include <sodium/utils.h>

void zt_jwt_drop(zt_jwt *jwt) {
    if (jwt == NULL) {
        return;
    }
    cstr_drop(&jwt->issuer);
    cstr_drop(&jwt->encoded);
    json_object_put(jwt->claims);
    json_object_put(jwt->header);
}

void zt_jwt_free(zt_jwt *jwt) {
    if (jwt == NULL) {
        return;
    }
    zt_jwt_drop(jwt);
    free(jwt);
}


int zt_jwt_parse(const char *jwt_str, zt_jwt *jwt) {
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

    // all good, populate jwt struct
    cstr_assign(&jwt->issuer, json_object_get_string(iss));
    jwt->expiration = exp ? json_object_get_int64(exp) : 0;
    jwt->claims = json_object_get(payload);
    jwt->header = json_object_get(header);
    cstr_assign(&jwt->encoded, jwt_str);
    result = 0;

error:
    json_object_put(header);
    json_object_put(payload);
    free(buf);
    return result;
}

int ziti_credential_from_jwt(const char *jwt, ziti_credential_t **cred) {
    assert(jwt);

    NEWP(c, ziti_credential_t);
    if (!c) return ZITI_ALLOC_FAILED;

    if (zt_jwt_parse(jwt, &c->jwt) != 0) {
        free(c);
        *cred = NULL;
        return ZITI_JWT_INVALID;
    }
    c->type = ZITI_CRED_TYPE_JWT;
    *cred = c;
    return 0;
}

void ziti_credential_drop(ziti_credential_t *cred) {
    if (cred == NULL) {
        return;
    }
    switch (cred->type) {
    case ZITI_CRED_TYPE_X509:
        cred->x509.key->free(cred->x509.key);
        cred->x509.cert->free(cred->x509.cert);
        break;
    case ZITI_CRED_TYPE_JWT:
        zt_jwt_drop(&cred->jwt);
        break;
    default:
        break;
    }
    free(cred);
}
