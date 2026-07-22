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

//
//

#pragma once

#ifndef ZITI_SDK_CREDENTIALS_H
#define ZITI_SDK_CREDENTIALS_H

#include <tlsuv/tls_engine.h>

#include "internal_model.h"
#include "utils.h"
#include "jwt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZITI_CRED_TYPE_INVALID = 0,
    ZITI_CRED_TYPE_X509 = 1,
    ZITI_CRED_TYPE_JWT = 2,
    ZITI_CRED_LEGACY_SESSION = 3,
} ziti_credential_type;

typedef struct tls_credentials {
    tlsuv_private_key_t key;
    tlsuv_certificate_t cert;
} zt_x509;

typedef struct ziti_credential_s {
    ziti_credential_type type;
    uint64_t expiration;
    bool persistent;
    union {
        // identity key/cert
        zt_x509 x509;
        // JWT
        zt_jwt jwt;
        // legacy session
        struct {
            cstr id;
            cstr token;
        } session;
    };
} ziti_credential_t;

extern void zt_x509_drop(zt_x509 *x509);
extern void zt_credential_drop(ziti_credential_t *cred);

extern int zt_credential_from_jwt(const char *jwt, ziti_credential_t *cred);
extern int zt_credential_from_legacy(ziti_api_session *session, ziti_credential_t *cred);
extern int zt_credential_from_x509(tlsuv_private_key_t key, tlsuv_certificate_t cert, ziti_credential_t *cred);

int load_tls(ziti_config *cfg, tls_context **tls, struct tls_credentials *creds);


#ifdef __cplusplus
}
#endif

#endif // ZITI_SDK_CREDENTIALS_H
