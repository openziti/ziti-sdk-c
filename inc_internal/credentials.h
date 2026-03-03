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

#pragma once

#ifndef ZITI_SDK_CREDENTIALS_H
#define ZITI_SDK_CREDENTIALS_H

#include <tlsuv/tls_engine.h>
#include <stc/cstr.h>

#include <ziti/errors.h>
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

struct tls_credentials {
    tlsuv_private_key_t key;
    tlsuv_certificate_t cert;
};

typedef struct ziti_credential_s {
    ziti_credential_type type;
    uint64_t expiration;
    bool persistent;
    union {
        // identity key/cert
        struct tls_credentials x509;
        // external JWT
        zt_jwt jwt;
        // legacy session
        ziti_session session;
    };
} ziti_credential_t;

extern void ziti_credential_drop(ziti_credential_t *cred);

extern int ziti_credential_from_jwt(const char *jwt, ziti_credential_t **cred);

#ifdef __cplusplus
}
#endif

#endif // ZITI_SDK_CREDENTIALS_H
