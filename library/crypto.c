// Copyright (c) 2023-2026.  NetFoundry Inc
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

#include <sodium.h>
#include "crypto.h"
#include "utils.h"

extern e2ee_t *new_libsodium_e2ee(void);
extern e2ee_t *new_none_e2ee(void);
extern e2ee_t *new_aes_gcm_e2ee(void);

e2ee_t* create_e2ee(ziti_crypto_method impl) {
    switch (impl) {
    case ziti_crypto_none:
        return new_none_e2ee();
    case ziti_crypto_libsodium:
        return new_libsodium_e2ee();
    case ziti_crypto_aes_gcm:
        return new_aes_gcm_e2ee();
    default:
        return NULL;
    }
}

const char *e2ee_method_id(ziti_crypto_method mode) {
    switch (mode) {
    case ziti_crypto_none:
        return "none";
    case ziti_crypto_libsodium:
        return "libsodium";
    case ziti_crypto_aes_gcm:
        return "aes-gcm";
    default:
        return "invalid";
    }
}

ziti_crypto_method e2ee_method_from_id(const char *id) {
    // this is the default
    if (id == NULL) {
        return ziti_crypto_libsodium;
    }

    if (strcmp(id, "none") == 0) {
        return ziti_crypto_none;
    } else if (strcmp(id, "libsodium") == 0) {
        return ziti_crypto_libsodium;
    } else if (strcmp(id, "aes-gcm") == 0) {
        return ziti_crypto_aes_gcm;
    } else {
        return ziti_crypto_invalid;
    }
}

