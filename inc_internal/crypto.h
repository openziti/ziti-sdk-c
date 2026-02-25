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

#ifndef ZITI_SDK_CRYPTO_H
#define ZITI_SDK_CRYPTO_H

#include <sodium.h>
#include <stdbool.h>

struct key_pair {
    uint8_t sk[crypto_kx_SECRETKEYBYTES];
    uint8_t pk[crypto_kx_PUBLICKEYBYTES];
};

struct key_exchange {
    uint8_t *rx;
    uint8_t *tx;
};

int init_key_pair(struct key_pair *kp);

int init_crypto(struct key_exchange *key_ex, struct key_pair *kp, const uint8_t *peer_key, bool server);

void free_key_exchange(struct key_exchange *key_ex);
#endif // ZITI_SDK_CRYPTO_H
