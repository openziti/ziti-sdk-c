// Copyright (c) 2023.  NetFoundry Inc.
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

#include <sodium.h>
#include "zt_internal.h"

int init_key_pair(struct key_pair *kp) {
    return crypto_kx_keypair(kp->pk, kp->sk);
}

int init_crypto(struct key_exchange *key_ex, struct key_pair *kp, const uint8_t *peer_key, bool server) {
    free(key_ex->rx);
    free(key_ex->tx);

    key_ex->rx = calloc(1, crypto_secretstream_xchacha20poly1305_keybytes());
    key_ex->tx = calloc(1, crypto_secretstream_xchacha20poly1305_keybytes());
    if (server) {
        return crypto_kx_server_session_keys(key_ex->rx, key_ex->tx, kp->pk, kp->sk, peer_key);
    } else {
        return crypto_kx_client_session_keys(key_ex->rx, key_ex->tx, kp->pk, kp->sk, peer_key);
    }
}

void free_key_exchange(struct key_exchange *key_ex) {
    FREE(key_ex->rx);
    FREE(key_ex->tx);
}