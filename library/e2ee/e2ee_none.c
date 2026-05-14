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


#include <string.h>

#include "crypto.h"

/// none e2ee_t implementation
static e2ee_pub_t none_pub(struct e2ee *e2ee) {
    return (e2ee_pub_t){ .key = NULL, .key_len = 0 };
}

static int none_init(struct e2ee *e2ee, const uint8_t *peer_key, size_t peer_key_len, bool server) {
    return 0;
}

static ssize_t none_encrypt(e2ee_t *e2ee, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t ciphertext_len) {
    if (ciphertext_len < plaintext_len) {
        return -1;
    }
    memcpy(ciphertext, plaintext, plaintext_len);
    return (ssize_t)plaintext_len;
}

static ssize_t none_decrypt(e2ee_t *e2ee, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext, size_t plaintext_len) {
    if (plaintext_len < ciphertext_len) {
        return -1;
    }
    memcpy(plaintext, ciphertext, ciphertext_len);
    return (ssize_t)ciphertext_len;
}

static ssize_t none_get_header(struct e2ee *e2ee, uint8_t header[E2EE_MAX_HEADER_LEN]) {
    memset(header, 0, E2EE_MAX_HEADER_LEN);
    return 0;
}

static e2ee_t* none_clone(e2ee_t *e2ee) {
    return e2ee;
}

static void none_free(e2ee_t *e2ee) {}

// singleton instance of none e2ee implementation
static e2ee_t none_e2ee_impl = {
    .clone = none_clone,
    .pub = none_pub,
    .init = none_init,
    .get_header = none_get_header,
    .encrypt = none_encrypt,
    .decrypt = none_decrypt,
    .free = none_free,
};

e2ee_t* new_none_e2ee() {
    return &none_e2ee_impl;
}
