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

#include <catch2/catch_all.hpp>
#include "crypto.h"

#include <sodium/randombytes.h>

struct e2ee_deleter {
    void operator()(e2ee_t *e) const {
        e->free(e);
    }
};

TEST_CASE("e2ee", "[crypto]") {
    auto e2ee = GENERATE(E2EE_NONE, E2EE_DEFAULT);
    INFO("Testing e2ee_impl_t: " << e2ee);
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee));

    auto alice_pub = alice->pub(alice.get());
    auto bob_pub = bob->pub(bob.get());

    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, true) == 0);
    REQUIRE(bob->init(bob.get(), alice_pub.key, alice_pub.key_len, false) == 0);

    uint8_t alice_header[E2EE_MAX_HEADER_LEN];
    uint8_t bob_header[E2EE_MAX_HEADER_LEN];
    auto alice_header_len = alice->get_header(alice.get(), alice_header);
    auto bob_header_len = bob->get_header(bob.get(), bob_header);
    REQUIRE(alice_header_len >= 0);
    REQUIRE(bob_header_len >= 0);

    uint8_t out[1024];
    if (alice_header_len > 0) {
        REQUIRE(bob->decrypt(bob.get(), alice_header, alice_header_len, out, sizeof(out)) == 0);
    }
    if (bob_header_len > 0) {
        REQUIRE(alice->decrypt(alice.get(), bob_header, bob_header_len, out, sizeof(out)) == 0);
    }

    for (auto test_case: { std::make_pair(alice.get(), bob.get()), std::make_pair(bob.get(), alice.get()) }) {
        auto sender = test_case.first;
        auto receiver = test_case.second;
        INFO("Testing: " << ( bob.get() == sender ? "Bob" : "Alice") << " -> " << (bob.get() == receiver ? "Bob" : "Alice"));

        char plaintext[1024];
        randombytes_buf(plaintext, sizeof(plaintext));

        uint8_t ciphertext[1024 + 256];
        auto ciphertext_len = sender->encrypt(sender, (uint8_t*)plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
        REQUIRE(ciphertext_len > 0);
        char plaintext_recv[1024];
        auto plaintext_recv_len = receiver->decrypt(receiver, ciphertext, ciphertext_len, (uint8_t*)plaintext_recv, sizeof(plaintext_recv));
        REQUIRE(plaintext_recv_len == sizeof(plaintext));
        REQUIRE(memcmp(plaintext, plaintext_recv, sizeof(plaintext)) == 0);
    }
}