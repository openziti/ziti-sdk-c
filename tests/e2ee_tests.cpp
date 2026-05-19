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
    auto e2ee = GENERATE(ziti_crypto_none, ziti_crypto_libsodium, ziti_crypto_aes_gcm);
    WHEN("e2ee_impl_t: " << e2ee_method_id(e2ee)) {
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

        for (int i = 0; i < 10; i++) {
            for (auto test_case : {std::make_pair(alice.get(), bob.get()), std::make_pair(bob.get(), alice.get())}) {
                auto sender = test_case.first;
                auto receiver = test_case.second;
                INFO("Testing: " << (bob.get() == sender ? "Bob" : "Alice") << " -> " << (bob.get() == receiver ? "Bob" : "Alice") << "(Round " << i << ")");

                char plaintext[1024];
                randombytes_buf(plaintext, sizeof(plaintext));

                uint8_t ciphertext[1024 + 256];
                auto ciphertext_len = sender->encrypt(sender, (uint8_t *)plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
                REQUIRE(ciphertext_len > 0);
                char plaintext_recv[1024];
                auto plaintext_recv_len = receiver->decrypt(receiver, ciphertext, ciphertext_len, (uint8_t *)plaintext_recv, sizeof(plaintext_recv));
                REQUIRE(plaintext_recv_len == sizeof(plaintext));
                REQUIRE(memcmp(plaintext, plaintext_recv, sizeof(plaintext)) == 0);
            }
        }
    }
}

TEST_CASE("e2ee libsodium init rejects wrong peer key length", "[crypto]") {
    auto e = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    uint8_t too_short[crypto_kx_PUBLICKEYBYTES - 1] = {0};
    uint8_t too_long[crypto_kx_PUBLICKEYBYTES + 1] = {0};

    REQUIRE(e->init(e.get(), too_short, sizeof(too_short), false) == -1);
    REQUIRE(e->init(e.get(), too_long, sizeof(too_long), false) == -1);
    REQUIRE(e->init(e.get(), nullptr, 0, false) == -1);
}

TEST_CASE("e2ee libsodium init is one-shot", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto bob_pub = bob->pub(bob.get());

    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, false) == 0);
    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, false) == -1);
}

TEST_CASE("e2ee libsodium get_header is one-shot", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto bob_pub = bob->pub(bob.get());
    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, false) == 0);

    uint8_t header[E2EE_MAX_HEADER_LEN];
    REQUIRE(alice->get_header(alice.get(), header) > 0);
    REQUIRE(alice->get_header(alice.get(), header) == -1);
}

TEST_CASE("e2ee libsodium clone is independent of parent", "[crypto]") {
    // Models the bind.c listener pattern: a parent keypair is cloned per
    // accepted connection, and init() on the clone must not consume the
    // parent's secret key.
    auto listener = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto listener_pub = listener->pub(listener.get());
    std::vector<uint8_t> pub_snapshot(listener_pub.key, listener_pub.key + listener_pub.key_len);

    auto peer1 = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto peer1_pub = peer1->pub(peer1.get());

    auto clone1 = std::unique_ptr<e2ee_t, e2ee_deleter>(listener->clone(listener.get()));
    REQUIRE(clone1->init(clone1.get(), peer1_pub.key, peer1_pub.key_len, true) == 0);

    auto listener_pub_after = listener->pub(listener.get());
    REQUIRE(listener_pub_after.key_len == pub_snapshot.size());
    REQUIRE(memcmp(listener_pub_after.key, pub_snapshot.data(), pub_snapshot.size()) == 0);

    // listener still usable: second clone+init succeeds against a fresh peer
    auto peer2 = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto peer2_pub = peer2->pub(peer2.get());
    auto clone2 = std::unique_ptr<e2ee_t, e2ee_deleter>(listener->clone(listener.get()));
    REQUIRE(clone2->init(clone2.get(), peer2_pub.key, peer2_pub.key_len, true) == 0);
}

TEST_CASE("e2ee libsodium decrypt retries after partial header", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium));
    auto alice_pub = alice->pub(alice.get());
    auto bob_pub = bob->pub(bob.get());
    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, true) == 0);
    REQUIRE(bob->init(bob.get(), alice_pub.key, alice_pub.key_len, false) == 0);

    uint8_t header[E2EE_MAX_HEADER_LEN];
    auto header_len = alice->get_header(alice.get(), header);
    REQUIRE(header_len > 0);

    uint8_t out[1024];
    // truncated header must fail without consuming the receiver's header state
    REQUIRE(bob->decrypt(bob.get(), header, (size_t)header_len - 1, out, sizeof(out)) == -1);
    // full header on retry must succeed
    REQUIRE(bob->decrypt(bob.get(), header, (size_t)header_len, out, sizeof(out)) == 0);

    // and the subsequent ciphertext round-trip still works
    uint8_t plaintext[64];
    randombytes_buf(plaintext, sizeof(plaintext));
    uint8_t ciphertext[sizeof(plaintext) + E2EE_MAX_MSG_OVERHEAD];
    auto ct_len = alice->encrypt(alice.get(), plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
    REQUIRE(ct_len > 0);
    auto pt_len = bob->decrypt(bob.get(), ciphertext, ct_len, out, sizeof(out));
    REQUIRE(pt_len == sizeof(plaintext));
    REQUIRE(memcmp(out, plaintext, sizeof(plaintext)) == 0);
}
