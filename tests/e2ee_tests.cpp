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
#include "ziti/ziti_log.h"

#include <sodium/randombytes.h>

struct e2ee_deleter {
    void operator()(e2ee_t *e) const {
        e->free(e);
    }
};

static void test_e2ee(e2ee_t *alice, e2ee_t *bob) {
    auto alice_pub = alice->pub(alice);
    auto bob_pub = bob->pub(bob);

    REQUIRE(alice->init(alice, bob_pub.key, bob_pub.key_len, true) == 0);
    REQUIRE(bob->init(bob, alice_pub.key, alice_pub.key_len, false) == 0);

    uint8_t alice_header[E2EE_MAX_HEADER_LEN];
    uint8_t bob_header[E2EE_MAX_HEADER_LEN];
    auto alice_header_len = alice->get_header(alice, alice_header);
    auto bob_header_len = bob->get_header(bob, bob_header);
    REQUIRE(alice_header_len >= 0);
    REQUIRE(bob_header_len >= 0);

    uint8_t out[1024];
    if (alice_header_len > 0) {
        REQUIRE(bob->decrypt(bob, alice_header, alice_header_len, out, sizeof(out)) == 0);
    }
    if (bob_header_len > 0) {
        REQUIRE(alice->decrypt(alice, bob_header, bob_header_len, out, sizeof(out)) == 0);
    }

    for (int i = 0; i < 10; i++) {
        for (auto test_case : {std::make_pair(alice, bob), std::make_pair(bob, alice)}) {
            auto sender = test_case.first;
            auto receiver = test_case.second;
            INFO("Testing: " << (bob == sender ? "Bob" : "Alice") << " -> " << (bob == receiver ? "Bob" : "Alice") << "(Round " << i << ")");

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

TEST_CASE("e2ee", "[crypto]") {
    ziti_log_init(nullptr, 5, nullptr);
    auto e2ee = GENERATE(ziti_crypto_none, ziti_crypto_libsodium, ziti_crypto_aes_gcm);
    WHEN("e2ee_impl_t: " << e2ee_method_id(e2ee)) {
        auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee));
        auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee));

        if (alice == nullptr || bob == nullptr) {
            SKIP("e2ee method " << e2ee_method_id(e2ee) << " not implemented, skipping");
        }

        test_e2ee(alice.get(), bob.get());
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

#if _WIN32
namespace ossl {
#include "../library/e2ee/e2ee_aes_gcm_ossl.c"
}
TEST_CASE("e2ee-ossl-wincrypto-interop", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>((e2ee_t*)ossl::new_aes_gcm_e2ee());
    test_e2ee(alice.get(), bob.get());
}
#endif

#if defined(__APPLE__)
namespace ossl {
#include "../library/e2ee/e2ee_aes_gcm_ossl.c"
}
// the Apple backend derives keys with Security.framework + CommonCrypto, so this is what
// proves it stays wire-compatible with the OpenSSL/BCrypt peers. Both orderings, because
// the two directions use different HKDF info.
TEST_CASE("e2ee-ossl-apple-interop", "[crypto]") {
    ziti_log_init(nullptr, 5, nullptr);

    WHEN("apple is the server") {
        auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm));
        auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>((e2ee_t *)ossl::new_aes_gcm_e2ee());
        test_e2ee(alice.get(), bob.get());
    }

    WHEN("openssl is the server") {
        auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>((e2ee_t *)ossl::new_aes_gcm_e2ee());
        auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm));
        test_e2ee(alice.get(), bob.get());

        // the ossl backend's own double-init guard -- the [crypto] "init is one-shot"
        // case above covers whichever backend create_e2ee() returns, which is the
        // Apple one here.
        auto bob_pub = bob->pub(bob.get());
        REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, true) == -1);
    }
}
// the ossl backend above defines the same tuning macros with different values
#undef AES_GCM_TAG_LEN
#undef AES_GCM_NONCE_LEN
#undef AES_GCM_NONCE_PREFIX_LEN
#undef AES_GCM_KEY_LEN
#undef P256_PUB_KEY_LEN
namespace apple {
#include "../library/e2ee/e2ee_aes_gcm_apple.c"
}
// An empty payload reaches the CryptoKit shim as (NULL, 0), a different path through the
// Swift bridging than a non-empty buffer -- and one that traps inside CryptoKit if the null
// base pointer is passed straight through, where the CommonCrypto one-shot accepted it.
// Note the receiving side rejects a tag-only frame (ciphertext_len <= AES_GCM_TAG_LEN); that
// guard is pre-existing and identical in the OpenSSL backend, so this only pins encrypt.
TEST_CASE("e2ee-apple-aes-gcm-empty-payload", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm));
    auto alice_pub = alice->pub(alice.get());
    auto bob_pub = bob->pub(bob.get());
    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, true) == 0);
    REQUIRE(bob->init(bob.get(), alice_pub.key, alice_pub.key_len, false) == 0);

    // must not trap: produces a tag and nothing else
    uint8_t ciphertext[E2EE_MAX_MSG_OVERHEAD];
    auto ct_len = alice->encrypt(alice.get(), nullptr, 0, ciphertext, sizeof(ciphertext));
    REQUIRE(ct_len == 16);

    // and the receive side must not trap on the resulting tag-only frame either
    uint8_t out[16];
    REQUIRE(bob->decrypt(bob.get(), ciphertext, ct_len, out, sizeof(out)) == -1);
}

// RFC 5869 test case 3: SHA-256, zero-length salt and info. The zero-length salt is exactly
// what derive_session_keys() uses, so this pins the CCHmac-based HKDF independently of OpenSSL.
TEST_CASE("e2ee-apple-hkdf-rfc5869", "[crypto]") {
    const uint8_t ikm[22] = {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    const uint8_t expected[42] = {
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
    };
    const uint8_t info[1] = {0};

    uint8_t out[sizeof(expected)];
    REQUIRE(apple::hkdf_sha256(ikm, sizeof(ikm), info, 0, out, sizeof(out)) == 0);
    REQUIRE(memcmp(out, expected, sizeof(expected)) == 0);

    // more than 255 blocks of output is out of range for HKDF
    REQUIRE(apple::hkdf_sha256(ikm, sizeof(ikm), info, 0, out, 255 * 32 + 1) == -1);
}

#endif
