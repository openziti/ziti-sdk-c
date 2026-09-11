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
        auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee, false, nullptr, nullptr));
        auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee, false, nullptr, nullptr));

        if (alice == nullptr || bob == nullptr) {
            SKIP("e2ee method " << e2ee_method_id(e2ee) << " not implemented, skipping");
        }

        test_e2ee(alice.get(), bob.get());
    }
}

TEST_CASE("e2ee libsodium init rejects wrong peer key length", "[crypto]") {
    auto e = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    uint8_t too_short[crypto_kx_PUBLICKEYBYTES - 1] = {0};
    uint8_t too_long[crypto_kx_PUBLICKEYBYTES + 1] = {0};

    REQUIRE(e->init(e.get(), too_short, sizeof(too_short), false) == -1);
    REQUIRE(e->init(e.get(), too_long, sizeof(too_long), false) == -1);
    REQUIRE(e->init(e.get(), nullptr, 0, false) == -1);
}

TEST_CASE("e2ee libsodium init is one-shot", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    auto bob_pub = bob->pub(bob.get());

    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, false) == 0);
    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, false) == -1);
}

TEST_CASE("e2ee libsodium get_header is one-shot", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
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
    auto listener = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    auto listener_pub = listener->pub(listener.get());
    std::vector<uint8_t> pub_snapshot(listener_pub.key, listener_pub.key + listener_pub.key_len);

    auto peer1 = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    auto peer1_pub = peer1->pub(peer1.get());

    auto clone1 = std::unique_ptr<e2ee_t, e2ee_deleter>(listener->clone(listener.get()));
    REQUIRE(clone1->init(clone1.get(), peer1_pub.key, peer1_pub.key_len, true) == 0);

    auto listener_pub_after = listener->pub(listener.get());
    REQUIRE(listener_pub_after.key_len == pub_snapshot.size());
    REQUIRE(memcmp(listener_pub_after.key, pub_snapshot.data(), pub_snapshot.size()) == 0);

    // listener still usable: second clone+init succeeds against a fresh peer
    auto peer2 = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    auto peer2_pub = peer2->pub(peer2.get());
    auto clone2 = std::unique_ptr<e2ee_t, e2ee_deleter>(listener->clone(listener.get()));
    REQUIRE(clone2->init(clone2.get(), peer2_pub.key, peer2_pub.key_len, true) == 0);
}

TEST_CASE("e2ee libsodium decrypt retries after partial header", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr, nullptr));
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
        auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm, false, nullptr, nullptr));
        auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>((e2ee_t *)ossl::new_aes_gcm_e2ee());
        test_e2ee(alice.get(), bob.get());
    }

    WHEN("openssl is the server") {
        auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>((e2ee_t *)ossl::new_aes_gcm_e2ee());
        auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm, false, nullptr, nullptr));
        test_e2ee(alice.get(), bob.get());
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
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm, false, nullptr, nullptr));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_aes_gcm, false, nullptr, nullptr));
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

TEST_CASE("e2ee-tls", "[crypto]") {
    ziti_log_init(nullptr, 6, nullptr);
    auto ca = R"(-----BEGIN CERTIFICATE-----
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
jrEaRTDiko6e0ifkFw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
)";

    auto key = R"(-----BEGIN RSA PRIVATE KEY-----
MIIJKAIBAAKCAgEA3y3PkACAfKzwaJCDnf39GnHzfmk6tX2cYWOR/qVTQMOR4koe
RLdAY7I+aiXV9bPXmYQ3/oHXzWsPuFnTqaiD2913BstqWF7oLZfFnhdg5uWoECvD
aLmMyPrMbHym+Eswn/dEL663F3V9ULbxYVn+3qmmW+nA/QcmiflVN8tkktPROc4n
qh+S9Vt5+5qbXsz4/Ys6WKFXpKebJdnxQe5cWa/ScbgJe904vkKTvtJhYJl8gAdd
lmvo+3h/pUohgB8xOujdTZwqBQ2O8DQkd1HvCcFKZ4Cf7BU4HtF6iuA8/VOvgy6V
r387swSTKzb8DxvYQRrXSFlMQj39IJ0z5Q86H0w5a6GyY88ldTFtWhHQUndO6Aay
bcf5+mT69VNC7eCS7q0FrYQt5SWjiK/PgcSXH4WVhpaCC3cwn0CTo3JbXt7mFxPj
eq70NrzLcgR+nnY92jCi3SXrLqggAOAPvUhsNnyRrGS8LJrGXwz28r5Ef4qzkaN7
e2ieBvmVOdoKKUqyM5dEC3X53c3yQRyvNwiA0GxtaN17XqZnSjvqak7xwHQa0lvb
VH4idHIHBqkCOn9mIA3YYtbxhcC3uidQUbSFYRN1DmQU7RK+xkaCJREDFYQw3mqU
s/lsNdnBaiC1VEC+zBo8QZWlJkwM/0W65Q8geCqwkyi38ABDNh7hQ9MHFkECAwEA
AQKCAgAC5v5tv54ar4KEIN8rH//QuH+NrzO8KQcFrwW2v8cawDv5iDRQBQA90XwL
NvqQ4SbZcFO+Fo904w5b6mFRGoIBkPd1v/qMs3i3flfgBIgtb8utzz+F8Tds2PJ4
5Cfq/co9RfQyO6OEoqwOEmL62cIgHYZRUPOH/5L9LxRwLCFqbNrvycfniuxM90ST
p4PhMl29188Jb9koNI4mmQucPOMJp+kNhEQtfTCLoN3WdeYeG2PJjKBtN4l9ppyx
ngqKwtFyn6xx0GNzI7x0Cq9eWpkONJpLvV/XCX0PcBXGVjS9kS2srms56axOn2eb
o6A7tVbmtAbtmUxrCTSb9VU3tRefYiloObewRoQ7a0syZxDZlkJGw1Qfkmuf2JfR
s3aMWNZArjfmwSOkoJYnmpi+T8f9qIHmC4c9TSo/v4OZp+qd9FUitsqYAWFRmf4P
1wErOwHFUEKimACMzTG4xpbsVmC2d++6lXiPWI4nj6fSB763cqfEvS+E4PcCFtyb
49zt3GrumNaPnW+VsgrX2E9ORrTAt87FXY2Pu3hcEhY4bk65kxRdUJ0OsYxQXNaL
aEzRZJGIkq57a+p8TuLauuJGeCEmiOKt2m8wk6OJN+LixI7fGpfdby3aUVEsI0Mg
wjpZ20oBMfBhp8a+fRu9vHQq1VHHwotbGCu09mGigqacgU8/dQKCAQEA4AIQZ9c6
PKhP5P9wzKGBQuTpFVQS7ARf+JQOAAx7DK33c4CiMbYeaNvfXxp1P1yicGNxUYVO
Hk+alUhHXYEVKxYvIwKC4hRs3GbQsPVschkdvsS+/UK42Go5vzAT5jW0W2LEbUGV
fouszi4IWS2N01HD+A28dPBQAewHvZb+9Iffa0yUDxypCniOqHqJlHgborys0dW9
62Bz+Q6XhQg5WBF7IPjZAnYArh6qnHe1khyJjGhDXAZ4e/h4O/JyjhZG4q6or8UH
28S+Mp9r4n2iD2c9PsZGRxmBS/dYBS6ffI+YFkwxOzpRichGnR1GuXtYoLvlnlrJ
LfaCqkv7SNV1XwKCAQEA/w1u/GMm1aW3JjvCFpOS6bB+v1l/NHS3tnnuESM6IfKn
nuz7R+rVtuR+oLF/0L/w2ZTuXaRDODD/jVD2C4qCYP3EaNqOrW3C7dje1AnZMH05
AivnWqQDeSeS4REG2IuBanE91z25X3HLH8JR4ZMorqIu7CZfzn5ZQ0EmZC8lPDtI
JNjGLrdYz6f9CYArFnIChoFxJ719d9ocKy2ke1vXcym+l6SRXXFjK/lTP5BthKuh
hwvuX1bKjlEpv+uRsjHKXMGkecDxEA7h1KqvTMa0zEmbj1y1+xyqUeFwX1mt6Uf9
Hlx75ODvSmexeRqRyoY+KU9c0+DkxHeF52z8irR4XwKCAQEAp7Ij4fkICfzewspQ
AYEuqYuAyozEFZg42HjN+k9dluJtizRTN+/k2A8yK5o9CBArMwPfA25OSvbA/Ny9
QEywMi9LXmQ041bzIBSAStmQM+KFmBjl+ecHRkxPqsctPnwZ5wgLkNc2OSQLW9au
PUSTFg3yLTLrUIfO/YFbUh1GBH3rTgJoHOAR1FroQUxqzpET70JcBkKDCUCN0XeR
CvBbLYj4qnhgzSzV2YPvqW8cqKNgfZJYSv41GGmsaQRZqfEXY//pHJzeAzJISNF8
DHSM7AcXnHUGi5eWae5jII4Eq1U8QAUOHg7Ml98srdYK6jRi5wGDJodEcHpI24BC
QAY89QKCAQATxh3ZsXI8VCm77BwjFfPo7EcXXL/w+C+aFR/w8jM6mI6IUsU0kS9a
i6KJoNlQ/OCWbeaBGhAgFiRp92HsCSQMkwAcRP2U0pKvUAYOmGjfSoYV9gNs0pR2
WywXCPPn7ADvmLH7swxhKvhdkPo6K+eWinpq0prQ7pjLDw0D7WfMoKf6O1g6HPrk
tph2mRo+Fj694OE9/IHyvdU7P8Gl0rwEcLMXHKosfXL74MukfPUQuSG/z5v+hkMT
/5TmDURxdUzEHjs7OUs3PIAjtcv7fthbkkVeOwjc3B8UVA8bRV+nW25zYSY1236R
3TI0OmwdMIU3PLDsuF3kIYQfKiL2OgGvAoIBAAYKVSObuOBqv2Lzq5/wfJKUW8AK
IkOsJTmb/fguYo7avtQ2bslWnSXGFN6hB7OxkHQtGdxE0QZoWMD0GbVmLJNTbG55
WKpd/NMTRPZAe8KAOmajMg9MK/pn8JOmmUn4Wxph8265SMQsJGFdLekEJBHGBjVf
9CKFikvbQkQp+xU/63z993PLF9+caic221pd25PZqZOp54KNBIzFpkvoc/TOmbdX
T4tIPlDfH0g2cxiWT7HCs6xRTfR/tkxhdxABXgChH2HgeK/hiETR4PtxDbbrcx0u
EnoeKpTsvpyAtUBE0hH2l92O9obk6ondws9Vq31hxBTTr2bdAeF0yPqrBVk=
-----END RSA PRIVATE KEY-----
)";
    auto cert = R"(-----BEGIN CERTIFICATE-----
MIIFrjCCA5agAwIBAgIUM1l0g/Czki5vF17O7eYxQj40ahQwDQYJKoZIhvcNAQEL
BQAwbTELMAkGA1UEBhMCVVMxEjAQBgNVBAcTCUNoYXJsb3R0ZTETMBEGA1UEChMK
TmV0Rm91bmRyeTEQMA4GA1UECxMHQURWLURFVjEjMCEGA1UEAxMaaW50ZXJtZWRp
YXRlLWNhLWluc3RhbmNlLTEwHhcNMjYwOTA5MTQ1NzQzWhcNMjcwOTA5MTQ1ODQz
WjA3MQswCQYDVQQGEwJVUzETMBEGA1UEChMKTmV0Rm91bmRyeTETMBEGA1UEAxMK
TGRuaXNrN216RzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAN8tz5AA
gHys8GiQg539/Rpx835pOrV9nGFjkf6lU0DDkeJKHkS3QGOyPmol1fWz15mEN/6B
181rD7hZ06mog9vddwbLalhe6C2XxZ4XYOblqBArw2i5jMj6zGx8pvhLMJ/3RC+u
txd1fVC28WFZ/t6pplvpwP0HJon5VTfLZJLT0TnOJ6ofkvVbefuam17M+P2LOlih
V6SnmyXZ8UHuXFmv0nG4CXvdOL5Ck77SYWCZfIAHXZZr6Pt4f6VKIYAfMTro3U2c
KgUNjvA0JHdR7wnBSmeAn+wVOB7ReorgPP1Tr4Mula9/O7MEkys2/A8b2EEa10hZ
TEI9/SCdM+UPOh9MOWuhsmPPJXUxbVoR0FJ3TugGsm3H+fpk+vVTQu3gku6tBa2E
LeUlo4ivz4HElx+FlYaWggt3MJ9Ak6NyW17e5hcT43qu9Da8y3IEfp52Pdowot0l
6y6oIADgD71IbDZ8kaxkvCyaxl8M9vK+RH+Ks5Gje3tongb5lTnaCilKsjOXRAt1
+d3N8kEcrzcIgNBsbWjde16mZ0o76mpO8cB0GtJb21R+InRyBwapAjp/ZiAN2GLW
8YXAt7onUFG0hWETdQ5kFO0SvsZGgiURAxWEMN5qlLP5bDXZwWogtVRAvswaPEGV
pSZMDP9FuuUPIHgqsJMot/AAQzYe4UPTBxZBAgMBAAGjfDB6MA4GA1UdDwEB/wQE
AwIEsDATBgNVHSUEDDAKBggrBgEFBQcDAjAfBgNVHSMEGDAWgBR1mDnkc8x4aq30
QoKkrZJOkbWxzTAyBgNVHREEKzAphidzcGlmZmU6Ly9xdWlja3N0YXJ0L2lkZW50
aXR5L0xkbmlzazdtekcwDQYJKoZIhvcNAQELBQADggIBAE36EwVVr3G+EED32Dml
3ehW8xr2Nu9z6aTeeFpcL66+ayISKVNBc4Vx6V3DB187meVZdb5iNzqGdJI2G5tt
YLnfrnfMSqZbgIOxnT8m+LHPhMIj/Oa157Au8G2+cUF9Zg9heXPSBy9G98XFKgEz
cHShMD/gdZJwsN3lE+HtHAk1/ywU3Wj52xcGPGuVwPJNBDr9chALuqT1fuLCfJnY
CIcxQMCqJ/46sQXdj/hU56c/M1ZenCS31Eu/gcK7K29Yz/8+rsiWa8japCAt07U0
LL1V7cxPl9Cgz/jHtP1yyAINtnjtozJ/y/rPu1cEuDW1k841ZOviZgLLUSkJO8Jg
taF6UYzY2k7r4QXCB2aTEYmj/PG+bpK05REsubcEFDzkYvymviL+EJ9vEdDsokeV
e3iLLCei9py+Q34TGPD8fLcp9EyA0hIlx6qy9S5I1wMSiS12cD6vdsmPbTDlaCX1
nHfY8Nup4u6NXOBNTCvzXh01iwv25rqRgqPCBuaC8fORgkIC1odO1OD7+f+YnUBM
Br5fRtNrtfVj6CdyFXR4MNC+sscka8/2IoCklqXJUK/7kv8yltMyGhZJWSvS7iDx
Pp9a5IQj/qZkR+X8jArkCO8vbpk1a7/z1Fwnxkve19xpHYiKX/zy4BylMWAWP3nh
uN3aX6cGcaaqgr7LXyxYTWCL
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
jrEaRTDiko6e0ifkFw==
-----END CERTIFICATE-----)";

    auto tls = default_tls_context(nullptr, 0);

    zt_x509 srv_cred{};

    REQUIRE(tls->load_cert(&srv_cred.cert, cert, strlen(cert)) == 0);
    REQUIRE(tls->load_key(&srv_cred.key, key, strlen(key)) == 0);


    auto srv = create_e2ee(ziti_crypto_tls, true, &srv_cred, ca);
    auto clt = create_e2ee(ziti_crypto_tls, false, nullptr, ca);

    auto clt_hello = clt->pub(clt);

    uint8_t srv_header[E2EE_MAX_HEADER_LEN];
    uint8_t clt_header[E2EE_MAX_HEADER_LEN];
    REQUIRE(srv->init(srv, clt_hello.key, clt_hello.key_len, true) == 0);
    auto srv_hello = srv->pub(srv);

    REQUIRE(clt->init(clt, srv_hello.key, srv_hello.key_len, false) == 0);

    uint8_t plaintext[8192];
    uint8_t ciphertext[8192];

    auto clt_hdr_len = clt->get_header(clt, clt_header);
    auto l = srv->decrypt(srv, clt_header, clt_hdr_len, plaintext, sizeof(plaintext));
    REQUIRE(l == 0);

    auto srv_hdr_len = srv->get_header(srv, srv_header);
    l = clt->decrypt(clt, srv_header, srv_hdr_len, plaintext, sizeof(plaintext));
    REQUIRE(l == 0);

    std::string msg("this is an important message");
    l = clt->encrypt(clt, (uint8_t*)msg.c_str(), msg.length(), ciphertext, sizeof(ciphertext));
    l = srv->decrypt(srv, ciphertext, l, plaintext, sizeof(plaintext));

    CHECK(std::string((char*)plaintext, l) == msg);

    std::ranges::reverse(msg);
    l = srv->encrypt(srv, (uint8_t*)msg.c_str(), msg.length(), ciphertext, sizeof(ciphertext));
    l = clt->decrypt(clt, ciphertext, l, plaintext, sizeof(plaintext));
    CHECK(std::string((char*)plaintext, l) == msg);

}
