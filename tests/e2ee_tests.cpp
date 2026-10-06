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
#include "tls_wire.h"

#include <sodium/randombytes.h>

struct e2ee_deleter {
    void operator()(e2ee_t *e) const {
        e->free(e);
    }
};

struct tls_ctx_deleter {
    void operator()(tls_context *t) const {
        t->free_ctx(t);
    }
};

// releases the key/cert pair even if an assertion unwinds out of the test
struct x509_guard {
    zt_x509 *x509;
    ~x509_guard() { zt_x509_drop(x509); }
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
    auto e2ee = GENERATE(ziti_crypto_none, ziti_crypto_libsodium);
    WHEN("e2ee_impl_t: " << e2ee_method_id(e2ee)) {
        auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee, false, nullptr));
        auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(e2ee, false, nullptr));

        if (alice == nullptr || bob == nullptr) {
            SKIP("e2ee method " << e2ee_method_id(e2ee) << " not implemented, skipping");
        }

        test_e2ee(alice.get(), bob.get());
    }
}

TEST_CASE("e2ee libsodium init rejects wrong peer key length", "[crypto]") {
    auto e = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    uint8_t too_short[crypto_kx_PUBLICKEYBYTES - 1] = {0};
    uint8_t too_long[crypto_kx_PUBLICKEYBYTES + 1] = {0};

    REQUIRE(e->init(e.get(), too_short, sizeof(too_short), false) == -1);
    REQUIRE(e->init(e.get(), too_long, sizeof(too_long), false) == -1);
    REQUIRE(e->init(e.get(), nullptr, 0, false) == -1);
}

TEST_CASE("e2ee libsodium init is one-shot", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    auto bob_pub = bob->pub(bob.get());

    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, false) == 0);
    REQUIRE(alice->init(alice.get(), bob_pub.key, bob_pub.key_len, false) == -1);
}

TEST_CASE("e2ee libsodium get_header is one-shot", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
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
    auto listener = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    auto listener_pub = listener->pub(listener.get());
    std::vector<uint8_t> pub_snapshot(listener_pub.key, listener_pub.key + listener_pub.key_len);

    auto peer1 = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    auto peer1_pub = peer1->pub(peer1.get());

    auto clone1 = std::unique_ptr<e2ee_t, e2ee_deleter>(listener->clone(listener.get()));
    REQUIRE(clone1->init(clone1.get(), peer1_pub.key, peer1_pub.key_len, true) == 0);

    auto listener_pub_after = listener->pub(listener.get());
    REQUIRE(listener_pub_after.key_len == pub_snapshot.size());
    REQUIRE(memcmp(listener_pub_after.key, pub_snapshot.data(), pub_snapshot.size()) == 0);

    // listener still usable: second clone+init succeeds against a fresh peer
    auto peer2 = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    auto peer2_pub = peer2->pub(peer2.get());
    auto clone2 = std::unique_ptr<e2ee_t, e2ee_deleter>(listener->clone(listener.get()));
    REQUIRE(clone2->init(clone2.get(), peer2_pub.key, peer2_pub.key_len, true) == 0);
}

TEST_CASE("e2ee libsodium decrypt retries after partial header", "[crypto]") {
    auto alice = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
    auto bob = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_libsodium, false, nullptr));
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


// in-memory TLS e2ee handshake plus data exchange between a server and a client engine.
// optionally hands back the server's first flight (its ServerHello), the TLS library's version string, and the
// header the server produces after decrypting the client's second flight
static void e2ee_tls_exchange(std::vector<uint8_t> *server_hello = nullptr, std::string *lib_version = nullptr,
                              std::vector<uint8_t> *server_final = nullptr) {
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
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
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

    // both engines borrow this context, so it has to outlive them: declared first so it
    // is destroyed last. the credentials are up-ref'd by set_own_cert, so the order of
    // cred_guard relative to the engines does not matter
    auto tls = default_tls_context();
    auto tls_guard = std::unique_ptr<tls_context, tls_ctx_deleter>(tls);
    // as the SDK's load_tls() does
    tls_restrict_fips(tls);
    REQUIRE(tls->set_ca_bundle(tls, ca, strlen(ca)) == 0);

    zt_x509 srv_cred{};
    x509_guard cred_guard{&srv_cred};

    REQUIRE(tls->load_cert(&srv_cred.cert, cert, strlen(cert)) == 0);
    REQUIRE(tls->load_key(&srv_cred.key, key, strlen(key)) == 0);

    REQUIRE(tls->set_own_cert(tls, srv_cred.key, srv_cred.cert) == 0);

    auto srv = create_e2ee(ziti_crypto_tls, true, tls);
    auto clt = create_e2ee(ziti_crypto_tls, false, tls);
    REQUIRE(srv != nullptr);
    REQUIRE(clt != nullptr);
    auto srv_guard = std::unique_ptr<e2ee_t, e2ee_deleter>(srv);
    auto clt_guard = std::unique_ptr<e2ee_t, e2ee_deleter>(clt);

    auto clt_hello = clt->pub(clt);

    uint8_t srv_header[E2EE_MAX_HEADER_LEN];
    uint8_t clt_header[E2EE_MAX_HEADER_LEN];
    REQUIRE(srv->init(srv, clt_hello.key, clt_hello.key_len, true) == 0);
    auto srv_hello = srv->pub(srv);
    if (server_hello) {
        server_hello->assign(srv_hello.key, srv_hello.key + srv_hello.key_len);
    }
    if (lib_version) {
        *lib_version = tls->version();
    }

    REQUIRE(clt->init(clt, srv_hello.key, srv_hello.key_len, false) == 0);

    uint8_t plaintext[8192];
    uint8_t ciphertext[8192];

    auto clt_hdr_len = clt->get_header(clt, clt_header);
    auto l = srv->decrypt(srv, clt_header, clt_hdr_len, plaintext, sizeof(plaintext));
    REQUIRE(l == 0);

    auto srv_hdr_len = srv->get_header(srv, srv_header);
    REQUIRE(srv_hdr_len >= 0);
    if (server_final) {
        server_final->assign(srv_header, srv_header + srv_hdr_len);
    }
    l = clt->decrypt(clt, srv_header, srv_hdr_len, plaintext, sizeof(plaintext));
    REQUIRE(l == 0);

    std::string msg("this is an important message");
    l = clt->encrypt(clt, (uint8_t*)msg.c_str(), msg.length(), ciphertext, sizeof(ciphertext));
    REQUIRE(l > 0);
    l = srv->decrypt(srv, ciphertext, l, plaintext, sizeof(plaintext));
    REQUIRE(l > 0);

    CHECK(std::string((char*)plaintext, l) == msg);

    std::ranges::reverse(msg);
    l = srv->encrypt(srv, (uint8_t*)msg.c_str(), msg.length(), ciphertext, sizeof(ciphertext));
    l = clt->decrypt(clt, ciphertext, l, plaintext, sizeof(plaintext));
    CHECK(std::string((char*)plaintext, l) == msg);

    // largest payload the SDK hands to encrypt() (MAX_CHAIN_LEN): spans multiple TLS
    // records, so it exceeds both the initial 16k buffers and a single record's framing
    std::vector<uint8_t> big(31 * 1024);
    randombytes_buf(big.data(), big.size());
    std::vector<uint8_t> big_ct(big.size() + E2EE_MAX_MSG_OVERHEAD);
    std::vector<uint8_t> big_pt(big.size());

    l = clt->encrypt(clt, big.data(), big.size(), big_ct.data(), big_ct.size());
    REQUIRE(l > 0);
    l = srv->decrypt(srv, big_ct.data(), l, big_pt.data(), big_pt.size());
    REQUIRE(l == (ssize_t)big.size());
    CHECK(memcmp(big.data(), big_pt.data(), big.size()) == 0);
}

TEST_CASE("e2ee-tls", "[crypto]") {
    e2ee_tls_exchange();
}

TEST_CASE("e2ee-tls server without own cert", "[crypto]") {
    // what a ziti context has when set_own_cert failed: the server engine cannot be created
    auto tls = default_tls_context();
    auto tls_guard = std::unique_ptr<tls_context, tls_ctx_deleter>(tls);

    CHECK(create_e2ee(ziti_crypto_tls, true, tls) == nullptr);
}

// TLS 1.2 ends with the server's ChangeCipherSpec and Finished, which it produces only while decrypting the
// client's second flight. The host must hand them back from get_header() after that decrypt, or the client never
// completes. Neither backend exposes a version cap, so the cap comes from outside the process:
//   OpenSSL:  OPENSSL_CONF=<config with "Protocol = -TLSv1.3" in its system_default section>
//   Schannel: SCHANNEL\Protocols\TLS 1.3\{Client,Server} Enabled=0 in the registry (machine-wide; test VMs only)
// The test fails if TLS 1.2 is not what the handshake negotiated, so a missing cap cannot pass silently.
TEST_CASE("e2ee-tls TLS 1.2 host sends its final flight after decrypt", "[crypto]") {
    const char *want = getenv("ZITI_TEST_TLS12");
    if (want == nullptr || strcmp(want, "1") != 0) {
        SKIP("set ZITI_TEST_TLS12=1 and cap the TLS backend at 1.2 (see comment) to run");
    }

    std::vector<uint8_t> server_hello;
    std::vector<uint8_t> server_final;
    e2ee_tls_exchange(&server_hello, nullptr, &server_final);

    tls_wire::server_hello_info info;
    REQUIRE(tls_wire::parse_server_hello(server_hello, info));
    CHECK(info.version == 0x0303);

    // a ChangeCipherSpec record (type 20) followed by the encrypted Finished (handshake record, type 22).
    // OpenSSL puts a NewSessionTicket handshake record ahead of them
    std::vector<uint8_t> types;
    for (size_t p = 0; p + 5 <= server_final.size(); p += 5 + ((server_final[p + 3] << 8) | server_final[p + 4])) {
        types.push_back(server_final[p]);
    }
    auto ccs = std::ranges::find(types, 0x14);
    REQUIRE(ccs != types.end());
    CHECK(std::find(ccs, types.end(), 0x16) != types.end());
}

#if !defined(__APPLE__) && __has_include(<openssl/provider.h>)
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

namespace {
using namespace tls_wire;

int print_provider(OSSL_PROVIDER *prov, void *) {
    const char *name = nullptr, *version = nullptr, *build = nullptr;
    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)&name, 0),
            OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)&version, 0),
            OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, (char **)&build, 0),
            OSSL_PARAM_construct_end(),
    };
    OSSL_PROVIDER_get_params(prov, params);
    printf("[fips] provider %s: %s, version %s, build %s\n", OSSL_PROVIDER_get0_name(prov),
           name ? name : "?", version ? version : "?", build ? build : "?");
    return 1;
}
}

// run with OPENSSL_CONF pointing at a config that activates only the fips and base providers, e.g.
//   OPENSSL_CONF=~/fips/openssl.cnf OPENSSL_MODULES=~/fips/lib/ossl-modules ZITI_TEST_FIPS=1 all_tests "e2ee-tls*"
// see scripts/fips-linux
TEST_CASE("e2ee-tls-fips", "[crypto][fips]") {
    const char *want = getenv("ZITI_TEST_FIPS");
    if (want == nullptr || strcmp(want, "1") != 0) {
        SKIP("set ZITI_TEST_FIPS=1 (and OPENSSL_CONF to a FIPS-only config) to run");
    }

    printf("[fips] libcrypto: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("[fips] OPENSSL_CONF=%s\n", getenv("OPENSSL_CONF") ? getenv("OPENSSL_CONF") : "(unset)");
    printf("[fips] OPENSSL_MODULES=%s\n", getenv("OPENSSL_MODULES") ? getenv("OPENSSL_MODULES") : "(unset)");
    OSSL_PROVIDER_do_all(nullptr, print_provider, nullptr);

    // tlsuv's openssl engine builds its SSL_CTX on its own OSSL_LIB_CTX only after tlsuv_set_config_path();
    // otherwise on the default (NULL) context, which OPENSSL_CONF configures. these checks are on that context,
    // and the handshake below re-checks it through tlsuv's own version string
    CHECK(EVP_default_properties_is_fips_enabled(nullptr) == 1);
    CHECK(OSSL_PROVIDER_available(nullptr, "fips") == 1);
    CHECK(OSSL_PROVIDER_available(nullptr, "default") == 0);

    EVP_MD *md5 = EVP_MD_fetch(nullptr, "MD5", nullptr);
    CHECK(md5 == nullptr);
    EVP_MD_free(md5);

    EVP_CIPHER *chacha = EVP_CIPHER_fetch(nullptr, "ChaCha20-Poly1305", nullptr);
    CHECK(chacha == nullptr);
    EVP_CIPHER_free(chacha);

    EVP_CIPHER *aes = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
    REQUIRE(aes != nullptr);
    CHECK(std::string(OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(aes))) == "fips");
    EVP_CIPHER_free(aes);

    std::vector<uint8_t> server_hello;
    std::string lib_version;
    e2ee_tls_exchange(&server_hello, &lib_version);

    printf("[fips] tlsuv tls lib: %s\n", lib_version.c_str());
    CHECK(lib_version.find("[FIPS]") != std::string::npos);

    server_hello_info info;
    REQUIRE(parse_server_hello(server_hello, info));
    printf("[fips] negotiated %s (0x%04x), cipher %s (0x%04x), key share %s (0x%04x)\n",
           tls_version_name(info.version), info.version,
           cipher_suite_name(info.cipher_suite), info.cipher_suite,
           group_name(info.key_share_group), info.key_share_group);
    CHECK(info.cipher_suite != 0x1303);
    CHECK(info.cipher_suite != 0xCCA8);

    // the 3.1.2 fips provider serves X25519/X448 itself, so fips=yes alone would let TLS 1.3 pick X25519.
    // tls_restrict_fips() keeps them out with or without a config that restricts the groups
    CHECK(info.key_share_group != 0x001d);
    CHECK(info.key_share_group != 0x001e);
}
#endif

namespace {
// a TLS 1.3-style ServerHello record carrying `version` in supported_versions, `suite`, and a
// key_share for `group`; enough for the parameter check, not a handshake
std::vector<uint8_t> server_hello(uint16_t version, uint16_t suite, uint16_t group) {
    std::vector<uint8_t> ext = {
            0x00, 0x2b, 0x00, 0x02, (uint8_t)(version >> 8), (uint8_t) version,
            0x00, 0x33, 0x00, 0x06, (uint8_t)(group >> 8), (uint8_t) group, 0x00, 0x02, 0xaa, 0xbb,
    };
    std::vector<uint8_t> body = {0x03, 0x03};         // legacy_version
    body.insert(body.end(), 32, 0x11);                // random
    body.push_back(0);                                // session id length
    body.push_back((uint8_t)(suite >> 8));
    body.push_back((uint8_t) suite);
    body.push_back(0);                                // compression
    body.push_back((uint8_t)(ext.size() >> 8));
    body.push_back((uint8_t) ext.size());
    body.insert(body.end(), ext.begin(), ext.end());

    std::vector<uint8_t> rec = {0x16, 0x03, 0x03, (uint8_t)((body.size() + 4) >> 8), (uint8_t)(body.size() + 4),
                                0x02, 0x00, (uint8_t)(body.size() >> 8), (uint8_t) body.size()};
    rec.insert(rec.end(), body.begin(), body.end());
    return rec;
}

void append_handshake(std::vector<uint8_t> &hs, uint8_t type, const std::vector<uint8_t> &body) {
    hs.insert(hs.end(), {type, 0x00, (uint8_t)(body.size() >> 8), (uint8_t) body.size()});
    hs.insert(hs.end(), body.begin(), body.end());
}

// a TLS 1.2 server flight: a ServerHello with `suite` (and the extended_master_secret extension if `ems`),
// a ServerKeyExchange naming `curve`, and a ServerHelloDone, cut into handshake records of at most
// `record_size` bytes, so a message can span records the way a real flight's Certificate does
std::vector<uint8_t> tls12_flight(uint16_t suite, uint16_t curve, bool ems, size_t record_size = 16384) {
    std::vector<uint8_t> hello = {0x03, 0x03};        // version
    hello.insert(hello.end(), 32, 0x11);              // random
    hello.push_back(0);                               // session id length
    hello.insert(hello.end(), {(uint8_t)(suite >> 8), (uint8_t) suite, 0x00});
    std::vector<uint8_t> ext = {0xff, 0x01, 0x00, 0x01, 0x00};  // renegotiation_info
    if (ems) {
        ext.insert(ext.end(), {0x00, 0x17, 0x00, 0x00});
    }
    hello.insert(hello.end(), {(uint8_t)(ext.size() >> 8), (uint8_t) ext.size()});
    hello.insert(hello.end(), ext.begin(), ext.end());

    // named_curve, the curve, a 65-byte point, then a signature the check does not read
    std::vector<uint8_t> ske = {0x03, (uint8_t)(curve >> 8), (uint8_t) curve, 65, 0x04};
    ske.insert(ske.end(), 64, 0x22);
    ske.insert(ske.end(), {0x04, 0x03, 0x00, 0x04, 0x33, 0x33, 0x33, 0x33});

    std::vector<uint8_t> hs;
    append_handshake(hs, 2, hello);
    append_handshake(hs, 12, ske);
    append_handshake(hs, 14, {});

    std::vector<uint8_t> flight;
    for (size_t p = 0; p < hs.size(); p += record_size) {
        // parenthesized: windows.h defines a min() macro on MSVC
        size_t n = (std::min)(record_size, hs.size() - p);
        flight.insert(flight.end(), {0x16, 0x03, 0x03, (uint8_t)(n >> 8), (uint8_t) n});
        flight.insert(flight.end(), hs.begin() + (long) p, hs.begin() + (long)(p + n));
    }
    return flight;
}
}

TEST_CASE("tls e2ee accepts only FIPS-approved parameters in FIPS mode", "[crypto][fips]") {
    auto check = [](bool fips, const std::vector<uint8_t> &hello) {
        return tls_e2ee_check_server_flight(fips, hello.data(), hello.size());
    };

    SECTION("approved: TLS 1.3, AES-GCM, NIST curves") {
        CHECK(check(true, server_hello(0x0304, 0x1301, 0x0017)) == 0);
        CHECK(check(true, server_hello(0x0304, 0x1302, 0x0018)) == 0);
        CHECK(check(true, server_hello(0x0304, 0x1302, 0x0019)) == 0);
    }
    SECTION("X25519 and X448 are refused") {
        CHECK(check(true, server_hello(0x0304, 0x1302, 0x001d)) == -1);
        CHECK(check(true, server_hello(0x0304, 0x1302, 0x001e)) == -1);
    }
    SECTION("ChaCha20-Poly1305 is refused") {
        CHECK(check(true, server_hello(0x0304, 0x1303, 0x0017)) == -1);
    }
    SECTION("approved: TLS 1.2, ECDHE AES-GCM, extended master secret, NIST curves") {
        CHECK(check(true, tls12_flight(0xc02b, 0x0017, true)) == 0);
        CHECK(check(true, tls12_flight(0xc02c, 0x0018, true)) == 0);
        CHECK(check(true, tls12_flight(0xc02f, 0x0017, true)) == 0);
        CHECK(check(true, tls12_flight(0xc030, 0x0019, true)) == 0);
    }
    SECTION("TLS 1.2 messages split across records are reassembled") {
        CHECK(check(true, tls12_flight(0xc02b, 0x0017, true, 7)) == 0);
        CHECK(check(true, tls12_flight(0xc02b, 0x001d, true, 7)) == -1);
    }
    SECTION("TLS 1.2 without the extended master secret is refused") {
        CHECK(check(true, tls12_flight(0xc02f, 0x0017, false)) == -1);
    }
    SECTION("TLS 1.2 with X25519, CBC, ChaCha20 or DHE is refused") {
        CHECK(check(true, tls12_flight(0xc02f, 0x001d, true)) == -1);
        CHECK(check(true, tls12_flight(0xc027, 0x0017, true)) == -1);
        CHECK(check(true, tls12_flight(0xcca8, 0x0017, true)) == -1);
        CHECK(check(true, tls12_flight(0x009e, 0x0017, true)) == -1);
    }
    SECTION("TLS 1.2 without a ServerKeyExchange is refused") {
        // the ServerHello alone names no curve
        auto flight = tls12_flight(0xc02f, 0x0017, true);
        size_t hello_len = 4 + ((flight[7] << 8) | flight[8]);
        flight.resize(5 + hello_len);
        flight[3] = (uint8_t)(hello_len >> 8);
        flight[4] = (uint8_t) hello_len;
        CHECK(check(true, flight) == -1);
    }
    SECTION("TLS 1.1 and older are refused") {
        CHECK(check(true, server_hello(0x0302, 0xc013, 0x0017)) == -1);
    }
    SECTION("a flight that is not a ServerHello is refused") {
        std::vector<uint8_t> junk(64, 0x42);
        CHECK(check(true, junk) == -1);
        CHECK(check(true, {}) == -1);
    }
    SECTION("outside FIPS mode the same parameters only get logged") {
        CHECK(check(false, server_hello(0x0304, 0x1303, 0x001d)) == 0);
        CHECK(check(false, server_hello(0x0303, 0xc02f, 0x0017)) == 0);
        CHECK(check(false, tls12_flight(0xc02f, 0x001d, false)) == 0);
    }
    SECTION("a HelloRetryRequest leaves the check to the ServerHello that follows") {
        // RFC 8446 4.1.3
        const uint8_t hrr_random[32] = {
                0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
        };
        // record header(5) + handshake header(4) + legacy_version(2)
        auto hrr = server_hello(0x0304, 0x1301, 0x001d);
        std::copy(std::begin(hrr_random), std::end(hrr_random), hrr.begin() + 11);
        CHECK(check(true, hrr) == 1);
        CHECK(check(false, hrr) == 1);
    }
}

namespace {
// a TLS engine past its handshake that frames nothing: each write() passes at most `chunk` bytes
// through, the way Schannel encrypts one record at a time. chunk 0 makes no progress at all
struct fake_engine {
    tlsuv_engine_s api{};
    io_ctx io = nullptr;
    io_write out = nullptr;
    size_t chunk = 0;
    int writes = 0;
};

fake_engine *the_fake;

fake_engine *fake(tlsuv_engine_t e) {
    return reinterpret_cast<fake_engine *>(e);
}

tlsuv_engine_t fake_new_engine(tls_context *, const char *) {
    the_fake->api.set_io = [](tlsuv_engine_t e, io_ctx io, io_read, io_write out) {
        fake(e)->io = io;
        fake(e)->out = out;
    };
    the_fake->api.handshake_state = [](tlsuv_engine_t) { return TLS_HS_COMPLETE; };
    the_fake->api.handshake = [](tlsuv_engine_t) { return TLS_HS_COMPLETE; };
    the_fake->api.write = [](tlsuv_engine_t e, const char *data, size_t len) {
        fake(e)->writes++;
        size_t n = (std::min)(len, fake(e)->chunk);
        if (n > 0) {
            fake(e)->out(fake(e)->io, data, n);
        }
        return (int) n;
    };
    the_fake->api.free = [](tlsuv_engine_t) {};
    return &the_fake->api;
}
}

TEST_CASE("e2ee-tls encrypt keeps writing until the engine took the whole payload", "[crypto]") {
    fake_engine eng;
    the_fake = &eng;
    tls_context ctx{};
    ctx.new_engine = fake_new_engine;
    ctx.fips_status = [](tls_context *, char *, size_t) { return TLS_FIPS_DISABLED; };

    auto e = std::unique_ptr<e2ee_t, e2ee_deleter>(create_e2ee(ziti_crypto_tls, false, &ctx));
    REQUIRE(e != nullptr);

    const std::string msg = "a payload the engine takes ten bytes at a time";
    std::vector<uint8_t> ct(msg.size() + E2EE_MAX_MSG_OVERHEAD);

    SECTION("partial writes add up to the payload") {
        eng.chunk = 10;
        ssize_t n = e->encrypt(e.get(), (const uint8_t *) msg.data(), msg.size(), ct.data(), ct.size());
        REQUIRE(n == (ssize_t) msg.size());
        CHECK(std::string((const char *) ct.data(), (size_t) n) == msg);
        CHECK(eng.writes == (int) (msg.size() + 9) / 10);
    }
    SECTION("an engine that takes nothing fails the encrypt") {
        eng.chunk = 0;
        CHECK(e->encrypt(e.get(), (const uint8_t *) msg.data(), msg.size(), ct.data(), ct.size()) == -1);
        CHECK(eng.writes == 1);
    }
}
