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


// The SDK's e2ee-tls against an OpenSSL peer, on whichever TLS backend the SDK is built with. OpenSSL serves as the
// peer and as the certificate factory.

#include "tls_test_util.h"

#include "crypto.h"

#if ZITI_TEST_OPENSSL_PEER
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

#if ZITI_TEST_OPENSSL_PEER
namespace {
struct pkey_deleter { void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); } };
using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_deleter>;

pkey_ptr fixture_key() {
    BIO *b = BIO_new_mem_buf(rsa_key, -1);
    pkey_ptr k{PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr)};
    BIO_free(b);
    return k;
}

void add_ext(X509 *x, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    REQUIRE(ext != nullptr);
    X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
}

struct x509_deleter { void operator()(X509 *x) const { X509_free(x); } };
using x509_ptr = std::unique_ptr<X509, x509_deleter>;

std::string to_pem(X509 *x) {
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, x);
    char *data = nullptr;
    long len = BIO_get_mem_data(out, &data);
    std::string pem(data, (size_t) len);
    BIO_free(out);
    return pem;
}

std::string to_pem(EVP_PKEY *k) {
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(out, k, nullptr, nullptr, 0, nullptr, nullptr);
    char *data = nullptr;
    long len = BIO_get_mem_data(out, &data);
    std::string pem(data, (size_t) len);
    BIO_free(out);
    return pem;
}

// a certificate for `key` with subject CN=`subject` and issuer CN=localhost (the fixture CA's name),
// signed with `signer`, valid from not_before_days to not_after_days relative to now
x509_ptr issue_cert(EVP_PKEY *key, const char *subject, EVP_PKEY *signer, bool ca,
                    long not_before_days, long not_after_days) {
    x509_ptr x{X509_new()};
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 4242);
    X509_gmtime_adj(X509_getm_notBefore(x.get()), not_before_days * 86400);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), not_after_days * 86400);
    X509_set_pubkey(x.get(), key);
    X509_NAME *sub = X509_get_subject_name(x.get());
    X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC, (const unsigned char *) subject, -1, -1, 0);
    X509_NAME *iss = X509_get_issuer_name(x.get());
    X509_NAME_add_entry_by_txt(iss, "CN", MBSTRING_ASC, (const unsigned char *) "localhost", -1, -1, 0);
    add_ext(x.get(), NID_subject_key_identifier, "hash");
    add_ext(x.get(), NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_ext(x.get(), NID_subject_alt_name, "DNS:localhost");
    add_ext(x.get(), NID_ext_key_usage, "serverAuth,clientAuth");
    add_ext(x.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment");
    REQUIRE(X509_sign(x.get(), signer, EVP_sha256()) > 0);
    return x;
}

// win32crypto's set_own_cert persists the key under the base64 of the certificate's key id
void delete_persisted_key(X509 *x) {
#if _WIN32
    const ASN1_OCTET_STRING *ski = X509_get0_subject_key_id(x);
    if (ski == nullptr) return;
    DWORD len = 0;
    CryptBinaryToStringW(ASN1_STRING_get0_data(ski), (DWORD) ASN1_STRING_length(ski),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
    std::wstring name(len, L'\0');
    CryptBinaryToStringW(ASN1_STRING_get0_data(ski), (DWORD) ASN1_STRING_length(ski),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, name.data(), &len);
    name.resize(len);
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (open_persisted_key(name.c_str(), &prov, &key) == ERROR_SUCCESS) {
        NCryptDeleteKey(key, 0);
        NCryptFreeObject(prov);
    }
#else
    (void) x;
#endif
}
}

// The host checks the dialer's certificate while it decrypts the dialer's second flight. Under TLS 1.3 the dialer is
// done once it has sent Finished, so its first app record can arrive in that same decrypt. A rejected certificate has
// to fail the decrypt, and none of the app data may come out of it.
TEST_CASE("e2ee-tls host delivers no data from a dialer whose certificate it rejects", "[crypto]") {
    persisted_key_cleanup cleanup;
    struct ctx_guard {
        tls_context *c;
        ~ctx_guard() { if (c) c->free_ctx(c); }
    };
    struct cred_guard {
        tlsuv_private_key_t k = nullptr;
        tlsuv_certificate_t c = nullptr;
        ~cred_guard() {
            if (c) c->free(c);
            if (k) k->free(k);
        }
    };
    struct e2ee_guard {
        e2ee_t *e;
        ~e2ee_guard() { if (e) e->free(e); }
    };

    // the host trusts only the fixture CA, and presents the fixture identity
    ctx_guard srv_ctx{tls_with_ca(rsa_cert)};
    cred_guard srv_cred;
    REQUIRE(srv_ctx.c->load_key(&srv_cred.k, rsa_key, strlen(rsa_key)) == 0);
    REQUIRE(srv_ctx.c->load_cert(&srv_cred.c, rsa_cert, strlen(rsa_cert)) == 0);
    REQUIRE(srv_ctx.c->set_own_cert(srv_ctx.c, srv_cred.k, srv_cred.c) == 0);

    // the dialer trusts the host, but its own leaf names the CA as issuer and is signed by another key
    pkey_ptr attacker{EVP_EC_gen("P-256")};
    pkey_ptr leaf_key{EVP_EC_gen("P-256")};
    REQUIRE(attacker);
    REQUIRE(leaf_key);
    x509_ptr leaf = issue_cert(leaf_key.get(), "dialer", attacker.get(), false, -1, 30);
    struct leaf_cleanup {
        X509 *x;
        ~leaf_cleanup() { delete_persisted_key(x); }
    } leaf_gone{leaf.get()};
    ctx_guard clt_ctx{tls_with_ca(rsa_cert)};
    cred_guard clt_cred;
    const std::string leaf_key_pem = to_pem(leaf_key.get());
    const std::string leaf_pem = to_pem(leaf.get());
    REQUIRE(clt_ctx.c->load_key(&clt_cred.k, leaf_key_pem.c_str(), leaf_key_pem.size()) == 0);
    REQUIRE(clt_ctx.c->load_cert(&clt_cred.c, leaf_pem.c_str(), leaf_pem.size()) == 0);
    REQUIRE(clt_ctx.c->set_own_cert(clt_ctx.c, clt_cred.k, clt_cred.c) == 0);

    e2ee_guard srv{create_e2ee(ziti_crypto_tls, true, srv_ctx.c)};
    e2ee_guard clt{create_e2ee(ziti_crypto_tls, false, clt_ctx.c)};
    REQUIRE(srv.e != nullptr);
    REQUIRE(clt.e != nullptr);

    e2ee_pub_t clt_hello = clt.e->pub(clt.e);
    REQUIRE(srv.e->init(srv.e, clt_hello.key, clt_hello.key_len, true) == 0);
    e2ee_pub_t srv_hello = srv.e->pub(srv.e);
    REQUIRE(clt.e->init(clt.e, srv_hello.key, srv_hello.key_len, false) == 0);

    std::vector<uint8_t> flight(E2EE_MAX_HEADER_LEN);
    ssize_t hdr_len = clt.e->get_header(clt.e, flight.data());
    REQUIRE(hdr_len > 0);
    flight.resize((size_t) hdr_len);

    const std::string secret = "app data the host must not deliver";
    if (!tls12_capped()) {
        // TLS 1.3: the dialer has finished, and its app data follows its flight
        REQUIRE(clt.e->ready(clt.e));
        std::vector<uint8_t> ct(secret.size() + E2EE_MAX_MSG_OVERHEAD);
        ssize_t ct_len = clt.e->encrypt(clt.e, (const uint8_t *) secret.data(), secret.size(), ct.data(), ct.size());
        REQUIRE(ct_len > 0);
        flight.insert(flight.end(), ct.begin(), ct.begin() + ct_len);
    }

    std::vector<uint8_t> pt(16 * 1024, 0);
    CHECK(srv.e->decrypt(srv.e, flight.data(), flight.size(), pt.data(), pt.size()) == -1);
    CHECK(std::search(pt.begin(), pt.end(), secret.begin(), secret.end()) == pt.end());
    CHECK_FALSE(srv.e->ready(srv.e));
}

namespace {
// an OpenSSL server on memory BIOs, fed from and to the same pipes as a tlsuv engine
struct openssl_server {
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    BIO *in = nullptr;
    BIO *out = nullptr;

    explicit openssl_server(int max_version = 0) {
        ctx = SSL_CTX_new(TLS_server_method());
        REQUIRE(ctx != nullptr);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, max_version);
        pkey_ptr key = fixture_key();
        BIO *b = BIO_new_mem_buf(rsa_cert, -1);
        x509_ptr cert{PEM_read_bio_X509(b, nullptr, nullptr, nullptr)};
        BIO_free(b);
        REQUIRE(SSL_CTX_use_certificate(ctx, cert.get()) == 1);
        REQUIRE(SSL_CTX_use_PrivateKey(ctx, key.get()) == 1);
        ssl = SSL_new(ctx);
        in = BIO_new(BIO_s_mem());
        out = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, in, out); // ssl owns both
        SSL_set_accept_state(ssl);
    }

    ~openssl_server() {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
};

// an OpenSSL client on memory BIOs, against a tlsuv server engine. TLS 1.3 unless capped at `max_version`
struct openssl_client {
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    BIO *in = nullptr;
    BIO *out = nullptr;

    explicit openssl_client(int max_version = 0) {
        ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ctx != nullptr);
        SSL_CTX_set_min_proto_version(ctx, max_version ? TLS1_2_VERSION : TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, max_version);
        // the server's certificate is not what this checks
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        // a server with a verify callback requires a client certificate
        pkey_ptr key = fixture_key();
        BIO *b = BIO_new_mem_buf(rsa_cert, -1);
        x509_ptr cert{PEM_read_bio_X509(b, nullptr, nullptr, nullptr)};
        BIO_free(b);
        REQUIRE(SSL_CTX_use_certificate(ctx, cert.get()) == 1);
        REQUIRE(SSL_CTX_use_PrivateKey(ctx, key.get()) == 1);
        ssl = SSL_new(ctx);
        in = BIO_new(BIO_s_mem());
        out = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, in, out); // ssl owns both
        SSL_set_connect_state(ssl);
    }

    ~openssl_client() {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
};
}

namespace {
struct ctx_guard {
    tls_context *c;
    ~ctx_guard() { if (c) c->free_ctx(c); }
};

struct e2ee_guard {
    e2ee_t *e;
    ~e2ee_guard() { if (e) e->free(e); }
};

std::vector<uint8_t> drain(BIO *b) {
    std::vector<uint8_t> out;
    uint8_t chunk[4096];
    int n;
    while ((n = BIO_read(b, chunk, sizeof(chunk))) > 0) out.insert(out.end(), chunk, chunk + n);
    return out;
}
}

// TLS 1.2 ends with the host's ChangeCipherSpec and Finished, produced while it decrypts the dialer's second flight.
// The host hands them back through handshake_output(), and cannot encrypt before the dialer's Finished arrived.
TEST_CASE("e2ee-tls TLS 1.2 host completes the handshake in decrypt", "[crypto]") {
    persisted_key_cleanup cleanup;
    identity_ctx srv_id;
    REQUIRE(srv_id.load() == 0);
    e2ee_guard srv{create_e2ee(ziti_crypto_tls, true, srv_id.tls)};
    REQUIRE(srv.e != nullptr);

    openssl_client clt(TLS1_2_VERSION);
    // NIST curves only, which a FIPS-mode host requires
    REQUIRE(SSL_set1_groups_list(clt.ssl, "P-256:P-384") == 1);
    SSL_do_handshake(clt.ssl);
    std::vector<uint8_t> hello = drain(clt.out);
    REQUIRE(srv.e->init(srv.e, hello.data(), hello.size(), true) == 0);
    e2ee_pub_t flight = srv.e->pub(srv.e);
    REQUIRE(flight.key_len > 0);
    BIO_write(clt.in, flight.key, (int) flight.key_len);
    SSL_do_handshake(clt.ssl);
    REQUIRE(SSL_version(clt.ssl) == TLS1_2_VERSION);
    std::vector<uint8_t> clt_flight = drain(clt.out);
    CHECK_FALSE(srv.e->ready(srv.e));

    uint8_t pt[4096];
    REQUIRE(srv.e->decrypt(srv.e, clt_flight.data(), clt_flight.size(), pt, sizeof(pt)) == 0);
    CHECK(srv.e->ready(srv.e));
    REQUIRE(srv.e->handshake_output != nullptr);
    std::vector<uint8_t> fin(E2EE_MAX_HEADER_LEN);
    ssize_t fin_len = srv.e->handshake_output(srv.e, fin.data());
    REQUIRE(fin_len > 0);
    BIO_write(clt.in, fin.data(), (int) fin_len);
    REQUIRE(SSL_do_handshake(clt.ssl) == 1);

    const std::string ping = "ping over TLS 1.2";
    std::vector<uint8_t> ct(ping.size() + E2EE_MAX_MSG_OVERHEAD);
    ssize_t ct_len = srv.e->encrypt(srv.e, (const uint8_t *) ping.data(), ping.size(), ct.data(), ct.size());
    REQUIRE(ct_len > 0);
    BIO_write(clt.in, ct.data(), (int) ct_len);
    char buf[256];
    int n = SSL_read(clt.ssl, buf, sizeof(buf));
    CHECK(std::string(buf, n > 0 ? (size_t) n : 0) == ping);
}

// A TLS 1.2 dialer completes on the host's ChangeCipherSpec and Finished, and takes what the host sends right behind
// them in the same message.
TEST_CASE("e2ee-tls TLS 1.2 dialer completes on the host's final flight", "[crypto]") {
    ctx_guard clt_ctx{tls_with_ca(rsa_cert)};
    e2ee_guard clt{create_e2ee(ziti_crypto_tls, false, clt_ctx.c)};
    REQUIRE(clt.e != nullptr);

    openssl_server srv(TLS1_2_VERSION);
    REQUIRE(SSL_set1_groups_list(srv.ssl, "P-256") == 1);
    e2ee_pub_t hello = clt.e->pub(clt.e);
    BIO_write(srv.in, hello.key, (int) hello.key_len);
    SSL_do_handshake(srv.ssl);
    std::vector<uint8_t> srv_flight = drain(srv.out);
    REQUIRE(clt.e->init(clt.e, srv_flight.data(), srv_flight.size(), false) == 0);

    std::vector<uint8_t> hdr(E2EE_MAX_HEADER_LEN);
    ssize_t hdr_len = clt.e->get_header(clt.e, hdr.data());
    REQUIRE(hdr_len > 0);
    BIO_write(srv.in, hdr.data(), (int) hdr_len);
    REQUIRE(SSL_do_handshake(srv.ssl) == 1);
    REQUIRE(SSL_version(srv.ssl) == TLS1_2_VERSION);
    // the dialer has sent its Finished, but cannot encrypt before the host's
    CHECK_FALSE(clt.e->ready(clt.e));

    uint8_t pt[4096] = {};
    SECTION("app data that comes with the final flight is delivered") {
        const std::string ping = "ping with the final flight";
        REQUIRE(SSL_write(srv.ssl, ping.data(), (int) ping.size()) == (int) ping.size());
        std::vector<uint8_t> recs = drain(srv.out);
        ssize_t n = clt.e->decrypt(clt.e, recs.data(), recs.size(), pt, sizeof(pt));
        CHECK(std::string((const char *) pt, n > 0 ? (size_t) n : 0) == ping);
        CHECK(clt.e->ready(clt.e));
    }
}
#endif
