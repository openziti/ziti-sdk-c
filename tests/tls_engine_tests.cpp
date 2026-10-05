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


// TLS engine behaviour that every backend has to show, driven through the tlsuv engine API with an
// in-memory transport. OpenSSL serves as the peer and as the certificate factory.

#include "tls_test_util.h"

#include "crypto.h"
#include "tls_wire.h"

#if ZITI_TEST_OPENSSL_PEER
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

// reads the negotiated parameters off the wire, since Schannel does not report the key exchange group
TEST_CASE("tls engine negotiated TLS parameters", "[crypto][fips]") {
    persisted_key_cleanup cleanup;
    identity_ctx srv;
    REQUIRE(srv.load(true) == 0);
    identity_ctx clt;
    REQUIRE(clt.load(true) == 0);

    engine_guard srv_eng{srv.tls->new_server_engine(srv.tls)};
    engine_guard clt_eng{clt.tls->new_engine(clt.tls, "localhost")};
    REQUIRE(srv_eng.e != nullptr);
    REQUIRE(clt_eng.e != nullptr);

    mem_pipe c2s, s2c;
    std::vector<uint8_t> server_flight;
    mem_endpoint clt_ep{&s2c, &c2s};
    mem_endpoint srv_ep{&c2s, &s2c, &server_flight};
    clt_eng.e->set_io(clt_eng.e, &clt_ep, mem_read, mem_write);
    srv_eng.e->set_io(srv_eng.e, &srv_ep, mem_read, mem_write);

    tls_handshake_state cs, ss;
    run_handshake(clt_eng.e, srv_eng.e, cs, ss);
    REQUIRE(cs == TLS_HS_COMPLETE);
    REQUIRE(ss == TLS_HS_COMPLETE);

    tls_wire::server_hello_info info;
    REQUIRE(tls_wire::parse_server_hello(server_flight, info));
    // the backend reports its FIPS mode in its version string
    bool fips = strstr(srv.tls->version(), "FIPS") != nullptr;
    printf("[tls] %s, FIPS mode %s: negotiated %s (0x%04x), cipher %s (0x%04x), key share %s (0x%04x)\n",
           srv.tls->version(), fips ? "on" : "off",
           tls_wire::tls_version_name(info.version), info.version,
           tls_wire::cipher_suite_name(info.cipher_suite), info.cipher_suite,
           tls_wire::group_name(info.key_share_group), info.key_share_group);
    CHECK(info.version == (tls12_capped() ? 0x0303 : 0x0304));
    if (fips) {
        // the SDK's own FIPS check; for TLS 1.2 it also reads the curve from the ServerKeyExchange
        CHECK(tls_e2ee_check_server_flight(true, server_flight.data(), server_flight.size()) == 0);
    }
}

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
    for (const auto &n : {name, legacy_key_name(name)}) {
        NCRYPT_PROV_HANDLE prov = 0;
        NCRYPT_KEY_HANDLE key = 0;
        if (open_persisted_key(n.c_str(), &prov, &key) == ERROR_SUCCESS) {
            NCryptDeleteKey(key, 0);
            NCryptFreeObject(prov);
        }
    }
#else
    (void) x;
#endif
}

// a client that trusts only the fixture certificate, against a server presenting `server_cert`
tls_handshake_state client_handshake_with(const std::string &server_key, const std::string &server_cert) {
    tls_context *srv = default_tls_context();
    tlsuv_private_key_t key = nullptr;
    tlsuv_certificate_t cert = nullptr;
    REQUIRE(srv->load_key(&key, server_key.c_str(), server_key.size()) == 0);
    REQUIRE(srv->load_cert(&cert, server_cert.c_str(), server_cert.size()) == 0);
    REQUIRE(srv->set_own_cert(srv, key, cert) == 0);

    // a CA bundle and no verify callback: the backend's own chain check runs
    tls_context *clt = tls_with_ca(rsa_cert);

    tlsuv_engine_t srv_eng = srv->new_server_engine(srv);
    tlsuv_engine_t clt_eng = clt->new_engine(clt, "localhost");
    REQUIRE(srv_eng != nullptr);
    REQUIRE(clt_eng != nullptr);
    mem_pipe c2s, s2c;
    mem_endpoint clt_ep{&s2c, &c2s};
    mem_endpoint srv_ep{&c2s, &s2c};
    clt_eng->set_io(clt_eng, &clt_ep, mem_read, mem_write);
    srv_eng->set_io(srv_eng, &srv_ep, mem_read, mem_write);

    tls_handshake_state cs, ss;
    run_handshake(clt_eng, srv_eng, cs, ss);

    clt_eng->free(clt_eng);
    srv_eng->free(srv_eng);
    cert->free(cert);
    key->free(key);
    clt->free_ctx(clt);
    srv->free_ctx(srv);
    return cs;
}

// a leaf for a fresh key, issued as below; its persisted copy is deleted afterwards
tls_handshake_state leaf_handshake(EVP_PKEY *signer, bool ca, long not_before_days, long not_after_days) {
    pkey_ptr leaf_key{EVP_EC_gen("P-256")};
    REQUIRE(leaf_key);
    x509_ptr leaf = issue_cert(leaf_key.get(), "leaf", signer, ca, not_before_days, not_after_days);
    tls_handshake_state st = client_handshake_with(to_pem(leaf_key.get()), to_pem(leaf.get()));
    delete_persisted_key(leaf.get());
    return st;
}
}
TEST_CASE("tls engine verifies the peer chain against the CA bundle", "[crypto]") {
    persisted_key_cleanup cleanup;
    pkey_ptr ca_key = fixture_key();
    REQUIRE(ca_key);

    SECTION("the CA certificate itself is accepted") {
        CHECK(client_handshake_with(rsa_key, rsa_cert) == TLS_HS_COMPLETE);
    }

    SECTION("a leaf the CA signed is accepted") {
        CHECK(leaf_handshake(ca_key.get(), false, -1, 30) == TLS_HS_COMPLETE);
    }

    SECTION("a leaf naming the CA as issuer but signed by another key is rejected") {
        pkey_ptr attacker{EVP_EC_gen("P-256")};
        REQUIRE(attacker);
        CHECK(leaf_handshake(attacker.get(), false, -1, 30) == TLS_HS_ERROR);
    }

    SECTION("an expired leaf the CA signed is rejected") {
        CHECK(leaf_handshake(ca_key.get(), false, -30, -1) == TLS_HS_ERROR);
    }

    SECTION("a copy of the CA certificate signed by another key is rejected") {
        pkey_ptr attacker{EVP_EC_gen("P-256")};
        REQUIRE(attacker);
        x509_ptr forged = issue_cert(ca_key.get(), "localhost", attacker.get(), true, -1, 30);
        CHECK(client_handshake_with(rsa_key, to_pem(forged.get())) == TLS_HS_ERROR);
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

// TLS makes a client certificate optional, and a backend may not even ask for one. The e2ee host requires the
// dialer's, so every backend refuses the same dialers.
TEST_CASE("e2ee-tls host refuses a dialer without a certificate", "[crypto]") {
    persisted_key_cleanup cleanup;
    struct ctx_guard {
        tls_context *c;
        ~ctx_guard() { if (c) c->free_ctx(c); }
    };
    struct e2ee_guard {
        e2ee_t *e;
        ~e2ee_guard() { if (e) e->free(e); }
    };

    identity_ctx srv_id;
    REQUIRE(srv_id.load(true) == 0);
    // the dialer trusts the host and has no identity of its own
    ctx_guard clt_ctx{tls_with_ca(rsa_cert)};

    e2ee_guard srv{create_e2ee(ziti_crypto_tls, true, srv_id.tls)};
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

    const std::string secret = "app data from an anonymous dialer";
    if (!tls12_capped()) {
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
    // the refusal holds: the host does not go on with the session
    uint8_t out[256];
    CHECK(srv.e->encrypt(srv.e, (const uint8_t *) "x", 1, out, sizeof(out)) == -1);
}

namespace {
// an OpenSSL server on memory BIOs, fed from and to the same pipes as a tlsuv engine
struct openssl_server {
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    BIO *in = nullptr;
    BIO *out = nullptr;

    // counts the KeyUpdate messages received from the client
    int key_updates_received = 0;
    // what arrived from the client: 'A' app data record, 'K' KeyUpdate
    std::string received_order;

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
        SSL_set_msg_callback(ssl, on_message);
        SSL_set_msg_callback_arg(ssl, this);
    }

    static void on_message(int write_p, int, int content_type, const void *buf, size_t len, SSL *, void *arg) {
        auto self = static_cast<openssl_server *>(arg);
        if (write_p || len == 0) return;
        auto type = static_cast<const uint8_t *>(buf)[0];
        if (content_type == SSL3_RT_HANDSHAKE && type == SSL3_MT_KEY_UPDATE) {
            self->key_updates_received++;
            self->received_order += 'K';
        } else if (content_type == SSL3_RT_INNER_CONTENT_TYPE && type == SSL3_RT_APPLICATION_DATA) {
            self->received_order += 'A';
        }
    }

    // runs the handshake against the client engine; returns the client's final state
    tls_handshake_state handshake(tlsuv_engine_t clt, mem_pipe &c2s, mem_pipe &s2c) {
        tls_handshake_state cs = TLS_HS_CONTINUE;
        bool done = false;
        for (int i = 0; i < 50 && !(cs == TLS_HS_COMPLETE && done); i++) {
            cs = clt->handshake(clt);
            if (cs == TLS_HS_ERROR) break;
            pump(c2s, s2c);
            done = SSL_do_handshake(ssl) == 1;
            pump(c2s, s2c);
        }
        return done ? cs : TLS_HS_ERROR;
    }

    ~openssl_server() {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    // moves what the client wrote into OpenSSL, and what OpenSSL wrote to the client
    void pump(mem_pipe &from_client, mem_pipe &to_client) {
        if (!from_client.buf.empty()) {
            std::vector<char> data(from_client.buf.begin(), from_client.buf.end());
            from_client.buf.clear();
            BIO_write(in, data.data(), (int) data.size());
        }
        char chunk[4096];
        int n;
        while ((n = BIO_read(out, chunk, sizeof(chunk))) > 0) {
            to_client.buf.insert(to_client.buf.end(), chunk, chunk + n);
        }
    }
};

// drives the client engine's read until it yields application data or fails
int client_read(tlsuv_engine_t clt, std::string &got) {
    char buf[1024];
    for (int i = 0; i < 20; i++) {
        size_t n = 0;
        int rc = clt->read(clt, buf, &n, sizeof(buf));
        got.append(buf, n);
        if (!got.empty() || rc == TLS_ERR || rc == TLS_EOF) return rc;
    }
    return TLS_AGAIN;
}

// an OpenSSL TLS 1.3 client on memory BIOs, against a tlsuv server engine
struct openssl_client {
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    BIO *in = nullptr;
    BIO *out = nullptr;

    // counts the KeyUpdate messages received from the server
    int key_updates_received = 0;
    // what arrived from the server: 'A' app data record, 'K' KeyUpdate
    std::string received_order;

    openssl_client() {
        ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ctx != nullptr);
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
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
        SSL_set_msg_callback(ssl, on_message);
        SSL_set_msg_callback_arg(ssl, this);
    }

    ~openssl_client() {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    static void on_message(int write_p, int, int content_type, const void *buf, size_t len, SSL *, void *arg) {
        auto self = static_cast<openssl_client *>(arg);
        if (write_p || len == 0) return;
        auto type = static_cast<const uint8_t *>(buf)[0];
        if (content_type == SSL3_RT_HANDSHAKE && type == SSL3_MT_KEY_UPDATE) {
            self->key_updates_received++;
            self->received_order += 'K';
        } else if (content_type == SSL3_RT_INNER_CONTENT_TYPE && type == SSL3_RT_APPLICATION_DATA) {
            self->received_order += 'A';
        }
    }

    // runs the handshake against the server engine; returns the server's final state
    tls_handshake_state handshake(tlsuv_engine_t srv, mem_pipe &c2s, mem_pipe &s2c) {
        tls_handshake_state ss = TLS_HS_CONTINUE;
        bool done = false;
        for (int i = 0; i < 50 && !(ss == TLS_HS_COMPLETE && done); i++) {
            done = SSL_do_handshake(ssl) == 1;
            pump(c2s, s2c);
            ss = srv->handshake(srv);
            if (ss == TLS_HS_ERROR) break;
            pump(c2s, s2c);
        }
        return done ? ss : TLS_HS_ERROR;
    }

    // moves what OpenSSL wrote to the server, and what the server wrote into OpenSSL
    void pump(mem_pipe &to_server, mem_pipe &from_server) {
        char chunk[4096];
        int n;
        while ((n = BIO_read(out, chunk, sizeof(chunk))) > 0) {
            to_server.buf.insert(to_server.buf.end(), chunk, chunk + n);
        }
        if (!from_server.buf.empty()) {
            std::vector<char> data(from_server.buf.begin(), from_server.buf.end());
            from_server.buf.clear();
            BIO_write(in, data.data(), (int) data.size());
        }
    }
};
}

// The server side of a KeyUpdate goes through AcceptSecurityContext, which no other test reaches. The client asks for
// an update in return; the server has to read the data behind the KeyUpdate and answer it.
TEST_CASE("tls engine server answers a TLS 1.3 KeyUpdate", "[crypto]") {
    persisted_key_cleanup cleanup;
    identity_ctx srv;
    if (tls12_capped()) {
        SKIP("ZITI_TEST_TLS12=1: the TLS backend has no TLS 1.3 here");
    }
    REQUIRE(srv.load(true) == 0);
    engine_guard eng{srv.tls->new_server_engine(srv.tls)};
    REQUIRE(eng.e != nullptr);

    openssl_client clt;
    mem_pipe c2s, s2c;
    mem_endpoint srv_ep{&c2s, &s2c};
    eng.e->set_io(eng.e, &srv_ep, mem_read, mem_write);

    REQUIRE(clt.handshake(eng.e, c2s, s2c) == TLS_HS_COMPLETE);
    REQUIRE(SSL_version(clt.ssl) == TLS1_3_VERSION);

    REQUIRE(SSL_key_update(clt.ssl, SSL_KEY_UPDATE_REQUESTED) == 1);
    const std::string ping = "ping after key update";
    REQUIRE(SSL_write(clt.ssl, ping.data(), (int) ping.size()) == (int) ping.size());
    clt.pump(c2s, s2c);

    std::string got;
    int rc = client_read(eng.e, got);
    CHECK(rc != TLS_ERR);
    CHECK(got == ping);

    const std::string pong = "pong under the new keys";
    REQUIRE(eng.e->write(eng.e, pong.data(), pong.size()) == (int) pong.size());
    clt.pump(c2s, s2c);

    std::string received;
    char buf[1024];
    int n;
    while ((n = SSL_read(clt.ssl, buf, sizeof(buf))) > 0) {
        received.append(buf, (size_t) n);
    }
    INFO("OpenSSL: " << ERR_error_string(ERR_peek_error(), nullptr));
    CHECK(SSL_get_error(clt.ssl, n) == SSL_ERROR_WANT_READ);
    CHECK(received == pong);
    CHECK(clt.key_updates_received == 1);
    // RFC 8446 4.6.3 puts the reply KeyUpdate before the next app record ("KA"); Schannel on Windows 11 26200
    // appends it after ("AK"). OpenSSL accepts both, so this only reports what the backend did
    WARN("KeyUpdate order, server engine: " << clt.received_order);
}

// A TLS 1.3 peer sends NewSessionTicket and KeyUpdate records after the handshake; Schannel
// hands them back as SEC_I_RENEGOTIATE and the engine has to process them in place, while app
// data waits behind a blocked write. The KeyUpdate asks for one in return. Schannel returns no
// reply token for it (seen on Windows 11 build 26200); it sends its own KeyUpdate from a later
// EncryptMessage, after the next app record, so the check is that one arrives at all.
TEST_CASE("tls engine TLS 1.3 post-handshake messages keep app data in order", "[crypto]") {
    struct ctx_guard {
        tls_context *c;
        ~ctx_guard() { if (c) c->free_ctx(c); }
    } clt_ctx{default_tls_context()};
    if (tls12_capped()) {
        SKIP("ZITI_TEST_TLS12=1: the TLS backend has no TLS 1.3 here");
    }
    int peer_certs = 0;
    clt_ctx.c->set_cert_verify(clt_ctx.c, count_peer_cert, &peer_certs);
    engine_guard clt{clt_ctx.c->new_engine(clt_ctx.c, "localhost")};
    REQUIRE(clt.e != nullptr);

    openssl_server srv;
    mem_pipe c2s, s2c;
    mem_endpoint clt_ep{&s2c, &c2s};
    clt.e->set_io(clt.e, &clt_ep, mem_read, mem_write);

    REQUIRE(srv.handshake(clt.e, c2s, s2c) == TLS_HS_COMPLETE);
    REQUIRE(SSL_version(srv.ssl) == TLS1_3_VERSION);
    const int verified = peer_certs;
    REQUIRE(verified > 0);

    // the client's first app data is encrypted but stuck behind a full socket. Schannel queues
    // the record and takes the data; OpenSSL keeps it too, but returns TLS_AGAIN and wants the
    // same write again
    clt_ep.block_writes = true;
    const std::string first = "first client record";
    const int w = clt.e->write(clt.e, first.data(), first.size());
    REQUIRE((w == (int) first.size() || w == TLS_AGAIN));
    // a write while the socket is still full has to be retried later, it is not an error
    CHECK(clt.e->write(clt.e, first.data(), first.size()) == TLS_AGAIN);

    // tickets (sent by OpenSSL after the handshake), then a KeyUpdate that wants a reply,
    // then app data under the new server keys
    REQUIRE(SSL_key_update(srv.ssl, SSL_KEY_UPDATE_REQUESTED) == 1);
    const std::string ping = "ping after key update";
    REQUIRE(SSL_write(srv.ssl, ping.data(), (int) ping.size()) == (int) ping.size());
    srv.pump(c2s, s2c);

    std::string got;
    int rc = client_read(clt.e, got);
    CHECK(rc != TLS_ERR);
    CHECK(got == ping);

    // the socket drains: the stuck record, new data, then Schannel's KeyUpdate
    clt_ep.block_writes = false;
    if (w == TLS_AGAIN) {
        REQUIRE(clt.e->write(clt.e, first.data(), first.size()) == (int) first.size());
    }
    const std::string second = "second client record";
    REQUIRE(clt.e->write(clt.e, second.data(), second.size()) == (int) second.size());
    srv.pump(c2s, s2c);

    std::string received;
    char buf[1024];
    int n;
    while ((n = SSL_read(srv.ssl, buf, sizeof(buf))) > 0) {
        received.append(buf, (size_t) n);
    }
    int err = SSL_get_error(srv.ssl, n);
    INFO("OpenSSL: " << ERR_error_string(ERR_peek_error(), nullptr));
    CHECK(err == SSL_ERROR_WANT_READ);
    CHECK(received == first + second);
    // the client answered the KeyUpdate: without the answer OpenSSL still decrypts the old-key records above
    CHECK(srv.key_updates_received == 1);
    // the stuck record came first; RFC 8446 puts the reply KeyUpdate before the second record ("AKA"), Schannel on
    // Windows 11 26200 after it ("AAK"). Reported, not checked
    WARN("KeyUpdate order, client engine: " << srv.received_order);
    // the post-handshake messages did not run the peer check again
    CHECK(peer_certs == verified);
}

// On TLS 1.2 Schannel also reports a HelloRequest as SEC_I_RENEGOTIATE. tlsuv does not support renegotiation: a
// second handshake would switch the session to a peer that is never verified. So no engine may start one. Schannel
// fails the read; OpenSSL (SSL_OP_NO_RENEGOTIATION) declines with a warning alert and keeps the session.
TEST_CASE("tls engine refuses a TLS 1.2 renegotiation", "[crypto]") {
    struct ctx_guard {
        tls_context *c;
        ~ctx_guard() { if (c) c->free_ctx(c); }
    } clt_ctx{default_tls_context()};
    int peer_certs = 0;
    clt_ctx.c->set_cert_verify(clt_ctx.c, count_peer_cert, &peer_certs);
    engine_guard clt{clt_ctx.c->new_engine(clt_ctx.c, "localhost")};
    REQUIRE(clt.e != nullptr);

    openssl_server srv(TLS1_2_VERSION);
    mem_pipe c2s, s2c;
    mem_endpoint clt_ep{&s2c, &c2s};
    clt.e->set_io(clt.e, &clt_ep, mem_read, mem_write);

    REQUIRE(srv.handshake(clt.e, c2s, s2c) == TLS_HS_COMPLETE);
    REQUIRE(SSL_version(srv.ssl) == TLS1_2_VERSION);
    const int verified = peer_certs;
    REQUIRE(verified > 0);

    // HelloRequest, then app data the client must not get past it
    REQUIRE(SSL_renegotiate(srv.ssl) == 1);
    SSL_do_handshake(srv.ssl);
    const std::string ping = "ping after hello request";
    SSL_write(srv.ssl, ping.data(), (int) ping.size());
    srv.pump(c2s, s2c);
    REQUIRE_FALSE(s2c.buf.empty());

    // Schannel fails the read; OpenSSL declines with a no_renegotiation warning alert and goes on
    std::string got;
    int rc = client_read(clt.e, got);
    CHECK((rc == TLS_ERR || got == ping));
    // no ClientHello went out: whatever the client sent is not a handshake record
    for (size_t p = 0; p + 5 <= c2s.buf.size();
         p += 5 + (((size_t) (uint8_t) c2s.buf[p + 3] << 8) | (uint8_t) c2s.buf[p + 4])) {
        CHECK((uint8_t) c2s.buf[p] != 0x16);
    }
    CHECK(peer_certs == verified);
}

// The same refusal one layer up, where the SDK enforces it whatever the backend does: an e2ee dialer whose
// host asks for a TLS 1.2 renegotiation gets no data past the request and the session ends.
TEST_CASE("e2ee-tls dialer refuses a TLS 1.2 renegotiation", "[crypto]") {
    struct ctx_guard {
        tls_context *c;
        ~ctx_guard() { if (c) c->free_ctx(c); }
    } clt_ctx{tls_with_ca(rsa_cert)};
    struct e2ee_guard {
        e2ee_t *e;
        ~e2ee_guard() { if (e) e->free(e); }
    } clt{create_e2ee(ziti_crypto_tls, false, clt_ctx.c)};
    REQUIRE(clt.e != nullptr);

    openssl_server srv(TLS1_2_VERSION);
    auto from_srv = [&srv]() {
        std::vector<uint8_t> b;
        uint8_t chunk[4096];
        int n;
        while ((n = BIO_read(srv.out, chunk, sizeof(chunk))) > 0) b.insert(b.end(), chunk, chunk + n);
        return b;
    };

    e2ee_pub_t hello = clt.e->pub(clt.e);
    BIO_write(srv.in, hello.key, (int) hello.key_len);
    SSL_do_handshake(srv.ssl);
    std::vector<uint8_t> srv_flight = from_srv();
    REQUIRE(clt.e->init(clt.e, srv_flight.data(), srv_flight.size(), false) == 0);

    std::vector<uint8_t> hdr(E2EE_MAX_HEADER_LEN);
    ssize_t hdr_len = clt.e->get_header(clt.e, hdr.data());
    REQUIRE(hdr_len > 0);
    BIO_write(srv.in, hdr.data(), (int) hdr_len);
    REQUIRE(SSL_do_handshake(srv.ssl) == 1);
    REQUIRE(SSL_version(srv.ssl) == TLS1_2_VERSION);
    std::vector<uint8_t> srv_final = from_srv();
    uint8_t pt[4096];
    REQUIRE(clt.e->decrypt(clt.e, srv_final.data(), srv_final.size(), pt, sizeof(pt)) == 0);
    REQUIRE(clt.e->ready(clt.e));

    // HelloRequest, then app data
    REQUIRE(SSL_renegotiate(srv.ssl) == 1);
    SSL_do_handshake(srv.ssl);
    const std::string ping = "ping after hello request";
    SSL_write(srv.ssl, ping.data(), (int) ping.size());
    std::vector<uint8_t> recs = from_srv();
    REQUIRE_FALSE(recs.empty());

    memset(pt, 0, sizeof(pt));
    CHECK(clt.e->decrypt(clt.e, recs.data(), recs.size(), pt, sizeof(pt)) == -1);
    CHECK(std::search(pt, pt + sizeof(pt), ping.begin(), ping.end()) == pt + sizeof(pt));
    CHECK_FALSE(clt.e->ready(clt.e));
    // no ClientHello for a second handshake
    CHECK(clt.e->get_header(clt.e, hdr.data()) == 0);
    uint8_t ct[256];
    CHECK(clt.e->encrypt(clt.e, (const uint8_t *) "x", 1, ct, sizeof(ct)) == -1);
}
#endif
