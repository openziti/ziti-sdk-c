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


// Fixtures and in-memory transport shared by the TLS engine tests and the win32crypto key tests.
#pragma once

#include <catch2/catch_all.hpp>

#include <tlsuv/tls_engine.h>

#include "crypto.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#if _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#endif

// RSA identity in PKCS#1 form, the way the ziti CLI enrolls by default. The
// self-signed cert is CN=localhost, EKU serverAuth + clientAuth. Its key id
// base64-encodes to "sgxT/vuuyAviWvuuZbkd5wVrKu8=", which has a '/'.
static const char *rsa_key = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsQnLQvgQZEWQa/Wdf5zCR6QtIPS28ZPDT8d+5gO+sCeaE66U
MmqWjoFsPJ/ANioQTqRHtsmXaTX7j+YXfg57I8AIRuveGjVO1Kx7541+heSM2VsY
Z7UmuGMShjEa8oaJjQVZxoOTakZpAvuk3FLd4bP3kFi4/7msiZ10tXwRDPjeSvle
QJlvCj90mPeR8YJX+3PfjLBm5iaH6iTkh4R65VMq/UtfMxLVXepSqZz0TtcLmmGt
wU5+tMHqwq3LJafBHbUDOI6XOrlOS7C1HvtPWJyXjRKbKvgAsA3g/T7Zhap+DJ+G
VpDhXEPdhFGXqZjJcu6Jfg/a9VobSP2CP69vRwIDAQABAoIBAC0DN3oMhmZoRYMd
jPEAU2lRteO2NLmRf0xOhdZHx3kUaJlufuGeti7/exyi5YUgBstn+4/fC69FeXOp
5fk4B1kcnz4hBHSXbzalsE88a5nxdVpiTf84UOL61Z/m5loZmOmRHbVaiOWxh0up
3c3jB+U2E9DQriDe/Z5zuVPXeqJYS8YVXV/KrV1YS5oSQALUrza2YFySQeXoAlRl
fJZOrLrJJWrgmCr9HL9jXax3XnLY8l3K3Y2O5+g4gjLmMgYi1KmDb7+afAHP7WZI
X1qrtDPPG0JhSuzFxQVL6aWp29LCIYqh2pANpdN13KLXYemGZ7eZdbOorS2p6R+h
8FgpplECgYEA6JsiKidUszTSr09axKCR2sUa6eR94qhT9+jONUkldMIAH9PYdj1P
pyzGGvBPSYLKOvUFyclSfU1466letYijfMeMvVvmMuD1GU42FQDaovZ5iaDvoWnL
VEPoBIPNypZR8en/yI3FoEMzGOddd8AZAGlv+YpQ9skwbtIFGYXzl28CgYEAwtf3
uINl3sEatzWE/M2aQPdlCLlJigAQKoItwbqcXpABwLnZXiCnFbnMB+pjg+THbkNK
en4Zguowq3g/oUrHWq9bB4wmbH0abEuLOTaN9H29fGx5TDllzDlAArR5r2FvX25z
mW+fJdti5i/H+V3nEdA3jFMVwiMsgPpfVCcDeakCgYAMnER45pL3+Dgn2vR/zni5
1I/F+GY+wIN04EE1sFaAgvgAwbpthptn48yFr1uND7MpCRmcO/bl5ipVFGSXEOZU
IHln1rCfN4TyL0RNVTOFPDmQlZIIPTURx3CvtfmVLxsYM2hzlgQN0TbW9cwibt6s
IAs7Cx2ik3u1tlsibBmtrwKBgQCBL+rKxyx7FnQdN3oWmEgHfUDbGOc+fa46URf/
lDhrpnXTECakd2fxSsCSGwGiiMUGQc2XDBbkK1zbxB4EVm15njzv8yfi1Mv5M9l6
tMZIbjp9zfpa5M+vKeJcKMdp1mOe1cAF4vGVizG2x8WCfJVhxTmfa9NIZkPyvI8K
X9e5CQKBgDrotzDBl5qd9pR73FYFQCfUbro+Ve+NhFLn9vUqUqknCNP8GE2gm52y
LSpWNnqkVD/vnVNzTRQX4UbmJgQT40qg/+bmlX22x0M0/+3b3uwQ4r6+q0tNR74v
b1psmjFkWcYibebp2RtwwO426tOQDfkFD7DcVpijQ6vhGtV7Yg/o
-----END RSA PRIVATE KEY-----
)";

static const char *rsa_cert = R"(-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUCB39GB6QgsWuEZFllze/CdOrVRowDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkzMDE2MjgxOVoYDzIxMjYw
OTA2MTYyODE5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCxCctC+BBkRZBr9Z1/nMJHpC0g9Lbxk8NPx37mA76w
J5oTrpQyapaOgWw8n8A2KhBOpEe2yZdpNfuP5hd+DnsjwAhG694aNU7UrHvnjX6F
5IzZWxhntSa4YxKGMRryhomNBVnGg5NqRmkC+6TcUt3hs/eQWLj/uayJnXS1fBEM
+N5K+V5AmW8KP3SY95Hxglf7c9+MsGbmJofqJOSHhHrlUyr9S18zEtVd6lKpnPRO
1wuaYa3BTn60werCrcslp8EdtQM4jpc6uU5LsLUe+09YnJeNEpsq+ACwDeD9PtmF
qn4Mn4ZWkOFcQ92EUZepmMly7ol+D9r1WhtI/YI/r29HAgMBAAGjdzB1MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjAUBgNVHREEDTALgglsb2NhbGhvc3QwHQYDVR0OBBYEFLIMU/77
rsgL4lr7rmW5HecFayrvMA0GCSqGSIb3DQEBCwUAA4IBAQA0xJr17IGEnoIzjC0S
h5VWLjvG1/ZrFMTwfIJAWpMW84KXNbyGVxTUkp3mS28zovmNX5KEi/+R4H1kUig7
EjtYkGfWUDxrHH2R//qgIIdsWtaVKzx8Z8Ph3ZxZMrY/cn2Jwp3sE61lO8Gl3Pq3
rHL7jPPRanZK82GZGAQ/yBCZxtvnFBKQkhIZqJ2fHQGC1bnsvh7EAnNLIuqKg316
uU7g65exZuLNJFKFEA70DnLxzotTrwOpNJ9D9LSSO+HIfeoygL+A54E6j70OZd4d
fV+mPToFKBDV7A3igJHJ6KbbnopIDIkBwQH99/PaatY0DlNebHV5EyRx0Om1WIuO
Y0eQ
-----END CERTIFICATE-----
)";

namespace {
struct mem_pipe {
    std::deque<char> buf;
};

struct mem_endpoint {
    mem_pipe *in;
    mem_pipe *out;
    // when set, keeps a copy of everything written
    std::vector<uint8_t> *tap = nullptr;
    // when set, writes fail the way a full non-blocking socket does
    bool block_writes = false;
};

ssize_t mem_read(io_ctx c, char *out, size_t len) {
    auto *p = static_cast<mem_endpoint *>(c)->in;
    if (p->buf.empty()) return TLS_AGAIN;

    size_t n = (std::min)(len, p->buf.size());
    std::copy_n(p->buf.begin(), n, out);
    p->buf.erase(p->buf.begin(), p->buf.begin() + (long) n);
    return (ssize_t) n;
}

ssize_t mem_write(io_ctx c, const char *in, size_t len) {
    auto *ep = static_cast<mem_endpoint *>(c);
    if (ep->block_writes) {
        // the io contract for a blocked write. no socket error is set, as with any io that is not a
        // Winsock socket, so an engine has to go by the return value
#if _WIN32
        SetLastError(ERROR_SUCCESS); // the slot WSAGetLastError() reads
#endif
        return TLS_AGAIN;
    }
    ep->out->buf.insert(ep->out->buf.end(), in, in + len);
    if (ep->tap) ep->tap->insert(ep->tap->end(), in, in + len);
    return (ssize_t) len;
}

// runs both engines until each completes or one fails
void run_handshake(tlsuv_engine_t clt, tlsuv_engine_t srv, tls_handshake_state &cs, tls_handshake_state &ss) {
    cs = TLS_HS_CONTINUE;
    ss = TLS_HS_CONTINUE;
    for (int i = 0; i < 100 && !(cs == TLS_HS_COMPLETE && ss == TLS_HS_COMPLETE); i++) {
        cs = clt->handshake(clt);
        ss = srv->handshake(srv);
        if (cs == TLS_HS_ERROR || ss == TLS_HS_ERROR) break;
    }
}

// counts the peer certs it is shown, and accepts them: the fixture is self-signed
int count_peer_cert(const struct tlsuv_certificate_s *, void *ctx) {
    (*static_cast<int *>(ctx))++;
    return 0;
}

// a context that trusts only `ca`, restricted in FIPS mode like the SDK's load_tls()
tls_context *tls_with_ca(const char *ca) {
    tls_context *tls = default_tls_context();
    tls_restrict_fips(tls);
    REQUIRE(tls->set_ca_bundle(tls, ca, strlen(ca)) == 0);
    return tls;
}

// stands in for a process without a loaded user profile, where every persisted key
// operation fails: the thread impersonates its own token with the user SID deny-only,
// so the user key store is denied
struct key_store_unreachable {
#if _WIN32
    HANDLE self = nullptr, restricted = nullptr, imp = nullptr;

    key_store_unreachable() {
        REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &self));
        BYTE user_buf[256];
        DWORD user_len = 0;
        REQUIRE(GetTokenInformation(self, TokenUser, user_buf, sizeof(user_buf), &user_len));
        // SYSTEM's key store stays reachable through a token that denies the SYSTEM SID
        if (IsWellKnownSid(reinterpret_cast<TOKEN_USER *>(user_buf)->User.Sid, WinLocalSystemSid)) {
            CloseHandle(self);
            self = nullptr;
            SKIP("the user key store cannot be denied to SYSTEM");
        }
        SID_AND_ATTRIBUTES deny = {reinterpret_cast<TOKEN_USER *>(user_buf)->User.Sid, 0};
        REQUIRE(CreateRestrictedToken(self, 0, 1, &deny, 0, nullptr, 0, nullptr, &restricted));
        REQUIRE(DuplicateToken(restricted, SecurityImpersonation, &imp));
        REQUIRE(SetThreadToken(nullptr, imp));
    }

    ~key_store_unreachable() {
        RevertToSelf();
        if (imp) CloseHandle(imp);
        if (restricted) CloseHandle(restricted);
        if (self) CloseHandle(self);
    }
#else
    key_store_unreachable() { FAIL("win32 only"); }
#endif
};

struct identity_ctx {
    tls_context *tls = nullptr;
    tlsuv_private_key_t key = nullptr;
    tlsuv_certificate_t cert = nullptr;
    int peer_certs = 0;

    identity_ctx() : tls(default_tls_context()) { tls_restrict_fips(tls); }

    ~identity_ctx() {
        if (tls) tls->free_ctx(tls);
        if (cert) cert->free(cert);
        if (key) key->free(key);
    }

    // verify_peer false leaves the context like ztx->e2ee_host_tls: no CA and no verify callback, so a host
    // does not ask for the dialer's certificate
    int load(bool key_store_reachable, bool verify_peer = true) {
        REQUIRE(tls->load_key(&key, rsa_key, strlen(rsa_key)) == 0);
        REQUIRE(tls->load_cert(&cert, rsa_cert, strlen(rsa_cert)) == 0);
        if (verify_peer) {
            tls->set_cert_verify(tls, count_peer_cert, &peer_certs);
        }
        if (key_store_reachable) {
            return tls->set_own_cert(tls, key, cert);
        }
        key_store_unreachable guard;
        return tls->set_own_cert(tls, key, cert);
    }
};

struct engine_guard {
    tlsuv_engine_t e;
    ~engine_guard() { if (e) e->free(e); }
};

// ZITI_TEST_TLS12=1: the TLS backend cannot negotiate TLS 1.3 here, because the OS predates it (Schannel below build
// 20348) or it is disabled (the Schannel registry, or an OpenSSL config cap; see the e2ee-tls TLS 1.2 test). Without
// it TLS 1.3 is required.
inline bool tls12_capped() {
    const char *tls12 = getenv("ZITI_TEST_TLS12");
    return tls12 != nullptr && strcmp(tls12, "1") == 0;
}
}

#if _WIN32
// set_own_cert persists the key into the user key store, named by the base64 of the cert's
// key id, the same way tlsuv derives it
static std::wstring persisted_key_name() {
    std::wstring name;
    DWORD der_len = 0;
    if (!CryptStringToBinaryA(rsa_cert, 0, CRYPT_STRING_BASE64HEADER, nullptr, &der_len, nullptr, nullptr)) {
        return name;
    }
    std::vector<BYTE> der(der_len);
    CryptStringToBinaryA(rsa_cert, 0, CRYPT_STRING_BASE64HEADER, der.data(), &der_len, nullptr, nullptr);
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, der.data(), der_len);
    if (cert == nullptr) return name;

    BYTE kid[64] = {};
    DWORD kid_len = sizeof(kid);
    DWORD len = 0;
    if (CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, kid, &kid_len) &&
        CryptBinaryToStringW(kid, kid_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len)) {
        name.resize(len);
        CryptBinaryToStringW(kid, kid_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, name.data(), &len);
        name.resize(len);
    }
    CertFreeCertificateContext(cert);
    return name;
}

static SECURITY_STATUS open_persisted_key(const wchar_t *name, NCRYPT_PROV_HANDLE *prov, NCRYPT_KEY_HANDLE *key) {
    SECURITY_STATUS rc = NCryptOpenStorageProvider(prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (rc != ERROR_SUCCESS) return rc;
    rc = NCryptOpenKey(*prov, key, name, 0, NCRYPT_SILENT_FLAG);
    if (rc != ERROR_SUCCESS) {
        NCryptFreeObject(*prov);
        *prov = 0;
    }
    return rc;
}

struct persisted_key_cleanup {
    ~persisted_key_cleanup() {
        std::wstring name = persisted_key_name();
        NCRYPT_PROV_HANDLE prov = 0;
        NCRYPT_KEY_HANDLE key = 0;
        if (!name.empty() && open_persisted_key(name.c_str(), &prov, &key) == ERROR_SUCCESS) {
            NCryptDeleteKey(key, 0); // frees the key handle
            NCryptFreeObject(prov);
        }
    }
};
#else
// only win32crypto persists identity keys
struct persisted_key_cleanup {
};
#endif
