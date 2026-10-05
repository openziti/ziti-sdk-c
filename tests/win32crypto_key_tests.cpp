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


// win32crypto identity keys: persisting them into the CNG user key store, and failing cleanly when it is out of reach.

#include "tls_test_util.h"

#include "credentials.h"
#include "ziti/errors.h"

TEST_CASE("win32crypto set_own_cert with RSA PKCS#1 key", "[crypto]") {
#if _WIN32
    persisted_key_cleanup cleanup;
#endif
    identity_ctx srv;
    if (strstr(srv.tls->version(), "win32crypto") == nullptr) {
        SKIP("not a win32crypto build: " << srv.tls->version());
    }

    SECTION("user key store unreachable") {
        // fails cleanly: Schannel has no use for a key that is not persisted
        CHECK(srv.load(false) == -1);
    }

    SECTION("load_tls reports the key/cert failure") {
        std::string key_ref = std::string("pem:") + rsa_key;
        std::string cert_ref = std::string("pem:") + rsa_cert;
        ziti_config cfg{};
        cfg.id.key = const_cast<char *>(key_ref.c_str());
        cfg.id.cert = const_cast<char *>(cert_ref.c_str());

        tls_context *tls = nullptr;
        zt_x509 creds{};
        int rc;
        {
            key_store_unreachable guard;
            rc = load_tls(&cfg, &tls, &creds);
        }
        CHECK(rc == ZITI_INVALID_CERT_KEY_PAIR);
        CHECK(tls == nullptr);
        CHECK(creds.key == nullptr);
        CHECK(creds.cert == nullptr);
        if (tls) tls->free_ctx(tls);
        zt_x509_drop(&creds);
    }

#if _WIN32
    SECTION("the key is persisted under its key id") {
        REQUIRE(srv.load(true) == 0);

        std::wstring name = persisted_key_name();
        REQUIRE_FALSE(name.empty());
        NCRYPT_PROV_HANDLE prov = 0;
        NCRYPT_KEY_HANDLE key = 0;
        CHECK(open_persisted_key(name.c_str(), &prov, &key) == ERROR_SUCCESS);
        if (key) NCryptFreeObject(key);
        if (prov) NCryptFreeObject(prov);
    }
#endif

    SECTION("mutual TLS handshake") {
        // both sides on the RSA identity: Schannel signs with the key on each side
        REQUIRE(srv.load(true) == 0);
        identity_ctx clt;
        REQUIRE(clt.load(true) == 0);

        engine_guard srv_eng{srv.tls->new_server_engine(srv.tls)};
        engine_guard clt_eng{clt.tls->new_engine(clt.tls, "localhost")};
        REQUIRE(srv_eng.e != nullptr);
        REQUIRE(clt_eng.e != nullptr);

        mem_pipe c2s, s2c;
        mem_endpoint clt_ep{&s2c, &c2s};
        mem_endpoint srv_ep{&c2s, &s2c};
        clt_eng.e->set_io(clt_eng.e, &clt_ep, mem_read, mem_write);
        srv_eng.e->set_io(srv_eng.e, &srv_ep, mem_read, mem_write);

        tls_handshake_state cs = TLS_HS_CONTINUE, ss = TLS_HS_CONTINUE;
        for (int i = 0; i < 100 && !(cs == TLS_HS_COMPLETE && ss == TLS_HS_COMPLETE); i++) {
            cs = clt_eng.e->handshake(clt_eng.e);
            ss = srv_eng.e->handshake(srv_eng.e);
            if (cs == TLS_HS_ERROR || ss == TLS_HS_ERROR) break;
        }
        CHECK(cs == TLS_HS_COMPLETE);
        CHECK(ss == TLS_HS_COMPLETE);
        CHECK(clt.peer_certs > 0);
        CHECK(srv.peer_certs > 0);
    }
}
