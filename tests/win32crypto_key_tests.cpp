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


// win32crypto identity keys: load_tls fails cleanly when the CNG user key store is out of reach.

#include "tls_test_util.h"

#include "credentials.h"
#include "ziti/errors.h"

TEST_CASE("load_tls reports a key the win32crypto key store cannot persist", "[crypto]") {
    persisted_key_cleanup cleanup;
    identity_ctx probe;
    if (strstr(probe.tls->version(), "win32crypto") == nullptr) {
        SKIP("not a win32crypto build: " << probe.tls->version());
    }

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

