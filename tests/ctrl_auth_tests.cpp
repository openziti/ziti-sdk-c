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

// The tokens a controller client puts on its requests. Setting a header on a tlsuv client adds a value to
// the ones it has, it does not replace them, and the controller takes the first token of an external signer
// that it finds in the Authorization headers: a token set again has to replace the one before it, and
// nothing may go out twice.
//
// The client never runs: the address is from the RFC 5737 documentation range, and only the headers
// it would send are read.

#include "catch2_includes.hpp"

#include <algorithm>
#include <string>
#include <vector>

// stc/cstr.h declares _cstr_init as plain `extern`, which mangles under C++; common.h first, then cstr.h
// under C linkage, satisfies both (as in posture_tests.cpp). Needed to fill in a zt_jwt.
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}

#include "ziti_ctrl.h"
#include "utils.h"  // strcasecmp on Windows
#include <ziti/errors.h>
#include <tlsuv/tlsuv.h>

namespace {
    // one loop for every case, never run and never closed: see ctrl_endpoint_tests.cpp
    uv_loop_t *test_loop() {
        static uv_loop_t *loop = uv_loop_new();
        return loop;
    }

    class Client {
    public:
        explicit Client(bool legacy) {
            tls = default_tls_context();
            model_list urls = {};
            model_list_append(&urls, (void *) "https://203.0.113.1:1280");
            REQUIRE(ziti_ctrl_init(test_loop(), &ctrl, &urls, tls) == ZITI_OK);
            model_list_clear(&urls, nullptr);
            ziti_ctrl_set_legacy(&ctrl, legacy);
        }

        ~Client() {
            ziti_ctrl_close(&ctrl);
            tls->free_ctx(tls);
        }

        // the values of the headers called `name` that a request would carry, sorted: their order is tlsuv's
        std::vector<std::string> values(const char *name) {
            std::vector<std::string> result;
            tlsuv_http_hdr *h;
            LIST_FOREACH(h, &ctrl.client->headers, _next) {
                if (strcasecmp(h->name, name) == 0) {
                    result.emplace_back(h->value);
                }
            }
            std::sort(result.begin(), result.end());
            return result;
        }

        // the controller keeps its own copy: the jwt is gone when this returns
        void set_ext(const char *issuer, const char *token) {
            zt_jwt jwt{};
            jwt.issuer = cstr_from(issuer);
            jwt.encoded = cstr_from(token);
            ziti_ctrl_set_ext_token(&ctrl, &jwt);
            zt_jwt_drop(&jwt);
        }

        ziti_controller ctrl{};
        tls_context *tls{};
    };

    using Values = std::vector<std::string>;
}

TEST_CASE("controller-sends-the-latest-token-of-each-issuer", "[controller]") {
    Client c(false);

    ziti_ctrl_set_token(&c.ctrl, "session1");
    CHECK(c.values("Authorization") == Values{"Bearer session1"});

    c.set_ext("issuer-a", "a1");
    CHECK(c.values("Authorization") == Values{"Bearer a1", "Bearer session1"});

    // the token of that issuer is refreshed: the old one must not go out any more
    c.set_ext("issuer-a", "a2");
    CHECK(c.values("Authorization") == Values{"Bearer a2", "Bearer session1"});

    c.set_ext("issuer-b", "b1");
    CHECK(c.values("Authorization") == Values{"Bearer a2", "Bearer b1", "Bearer session1"});

    // a new api session token takes the place of the old one, and keeps the external tokens
    ziti_ctrl_set_token(&c.ctrl, "session2");
    CHECK(c.values("Authorization") == Values{"Bearer a2", "Bearer b1", "Bearer session2"});

    ziti_ctrl_clear_auth(&c.ctrl);
    CHECK(c.values("Authorization").empty());
    CHECK(c.values("zt-session").empty());
}

TEST_CASE("controller-sends-the-token-set-before-the-session", "[controller]") {
    Client c(false);

    c.set_ext("issuer-a", "a1");
    CHECK(c.values("Authorization") == Values{"Bearer a1"});

    ziti_ctrl_set_token(&c.ctrl, "session1");
    CHECK(c.values("Authorization") == Values{"Bearer a1", "Bearer session1"});
}

TEST_CASE("legacy-controller-sends-the-session-once-next-to-the-external-tokens", "[controller]") {
    Client c(true);

    ziti_ctrl_set_token(&c.ctrl, "session1");
    c.set_ext("issuer-a", "a1");
    c.set_ext("issuer-a", "a2");
    CHECK(c.values("zt-session") == Values{"session1"});
    CHECK(c.values("Authorization") == Values{"Bearer a2"});

    ziti_ctrl_set_token(&c.ctrl, "session2");
    CHECK(c.values("zt-session") == Values{"session2"});
    CHECK(c.values("Authorization") == Values{"Bearer a2"});

    ziti_ctrl_clear_auth(&c.ctrl);
    CHECK(c.values("zt-session").empty());
    CHECK(c.values("Authorization").empty());
}
