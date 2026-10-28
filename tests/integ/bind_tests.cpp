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

#include <ziti/ziti.h>
#include <ziti/ziti_log.h>

#include "fixtures.h"

// The context runs as the identity that can bind the test service.
class ZitiBindTestCase : public ZitiTestCase {
  protected:
    ZitiBindTestCase() {
        REQUIRE_ZITI_OK(load());
    }

    // Has the context listen on `service` and closes the listener `close_after_ms` later, whatever it has
    // got to by then (looking its service up, getting its session and routers, binding to an edge router).
    // Then lets the answers to what it asked of the controller and of the edge routers come in.
    void close_listener_while_establishing(const char *service, int close_after_ms);
};

// An app can close a listener that is still being established. The answers to what the listener asked
// of the controller and of the edge routers come after that, and have to find it still there (an ASAN
// build reports it when they do not).

TEST_CASE_METHOD(ZitiBindTestCase, "a listener closed while its session and routers are requested", "[bind]") {
    // the context has not listened on the service: the listener asks the controller for its session and routers
    ensureService();
    close_listener_while_establishing(test_service(), 0);
}

TEST_CASE_METHOD(ZitiBindTestCase, "a listener closed while its service is looked up", "[bind]") {
    // the context does not know the service: the listener asks the controller for it
    close_listener_while_establishing("no-such-service", 0);
}

TEST_CASE_METHOD(ZitiBindTestCase, "a listener closed at any point while it is being established", "[bind]") {
    for (int after_ms = 0; after_ms < 40; after_ms += 2) {
        close_listener_while_establishing(test_service(), after_ms);
    }
}

void ZitiBindTestCase::close_listener_while_establishing(const char *service, int close_after_ms) {
    struct listener_ctx_s {
        bool closed{};
    } l;
    ziti_connection srv{};
    REQUIRE_ZITI_OK(ziti_conn_init(ztx, &srv, &l));

    INFO("listening on service: " << service << ", closing after " << close_after_ms << " ms");
    REQUIRE_ZITI_OK(ziti_listen(srv, service,
                                [](ziti_connection, int) {},
                                [](ziti_connection, ziti_connection, int, const ziti_client_ctx *) {}));
    run(UNTIL(false), close_after_ms);

    REQUIRE_ZITI_OK(ziti_close(srv, [](ziti_connection c) {
        static_cast<listener_ctx_s *>(ziti_conn_data(c))->closed = true;
    }));
    CHECK(run(UNTIL(l.closed)));

    // the answers to the requests of the listener
    run(UNTIL(false), 200);
}
