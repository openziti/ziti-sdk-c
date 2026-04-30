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

#include <tlsuv/tlsuv.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>

#include "fixtures.h"

struct capture {
    bool loaded{};
    int connect_error{};
    bool connected{};

    std::vector<std::vector<uint8_t>> received;
    bool eof{};
    int read_error{};

    bool closed{};
    uv_loop_t *loop{nullptr};
};

TEST_CASE_METHOD(ZitiTestCase, "connect", "[connection]") {
    auto config = test_client();
    auto service = test_service();
    if(!config || !service) {
        SKIP("test_client and test_service environment variables must be set to run this test");
    }

    ziti_config cfg{};
    ziti_context ztx{};
    DEFER {
        ziti_shutdown(ztx);
        free_ziti_config(&cfg);
    };

    INFO("config file: " << config);
    REQUIRE(ziti_load_config(&cfg, config) == ZITI_OK);
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);
    capture c{.loop = loop()};
    const ziti_options opts {
        .app_ctx = &c,
        .events = ZitiContextEvent,
        .event_cb = [](ziti_context ztx, const ziti_event_t *ev) {
            auto capt = (capture*)ziti_app_ctx(ztx);
            if (ev->type == ZitiContextEvent) {
                if (ev->ctx.ctrl_status == ZITI_OK) {
                    capt->loaded = true;
                    printf("ZITI_CONTEXT_READY\n");
                    fflush(stdout);
                }
            }
        },
    };
    REQUIRE(ziti_context_set_options(ztx, &opts) == ZITI_OK);
    REQUIRE(ziti_context_run(ztx, loop()) == ZITI_OK);
    REQUIRE(run(UNTIL(c.loaded)));

    ziti_connection conn{};
    ziti_conn_init(ztx, &conn, &c);
    INFO("dialing service: " << service);

    CHECK(ZITI_OK == ziti_dial(conn, service,
                               [](ziti_connection conn, int status) {
                                 auto capt = (capture*)ziti_conn_data(conn);
                                 capt->connect_error = status;
                                 if (status == ZITI_OK) {
                                     capt->connected = true;
                                     ZITI_LOG(INFO, "connection ready");
                                 }
                               },
                               [](ziti_connection conn, const uint8_t * data, ssize_t len) {
                                 auto capt = (capture*)ziti_conn_data(conn);
                                 if (len == ZITI_EOF) {
                                     capt->eof = true;
                                 } else if (len < 0) {
                                     capt->read_error = len;
                                 } else {
                                     capt->received.emplace_back(data, data + len);
                                 }
                                 return len;
              }));

    CHECK(run(UNTIL(c.connected || c.connect_error != 0)));
    CHECK(c.connect_error == ZITI_OK);
    CHECK(c.connected);

    CHECK(ziti_write(conn, (uint8_t*)"hello", 5, nullptr, nullptr) == ZITI_OK);
    CHECK(run(UNTIL(!c.received.empty() || c.read_error != 0 || c.eof)));
    CHECK(c.read_error == 0);
    CHECK(!c.eof);
    CHECK(c.received.size() == 1);
    CHECK(c.received[0].size() == 5);
    CHECK(memcmp(c.received[0].data(), "hello", 5) == 0);

    ziti_close(conn, [](ziti_connection conn){
      auto capt = (capture*)ziti_conn_data(conn);
      capt->closed = true;
      printf("ZITI_CONNECTION_CLOSED\n");
      fflush(stdout);
    });
    CHECK(run(UNTIL(c.closed)));
}
