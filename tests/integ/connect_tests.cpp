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
#include "test-data.h"

TEST_CASE_METHOD(LoopTestCase, "connect", "[connection]") {
    ziti_log_init(loop(), 5, nullptr);
    ziti_config cfg{};
    ziti_context ztx{};
    DEFER {
        ziti_shutdown(ztx);
        free_ziti_config(&cfg);
    };

    auto config = TEST_CLIENT;
    INFO("config file: " << config);
    REQUIRE(ziti_load_config(&cfg, TEST_CLIENT) == ZITI_OK);
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);
    struct capture {
        bool loaded;
        bool shutdown;
        int connect_error;
        bool connected;
        bool closed;
        uv_loop_t *loop;
    } c{.loop = loop()};
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
                if (ev->ctx.ctrl_status == ZITI_DISABLED) {
                    capt->shutdown = true;
                    ZITI_LOG(INFO, "context shutdown");
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

    ziti_dial(conn, "test-service",
              [](ziti_connection conn, int status) {
                auto capt = (capture*)ziti_conn_data(conn);
                capt->connect_error = status;
                if (status == ZITI_OK) {
                    capt->connected = true;
                    printf("ZITI_CONNECTION_READY\n");
                    fflush(stdout);
                }
              },
              [](ziti_connection conn, const uint8_t * data, ssize_t len) {
                auto capt = (capture*)ziti_conn_data(conn);
                return len;
              });

    run(UNTIL(c.connected || c.connect_error != 0));
    CHECK(c.connect_error == ZITI_OK);
    CHECK(c.connected);

    ziti_close(conn, [](ziti_connection conn){
      auto capt = (capture*)ziti_conn_data(conn);
      capt->closed = true;
      printf("ZITI_CONNECTION_CLOSED\n");
      fflush(stdout);
    });
    run(UNTIL(c.closed));
//    ZITI_LOG(INFO, "initiating context shutdown");
//    ziti_shutdown(ztx);
//    ZITI_LOG(INFO, "waiting for context shutdown");
//    run(UNTIL(c.shutdown));
}

TEST_CASE("defer", "[defer]") {

    ziti_config cfg{};
    DEFER {
        fprintf(stderr, "freeing config\n");
        free_ziti_config(&cfg);
    };

    DEFER {
        fprintf(stderr, "defer 2\n");
    };

    DEFER {
        fprintf(stderr, "defer 3\n");
    };

    ziti_load_config(&cfg, "/Users/eugene/work/mm/mm.json");
    REQUIRE(cfg.controller_url != nullptr);
}