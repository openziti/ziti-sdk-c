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
    int connect_error{};
    bool connected{};

    std::vector<std::vector<uint8_t>> received;
    bool eof{};
    int read_error{};

    bool closed{};
};

class ZitiConnectTestCase : public ZitiTestCase {
  protected:
    ZitiConnectTestCase() {
        REQUIRE_ZITI_OK(load());
    }
    void run_connect_test(const char *service, const ziti_dial_opts *dialOpts);
};

TEST_CASE_METHOD(ZitiConnectTestCase, "connect with intercept", "[connection]") {

    ziti_dial_opts dialOpts{};
    ziti_intercept_cfg_v1 intercept_cfg{};
    DEFER {
        ziti_dial_opts_free(&dialOpts);
        free_ziti_intercept_cfg_v1(&intercept_cfg);
    };

    auto srv = ensureService();
    REQUIRE(ziti_service_get_config(srv, ZITI_INTERCEPT_CFG_V1,
                                    (void*)&intercept_cfg, (parse_service_cfg_f)parse_ziti_intercept_cfg_v1) == ZITI_OK);
    auto addr = (ziti_address*)model_list_head(&intercept_cfg.addresses);
    auto ports = (ziti_port_range*)model_list_head(&intercept_cfg.port_ranges);
    REQUIRE(addr);
    REQUIRE(addr->type == ziti_address_hostname);
    REQUIRE(ports);

    INFO("hostname: " << addr->addr.hostname);
    INFO("ports: " << ports->low << "-" << ports->high);

    auto s = ziti_dial_opts_for_addr(&dialOpts, ztx,
                                     ziti_protocols.tcp, addr->addr.hostname, (int)ports->low, nullptr, 0);

    REQUIRE(s);
    CHECK(s == srv);
    run_connect_test(s->name, &dialOpts);
}

TEST_CASE_METHOD(ZitiConnectTestCase, "connect", "[connection]") {
    auto service = ensureService();
    run_connect_test(service->name, nullptr);
}

void ZitiConnectTestCase::run_connect_test(const char *service, const ziti_dial_opts *dialOpts) {
    capture c{};
    ziti_connection conn{};
    ziti_conn_init(ztx, &conn, &c);
    REQUIRE(conn);

    INFO("dialing service: " << service);
    DEFER {
            int r = ziti_close(conn, [](ziti_connection conn){
              auto capt = (capture*)ziti_conn_data(conn);
              capt->closed = true;
            });
            CHECK_ZITI_OK(r);
            if (r == ZITI_OK) {
                run(UNTIL(c.closed));
            }
    };

    auto dial_rc = ziti_dial_with_options(conn, service, dialOpts,
                                          [](ziti_connection conn, int status) {
                                            auto capt = (capture*)ziti_conn_data(conn);
                                            capt->connect_error = status;
                                            if (status == ZITI_OK) {
                                                capt->connected = true;
                                                ZITI_LOG(INFO, "connection ready");
                                            }
                                          },
                                          nullptr);
    CHECK_ZITI_OK(dial_rc);
    CHECK(run(UNTIL(c.connected || c.connect_error != 0)));

    CHECK_ZITI_OK(c.connect_error);
    REQUIRE(c.connected);

    ziti_conn_set_data_cb(conn,
                          [](ziti_connection conn, const uint8_t * data, ssize_t len) {
                            auto capt = (capture*)ziti_conn_data(conn);
                            ZITI_LOG(INFO, "received data: %ld bytes", (long)len);
                            if (len == ZITI_EOF) {
                                capt->eof = true;
                            } else if (len < 0) {
                                capt->read_error = (int)len;
                            } else {
                                capt->received.emplace_back(data, data + len);
                            }
                            return len;
                          });

    CHECK_ZITI_OK(ziti_write(conn, (uint8_t*)"hello", 5, nullptr, nullptr));
    CHECK(run(WHILE(c.received.empty() && c.read_error == 0 && !c.eof)));
    CHECK_ZITI_OK(c.read_error);
    CHECK(!c.eof);
    REQUIRE(c.received.size() == 1);
    CHECK(c.received[0].size() == 5);
    CHECK(memcmp(c.received[0].data(), "hello", 5) == 0);
}
