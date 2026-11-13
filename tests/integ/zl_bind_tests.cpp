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

// Ziti_bind (library/zitilib/zl_bind.c) against a real controller and router.
//
// The SDK keeps the server connection of a bind that failed, and goes on reporting to the callbacks of zitilib (with
// the socket of zitilib as their data), until the application closes it. zitilib frees that socket when the bind fails,
// so it has to close the connection with it.

#include <catch2/catch_all.hpp>

#include "fixtures.h"
#include <ziti/zitilib.h>

#ifdef _WIN32
#include <WinSock2.h>
#define close(s) closesocket(s)
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

extern "C" int zl_test_open_server_conns(ziti_handle_t handle); // zl_bind_helper.c

// `test_client` can dial `test_service` but not bind it, so the bind is turned down. Nothing is left of it: the context
// has no server connection that was not closed.
TEST_CASE_METHOD(ZitilibTestCase, "zitilib: a bind that is turned down leaves no server connection", "[zl-bind]") {
    auto srv = checkENV("test_service");
    auto cfg = checkENV("test_client");

    auto ztx = loadContext(cfg);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);
    REQUIRE(zl_test_open_server_conns(ztx) == 0);

    ziti_socket_t server = Ziti_socket(SOCK_STREAM);
    REQUIRE(server != (ziti_socket_t) -1);
    DEFER {
        close(server);
    };

    CHECK(Ziti_bind(server, ztx, srv, nullptr) == -1);
    CHECK(zl_test_open_server_conns(ztx) == 0);
}
