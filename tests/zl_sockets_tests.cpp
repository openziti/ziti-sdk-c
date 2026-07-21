// Copyright (c) 2026. NetFoundry Inc.
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

// Tests that the zitilib socket bridge preserves the blocking mode of the caller's socket.
// connect_socket() (shared by Ziti_bind and Ziti_connect) sets the caller's fd non-blocking for its
// internal loopback connect and restores the original flags afterward. It uses only a local loopback
// listen/connect/accept -- no controller -- so this is a plain unit test.

#include <catch2/catch_all.hpp>
#include <ziti/zitilib.h>

#ifdef _WIN32
#include <winsock2.h>
#define close(s) closesocket(s)
#else
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#endif

// internal zitilib helpers (declared in library/zitilib/zl.h). Forward-declared here to avoid
// pulling in that internal header's transitive dependencies.
extern "C" {
    int connect_socket(int af, ziti_socket_t clt_sock, ziti_socket_t *ziti_sock);
    bool zl_is_blocking(ziti_socket_t s);
}

namespace {
    ziti_socket_t make_tcp(bool blocking) {
        ziti_socket_t s = socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(s != SOCKET_ERROR);
#ifdef _WIN32
        u_long nb = blocking ? 0 : 1;
        REQUIRE(ioctlsocket(s, FIONBIO, &nb) == 0);
#else
        int fl = fcntl(s, F_GETFL, 0);
        REQUIRE(fl != -1);
        REQUIRE(fcntl(s, F_SETFL, blocking ? (fl & ~O_NONBLOCK) : (fl | O_NONBLOCK)) == 0);
#endif
        return s;
    }
}

// A blocking caller socket -- the common case for ordinary socket code over the bridge -- must
// remain blocking after connect_socket() returns.
TEST_CASE("zitilib bridge preserves a blocking caller socket", "[zl-sockets]") {
#ifdef _WIN32
    WSADATA wsa;
    REQUIRE(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#endif
    ziti_socket_t s = make_tcp(/*blocking=*/true);
    REQUIRE(zl_is_blocking(s));

    ziti_socket_t ziti_fd = SOCKET_ERROR;
    int rc = connect_socket(AF_INET, s, &ziti_fd);
    INFO("connect_socket rc=" << rc);
    REQUIRE(rc == 0);

    CHECK(zl_is_blocking(s));   // caller socket must remain blocking

    close(s);
    if (ziti_fd != SOCKET_ERROR) close(ziti_fd);
}

#ifndef _WIN32
// A socket the caller deliberately made non-blocking must stay non-blocking.
// unix only: Win32 has no reliable non-blocking query, and its bridge branch forces blocking.
TEST_CASE("zitilib bridge preserves a non-blocking caller socket", "[zl-sockets]") {
    ziti_socket_t s = make_tcp(/*blocking=*/false);
    REQUIRE_FALSE(zl_is_blocking(s));

    ziti_socket_t ziti_fd = SOCKET_ERROR;
    int rc = connect_socket(AF_INET, s, &ziti_fd);
    INFO("connect_socket rc=" << rc);
    REQUIRE(rc == 0);

    CHECK_FALSE(zl_is_blocking(s));

    close(s);
    if (ziti_fd != SOCKET_ERROR) close(ziti_fd);
}
#endif
