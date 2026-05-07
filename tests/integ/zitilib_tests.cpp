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

//
//

#include <catch2/catch_all.hpp>

#include "fixtures.h"
#include <ziti/zitilib.h>

#include <functional>

#ifdef _WIN32
#include <WinSock2.h>
#define close(s) closesocket(s)
#define poll(f,d,t) WSAPoll(f,d,t)
#else
#include <poll.h>
#endif

static inline void checkPollErr(pollfd& fd) {
    INFO("poll events[" << std::hex << fd.revents << "]");
    if (fd.revents & POLLNVAL) {
        FAIL("invalid fd: " << fd.fd);
    }

    if (fd.revents & POLLERR) {
        int err = 0;
        socklen_t err_len = sizeof(err);
        if (getsockopt(fd.fd, SOL_SOCKET, SO_ERROR, (char*)&err, &err_len) == 0) {
            FAIL("socket error: " << strerror(err));
        } else {
            FAIL("getsockopt error: " << strerror(errno));
        }
    }
}

class ZitilibTestCase {
  protected:
    ZitilibTestCase() {
        ZITI_LOG(INFO, "starting test case: %s", Catch::getResultCapture().getCurrentTestName().c_str());
        Ziti_lib_init();
    }
    ~ZitilibTestCase() {
        Ziti_lib_shutdown();
        ZITI_LOG(INFO, "finished test case: %s", Catch::getResultCapture().getCurrentTestName().c_str());
    }
};

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: init", "[zitilib]") {
    auto error = Ziti_last_error();
    INFO("error: " << error << ": " << ziti_errorstr(error));
    REQUIRE(error == ZITI_OK);
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load context", "[zitilib]") {
    auto params = GENERATE(
        std::pair((const char*)nullptr, ZITI_INVALID_CONFIG),
        std::pair("invalid", ZITI_CONFIG_NOT_FOUND),
        std::pair(getenv("test_client"), ZITI_OK)
        );

    WHEN("context: " << (params.first ? params.first : "(null)")) {
        ziti_handle_t ztx{};
        auto error = Ziti_load_context(&ztx, params.first);
        INFO("error[" << (params.first ? params.first : "(null)") << "]: " << error << "/" << ziti_errorstr(error));
        CHECK(error == params.second);
        CHECK(Ziti_last_error() == params.second);
        if (params.second == ZITI_OK) {
            CHECK(ztx != ZITI_INVALID_HANDLE);
        } else {
            CHECK(ztx == ZITI_INVALID_HANDLE);
        }
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load after shutdown", "[zitilib]") {
    Ziti_lib_shutdown();
    ziti_handle_t ztx{};
    auto cfg = getenv("test_client");
    WHEN("with timeout") {
        auto error = Ziti_load_context_with_timeout(&ztx, cfg, 1000);
        INFO("error: " << error << "/" << ziti_errorstr(error));
        CHECK(error == ZITI_INVALID_STATE);
        CHECK(Ziti_last_error() == ZITI_INVALID_STATE);
    }
    WHEN("without timeout") {
        auto error = Ziti_load_context(&ztx, cfg);
        INFO("error: " << error << "/" << ziti_errorstr(error));
        CHECK(error == ZITI_INVALID_STATE);
        CHECK(Ziti_last_error() == ZITI_INVALID_STATE);
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load context with timeout", "[zitilib]") {
    auto params = GENERATE(
        std::tuple((const char*)nullptr, -1, ZITI_INVALID_CONFIG),
        std::tuple("invalid", -1, ZITI_CONFIG_NOT_FOUND),
        std::tuple(getenv("test_client"), 2000, ZITI_OK),
        std::tuple(getenv("test_client"), 1, ZITI_TIMEOUT)
        );

    WHEN("context[" << (std::get<0>(params) ? std::get<0>(params) : "(null)")
                    << "] with timeout[" << std::get<1>(params) << "]") {
        ziti_handle_t ztx{};
        auto error = Ziti_load_context_with_timeout(&ztx, std::get<0>(params), std::get<1>(params));
        INFO("error: " << error << "/" << ziti_errorstr(error));
        CHECK(error == std::get<2>(params));
        CHECK(Ziti_last_error() == std::get<2>(params));
        if (std::get<2>(params) == ZITI_OK) {
            CHECK(ztx != ZITI_INVALID_HANDLE);
        } else {
            CHECK(ztx == ZITI_INVALID_HANDLE);
        }
    }
}

static void set_blocking (ziti_socket_t sock, bool blocking) {
#if _WIN32
    u_long opt = blocking ? 0 : 1;
    REQUIRE(ioctlsocket(sock, FIONBIO, &opt) == 0);
#else
    int opt = fcntl(sock, F_GETFL);
    REQUIRE(opt != -1);
    if (blocking) {
        opt &= ~O_NONBLOCK;
    } else {
        opt |= O_NONBLOCK;
    }
    REQUIRE(fcntl(sock, F_SETFL, opt) == 0);
#endif
}

static void checkSocketSync(ziti_socket_t sock, const std::function<int(ziti_socket_t)> &connect_fn) {
    auto conn_rc = connect_fn(sock);
    auto err = errno;
    auto ze = Ziti_last_error();
    INFO("error: " << ze << "/" << ziti_errorstr(ze) << " errno: " << err << "/" << strerror(err));
    REQUIRE(conn_rc == 0);
    CHECK(ze == ZITI_OK);

    auto send_rc = send(sock, "hello", 5, 0);
    auto send_err = send_rc == -1 ?  errno : 0;
    INFO("send error: " << send_err << "/" << strerror(send_err));
    REQUIRE(send_rc == 5);

    char buf[16];
    auto read_rc = read(sock, buf, sizeof(buf));
    auto read_err = read_rc == -1 ? errno : 0;
    INFO("recv error: " << read_err << "/" << strerror(read_err));
    REQUIRE(read_rc == 5);
    CHECK(std::string(buf, buf + read_rc) == "hello");
}

static void checkSocketAsync(ziti_socket_t sock, const std::function<int(ziti_socket_t)> &connect_fn) {
    int sock_type = 0;
    socklen_t sock_type_len = sizeof(sock_type);
    REQUIRE(getsockopt(sock, SOL_SOCKET, SO_TYPE, (void*)&sock_type, &sock_type_len) == 0);

    auto conn_rc = connect_fn(sock);
    if (conn_rc == -1) {
        REQUIRE(sock_type == SOCK_STREAM); // UDP should connect immediately
        auto err = errno;
        auto ze = Ziti_last_error();
        INFO("error: " << ze << "/" << ziti_errorstr(ze) << " errno: " << err << "/" << strerror(err));
        CHECK(ze == ZITI_OK);
        REQUIRE((err == EINPROGRESS || err == EWOULDBLOCK));
        pollfd p = {
            .fd = sock,
            .events = POLLOUT,
        };
        REQUIRE(poll(&p, 1, 5000) == 1);
        checkPollErr(p);
        REQUIRE((p.revents & POLLOUT) > 0);
    } else if (conn_rc == 0) {
        INFO("connect completed immediately");
        auto ze = Ziti_last_error();
        INFO("error: " << ze << "/" << ziti_errorstr(ze));
        CHECK(ze == ZITI_OK);
    } else {
        FAIL("unexpected return code: " << conn_rc);
    }

    auto send_rc = send(sock, "hello", 5, 0);
    auto send_err = send_rc == -1 ?  errno : 0;
    INFO("send error: " << send_err << "/" << strerror(send_err));
    REQUIRE(send_rc == 5);

    char buf[16];
    auto read_rc = recv(sock, buf, sizeof(buf), 0);
    if (read_rc == -1) { // this is expected in non-blocking mode
        auto read_err = errno;
        INFO("recv error: " << read_err << "/" << strerror(read_err));
        REQUIRE((read_err == EWOULDBLOCK || read_err == EAGAIN));
        INFO("data not available immediately, waiting for it...");

        INFO("polling socket " << sock);
        pollfd p = {
            .fd = sock,
            .events = POLLIN
        };
        REQUIRE(poll(&p, 1, 5000) == 1);
        checkPollErr(p);
        REQUIRE((p.revents & POLLIN) > 0);

        read_rc = recv(sock, buf, sizeof(buf), 0);
    }
    REQUIRE(read_rc == 5);
    CHECK(std::string(buf, buf + read_rc) == "hello");
}

static inline void checkSocket(ziti_socket_t sock, bool block, const std::function<int(ziti_socket_t)> &connect_fn) {
    if (block) {
        checkSocketSync(sock, connect_fn);
    } else {
        checkSocketAsync(sock, connect_fn);
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect service", "[zitilib]") {
    auto srv = getenv("test_service");
    if (srv == nullptr) {
        SKIP("'test_service' is not set");
    }

    ziti_handle_t ztx{};
    auto error = Ziti_load_context(&ztx, getenv("test_client"));
    REQUIRE(error == ZITI_OK);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);
    REQUIRE(Ziti_last_error() == ZITI_OK);
    auto bl = GENERATE(true, false);
    auto sock_type = GENERATE(SOCK_STREAM, SOCK_DGRAM);
    auto sock_af = GENERATE(AF_INET, AF_INET6);

    WHEN((bl ? "blocking" : "async")
         << "/" << (sock_type == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM")
         << "/" << (sock_af == AF_INET ? "AF_INET" : "AF_INET6")) {
        auto sock = socket(sock_af, sock_type, 0);
        INFO("socket error: " << errno << "/" << strerror(errno));
        REQUIRE(sock != -1);
        DEFER {
            close(sock);
        };

        set_blocking(sock, bl);
        checkSocket(sock, bl, [&](ziti_socket_t s) {
          return Ziti_connect(s, ztx, srv, nullptr);
        });
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect invalid service", "[zitilib]") {
    ziti_handle_t ztx{};
    auto error = Ziti_load_context(&ztx, getenv("test_client"));
    REQUIRE(error == ZITI_OK);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);
    REQUIRE(Ziti_last_error() == ZITI_OK);

    for (auto block: {true, false}) {
        INFO("blocking: " << block);
        for (auto sock_af : {AF_INET, AF_INET6}) {
            INFO("AF: " << (sock_af == AF_INET ? "AF_INET" : "AF_INET6"));
            for (auto sock_type : {SOCK_DGRAM, SOCK_STREAM}) {
                INFO("socket type: " << (sock_type == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM"));
                auto sock = socket(sock_af, sock_type, 0);
                INFO("socket error: " << errno << "/" << strerror(errno));
                REQUIRE(sock != -1);
                DEFER {
                    close(sock);
                };

                set_blocking(sock, block);
                auto conn_rc = Ziti_connect(sock, ztx, "invalid_service", nullptr);
                REQUIRE(conn_rc == -1);
                REQUIRE(errno == ECONNREFUSED);
                CHECK(Ziti_last_error() == ZITI_SERVICE_UNAVAILABLE);
            }
        }
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect addr", "[zitilib]") {
    auto intercept_json = getenv("test_intercept");
    if (intercept_json == nullptr) {
        SKIP("'test_intercept' is not set");
    }

    ziti_handle_t ztx{};
    auto error = Ziti_load_context(&ztx, getenv("test_client"));
    REQUIRE(error == ZITI_OK);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);
    REQUIRE(Ziti_last_error() == ZITI_OK);
    auto bl = GENERATE(true, false);
    auto sock_type = GENERATE(SOCK_STREAM);
    auto sock_af = GENERATE(AF_INET, AF_INET6);

    ziti_intercept_cfg_v1 intercept = {};
    if (parse_ziti_intercept_cfg_v1(&intercept, intercept_json, strlen(intercept_json)) < 0) {
        FAIL("failed to parse intercept config: " << intercept_json);
    }
    DEFER {
        free_ziti_intercept_cfg_v1(&intercept);
    };
    auto addr = (const ziti_address*)model_list_head(&intercept.addresses);
    REQUIRE(addr != nullptr);
    auto ports = (const ziti_port_range*)model_list_head(&intercept.port_ranges);
    REQUIRE(ports != nullptr);

    REQUIRE(addr->type == ziti_address_hostname);
    auto hostname = addr->addr.hostname;
    auto port = (int)ports->low;

    WHEN((bl ? "blocking" : "async")
         << "/" << (sock_type == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM")
         << "/" << (sock_af == AF_INET ? "AF_INET" : "AF_INET6")) {
        auto sock = socket(sock_af, sock_type, 0);
        INFO("socket error: " << errno << "/" << strerror(errno));
        REQUIRE(sock != -1);
        DEFER {
            close(sock);
        };

        set_blocking(sock, bl);
        checkSocket(sock, bl, [&](ziti_socket_t s) {
            return Ziti_connect_addr(s, hostname, port);
        });
    }

}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect sockaddr", "[zitilib]") {
    auto intercept_json = getenv("test_intercept");
    if (intercept_json == nullptr) {
        SKIP("'test_intercept' is not set");
    }

    ziti_handle_t ztx{};
    auto error = Ziti_load_context(&ztx, getenv("test_client"));
    REQUIRE(error == ZITI_OK);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);
    REQUIRE(Ziti_last_error() == ZITI_OK);
    auto bl = GENERATE(true, false);

    ziti_intercept_cfg_v1 intercept = {};
    if (parse_ziti_intercept_cfg_v1(&intercept, intercept_json, strlen(intercept_json)) < 0) {
        FAIL("failed to parse intercept config: " << intercept_json);
    }
    DEFER {
        free_ziti_intercept_cfg_v1(&intercept);
    };
    auto addr = (const ziti_address*)model_list_head(&intercept.addresses);
    REQUIRE(addr != nullptr);
    auto ports = (const ziti_port_range*)model_list_head(&intercept.port_ranges);
    REQUIRE(ports != nullptr);

    REQUIRE(addr->type == ziti_address_hostname);

    auto hostname = addr->addr.hostname;
    auto port = std::to_string((int)ports->low);

    addrinfo *resolved_addr = nullptr;
    addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    REQUIRE(Ziti_resolve(hostname, port.c_str(), &hints, &resolved_addr) == 0);
    REQUIRE(resolved_addr != nullptr);
    DEFER {
        uv_freeaddrinfo(resolved_addr);
    };

    WHEN((bl ? "blocking" : "async")) {
        auto sock = socket(resolved_addr->ai_family, resolved_addr->ai_socktype, 0);
        INFO("socket error: " << errno << "/" << strerror(errno));
        REQUIRE(sock != -1);
        DEFER {
            close(sock);
        };

        set_blocking(sock, bl);
        checkSocket(sock, bl, [&](ziti_socket_t s) {
            return Ziti_connect_sockaddr(s, resolved_addr->ai_addr, resolved_addr->ai_addrlen);
        });
    }

}
