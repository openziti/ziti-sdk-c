// Copyright (c) 2026. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <catch2/catch_all.hpp>

#include "fixtures.h"
#include <ziti/zitilib.h>

#include <functional>

#ifdef _WIN32
#include <WinSock2.h>
#define close(s) closesocket(s)
#define poll(f,d,t) WSAPoll(f,d,t)
#define sockerr() WSAGetLastError()
static char wsa_err_buf[256];
static const char *wsa_error(int err) {
    wsa_err_buf[0] = 0;
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   wsa_err_buf, sizeof(wsa_err_buf), NULL);
    if (wsa_err_buf[0] == 0) {
        snprintf(wsa_err_buf, sizeof(wsa_err_buf), "Unknown error %d", err);
    }
    return wsa_err_buf;
}
#define strerror(e) wsa_error(e)
#define in_progress(e) ((e) == WSAEINPROGRESS || (e) == WSAEWOULDBLOCK)
#else
#include <poll.h>
#  ifndef SOCKET_ERROR
#    define SOCKET_ERROR		(-1)
#  endif
#define sockerr() errno
#define in_progress(e) ((e) == EINPROGRESS || (e) == EWOULDBLOCK)
#endif

#define RECV_TIMEOUT 5


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
            FAIL("getsockopt error: " << strerror(sockerr()));
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

    if (blocking) {
#if _WIN32
        DWORD timeout = RECV_TIMEOUT * 1000;
#else
        struct timeval timeout{
            .tv_sec = RECV_TIMEOUT, .tv_usec = 0,
        };
#endif
        REQUIRE(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    }
}

static ziti_socket_t mk_socket(int af, int type, bool blocking) {
    ziti_socket_t s = SOCKET_ERROR;
    int proto;
    if (type == SOCK_STREAM) { proto = IPPROTO_TCP; }
    else if (type == SOCK_DGRAM) { proto = IPPROTO_UDP; }
    else return SOCKET_ERROR;

#if _WIN32
    s = WSASocket(af, type, proto, nullptr, 0, WSA_FLAG_OVERLAPPED);
#else
    s = socket(af, type, proto);
#endif
    if (s == SOCKET_ERROR) return s;

    set_blocking(s, blocking);
    return s;
}


static void checkSocketSync(ziti_socket_t sock, const std::function<int(ziti_socket_t)> &connect_fn) {
    auto conn_rc = connect_fn(sock);
    auto err = sockerr();
    auto ze = Ziti_last_error();
    INFO("error: " << ze << "/" << ziti_errorstr(ze) << " errno: " << err << "/" << strerror(err));
    REQUIRE(conn_rc == 0);
    CHECK(ze == ZITI_OK);

    auto send_rc = send(sock, "hello", 5, 0);
    auto send_err = send_rc == -1 ?  sockerr() : 0;
    INFO("send error: " << send_err << "/" << strerror(send_err));
    REQUIRE(send_rc == 5);

    char buf[16];
    auto read_rc = recv(sock, buf, sizeof(buf), 0);
    auto read_err = read_rc == -1 ? sockerr() : 0;
    INFO("recv error: " << read_err << "/" << strerror(read_err));
    REQUIRE(read_rc == 5);
    CHECK(std::string(buf, buf + read_rc) == "hello");
}

static void checkSocketAsync(ziti_socket_t sock, const std::function<int(ziti_socket_t)> &connect_fn) {
    int sock_type = 0;
    socklen_t sock_type_len = sizeof(sock_type);
    INFO("socket: " << sock);
    REQUIRE(getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &sock_type_len) == 0);

    auto conn_rc = connect_fn(sock);
    if (conn_rc == -1) {
        REQUIRE(sock_type == SOCK_STREAM); // UDP should connect immediately
        auto err = sockerr();
        auto ze = Ziti_last_error();
        INFO("error: " << ze << "/" << ziti_errorstr(ze) << " errno: " << err << "/" << strerror(err));
        CHECK(ze == ZITI_OK);
        INFO("connect in progress, waiting for completion...");
        REQUIRE(in_progress(err));
        pollfd p = {
            .fd = sock,
            .events = POLLOUT,
        };
        REQUIRE(poll(&p, 1, RECV_TIMEOUT * 1000) == 1);
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
    auto send_err = send_rc == -1 ?  sockerr() : 0;
    INFO("send error: " << send_err << "/" << strerror(send_err));
    REQUIRE(send_rc == 5);

    char buf[16];
    auto read_rc = recv(sock, buf, sizeof(buf), 0);
    if (read_rc == -1) { // this is expected in non-blocking mode
        auto read_err = sockerr();
        INFO("recv error: " << read_err << "/" << strerror(read_err));
        REQUIRE(in_progress(read_err));
        INFO("data not available immediately, waiting for it...");

        INFO("polling socket " << sock);
        pollfd p = {
            .fd = sock,
            .events = POLLIN
        };
        REQUIRE(poll(&p, 1, RECV_TIMEOUT * 1000) == 1);
        checkPollErr(p);
        REQUIRE((p.revents & POLLIN) > 0);

        read_rc = recv(sock, buf, sizeof(buf), 0);
    }
    REQUIRE(read_rc == 5);
    CHECK(std::string(buf, buf + read_rc) == "hello");
}

static inline void checkSocket(ziti_socket_t sock, bool block, const std::function<int(ziti_socket_t)> &connect_fn) {
    INFO("socket error: " << sockerr() << "/" << strerror(sockerr()));
    if (sock == SOCKET_ERROR) {
        SKIP("failed to create socket: " << sockerr() << "/" << strerror(sockerr()));
        return;
    }
    DEFER {
        close(sock);
    };

    INFO("testing socket: " << sock);
    if (block) {
        checkSocketSync(sock, connect_fn);
    } else {
        checkSocketAsync(sock, connect_fn);
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect service", "[zitilib:connect]") {
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
        auto sock = mk_socket(sock_af, sock_type, bl);
        checkSocket(sock, bl, [&](ziti_socket_t s) {
          return Ziti_connect(s, ztx, srv, nullptr);
        });
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect invalid service", "[zitilib:connect]") {
    ziti_handle_t ztx{};
    auto error = Ziti_load_context(&ztx, getenv("test_client"));
    REQUIRE(error == ZITI_OK);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);
    REQUIRE(Ziti_last_error() == ZITI_OK);

    auto block = GENERATE(true, false);
    auto sock_af = GENERATE(AF_INET, AF_INET6);
    auto sock_type = GENERATE(SOCK_STREAM, SOCK_DGRAM);
    WHEN("blocking: " << block
                      << " AF: " << (sock_af == AF_INET ? "AF_INET" : "AF_INET6")
                      << " type: " << (sock_type == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM")) {
        auto sock = mk_socket(sock_af, sock_type, block);
        INFO("socket error: " << sockerr() << "/" << strerror(sockerr()));
        REQUIRE(sock != SOCKET_ERROR);
        DEFER {
            close(sock);
        };

        auto conn_rc = Ziti_connect(sock, ztx, "invalid_service", nullptr);
        REQUIRE(conn_rc == -1);
#if _WIN32
        REQUIRE(sockerr() == WSAECONNREFUSED);
#else
        REQUIRE(sockerr() == ECONNREFUSED);
#endif
        CHECK(Ziti_last_error() == ZITI_SERVICE_UNAVAILABLE);
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect addr", "[zitilib:connect]") {
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
    auto sock_type = SOCK_STREAM; // TCP only
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
        auto sock = mk_socket(sock_af, sock_type, bl);
        checkSocket(sock, bl, [&](ziti_socket_t s) {
            return Ziti_connect_addr(s, hostname, port);
        });
    }

}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect sockaddr", "[zitilib:connect]") {
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
    INFO("hostname: " << addr->addr.hostname << " port: " << ports->low);
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
        auto sock = mk_socket(resolved_addr->ai_family, resolved_addr->ai_socktype, bl);
        checkSocket(sock, bl, [&](ziti_socket_t s) {
            return Ziti_connect_sockaddr(s, resolved_addr->ai_addr, (int)resolved_addr->ai_addrlen);
        });
    }
}
