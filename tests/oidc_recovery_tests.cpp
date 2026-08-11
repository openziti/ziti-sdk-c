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

// Reproduces the "restart fixes it" bug from
// https://openziti.discourse.group/t/zet-does-not-recover-after-prolonged-controller-network-outage-once-api-session-expires/5993
//
// oidc_client_refresh()/ext_oidc_client_refresh() are how ziti.c forces an
// OIDC token refresh (e.g. from ziti_re_auth() once connectivity looks like
// it may have returned). Before the fix, if a refresh request's underlying
// TCP connection died silently (no FIN/RST - the common shape of a real
// network partition, as opposed to the RST-on-connect a local dead listener
// produces), clt->refresh_req stayed permanently non-NULL: the request's
// resp_cb/oidc_refresh_cb would never fire on its own, so
// oidc_client_refresh's `if (clt->refresh_req)` guard returned UV_EALREADY
// forever, and refresh_time_cb's identical guard silently no-op'd forever -
// no matter how many times ziti.c called force_refresh afterward. Only a
// process restart (fresh clt->refresh_req = NULL) ever recovered.
//
// This test drives library/oidc.c's oidc_client_t directly (bypassing the
// full discovery/login/PKCE dance - oidc_client_refresh only needs
// clt->config's token_endpoint and clt->refresh_token to be set) against a
// local fake token endpoint that can "hang" a connection open without ever
// responding or closing it, then switch to actually serving a token
// response - modeling a silent network partition healing.

#include "catch2_includes.hpp"

#include "oidc.h"
#include <tlsuv/tlsuv.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
static constexpr int INVALID_SOCK = (int) INVALID_SOCKET;
#define CLOSESOCK closesocket
#define SHUT_SEND SD_SEND
#define SHUT_BOTH SD_BOTH
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
static constexpr int INVALID_SOCK = -1;
#define CLOSESOCK close
#define SHUT_BOTH SHUT_RDWR
#define SHUT_SEND SHUT_WR
#endif

namespace {

// Three dot-separated base64url(no padding) segments; zt_jwt_parse only
// requires the header/payload segments to be valid base64url JSON with the
// payload carrying a string "iss" (and, if present, an integer "exp") - the
// signature segment is never decoded or verified.
constexpr const char *FAKE_REFRESH_TOKEN =
    "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjo0MDAwMDAwMDAwfQ.sig";
constexpr const char *FAKE_ACCESS_TOKEN_1 =
    "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjo0MDAwMDAwMDAxfQ.sig";
constexpr const char *FAKE_ACCESS_TOKEN_2 =
    "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjo0MDAwMDAwMDAyfQ.sig";

// A local token endpoint that can either "hang" an accepted connection -
// never read from it, never write to it, never close it, modeling a network
// partition that drops packets silently rather than resetting the
// connection - or serve a real 200 JSON token response. Runs entirely on
// background threads, independent of the test's uv_loop.
class FakeTokenEndpoint {
public:
    std::atomic<bool> hang{true};
    uint16_t port{};

    FakeTokenEndpoint() {
#if _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
        listen_fd_ = (int) ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        REQUIRE(::bind(listen_fd_, (sockaddr *) &addr, sizeof(addr)) == 0);

        socklen_t len = sizeof(addr);
        REQUIRE(getsockname(listen_fd_, (sockaddr *) &addr, &len) == 0);
        port = ntohs(addr.sin_port);

        listen(listen_fd_, 16);
        accept_thread_ = std::thread([this] { acceptLoop(); });
    }

    ~FakeTokenEndpoint() {
        stop_ = true;
        shutdown(listen_fd_, SHUT_BOTH);
        CLOSESOCK(listen_fd_);
        if (accept_thread_.joinable()) accept_thread_.join();

        // hung connections are never closed during the test (that's the
        // point - no FIN/RST ever arrives); clean them up now.
        std::lock_guard<std::mutex> lock(mu_);
        for (int fd: hungFds_) CLOSESOCK(fd);
#if _WIN32
        WSACleanup();
#endif
    }

private:
    void acceptLoop() {
        while (!stop_) {
            int client = (int) accept(listen_fd_, nullptr, nullptr);
            if (client == INVALID_SOCK) {
                if (stop_) return;
                continue;
            }
            if (hang.load()) {
                std::lock_guard<std::mutex> lock(mu_);
                hungFds_.push_back(client);
                continue;
            }
            std::thread(serveAlive, client).detach();
        }
    }

    static void serveAlive(int client) {
        // Read headers, then drain exactly Content-Length bytes of body -
        // the refresh POST always carries a form-encoded body. Leaving any
        // of it unread in the socket's receive buffer and then closing is
        // a well-known way to get an abortive close (RST) on Windows
        // instead of a graceful FIN, which can discard the response we
        // already handed to send() - POSIX stacks are far more forgiving
        // of this shortcut, which is why skipping this only broke Windows.
        char buf[4096];
        std::string received;
        size_t headerEnd;
        while ((headerEnd = received.find("\r\n\r\n")) == std::string::npos) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) { CLOSESOCK(client); return; }
            received.append(buf, n);
        }

        size_t contentLength = 0;
        size_t clPos = received.find("Content-Length:");
        if (clPos != std::string::npos && clPos < headerEnd) {
            contentLength = (size_t) std::strtoul(received.c_str() + clPos + strlen("Content-Length:"), nullptr, 10);
        }
        size_t bodySoFar = received.size() - (headerEnd + 4);
        while (bodySoFar < contentLength) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) { CLOSESOCK(client); return; }
            bodySoFar += (size_t) n;
        }

        std::string body = std::string("{\"access_token\":\"") + FAKE_ACCESS_TOKEN_2 +
                            "\",\"refresh_token\":\"" + FAKE_REFRESH_TOKEN + "\"}";
        std::string resp = "HTTP/1.1 200 OK\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: " + std::to_string(body.size()) + "\r\n"
                            "Connection: close\r\n\r\n" + body;
        send(client, resp.data(), resp.size(), 0);
        // Closing right after send() risks the OS discarding the just-sent
        // bytes with an abortive close instead of flushing them - shutdown()
        // the write side first so the client is guaranteed to see the
        // response before the FIN.
        shutdown(client, SHUT_SEND);
        CLOSESOCK(client);
    }

    int listen_fd_{};
    std::atomic<bool> stop_{false};
    std::thread accept_thread_;
    std::mutex mu_;
    std::vector<int> hungFds_;
};

struct RefreshResult {
    bool called = false;
    enum oidc_status status{};
    std::string token;
};

} // namespace

TEST_CASE("oidc-refresh-recovers-after-silent-connection-death", "[oidc]") {
    FakeTokenEndpoint server;

    uv_loop_t *loop = uv_loop_new();
    tls_context *tls = default_tls_context(nullptr, 0);

    oidc_client_t clt{};
    // Provider URL is never actually dialed by the refresh path - refresh
    // always retargets clt->http at clt->config's token_endpoint - so it
    // just needs to parse as a URL.
    REQUIRE(oidc_client_init(loop, &clt, "http://127.0.0.1:1/oidc", tls) == 0);

    RefreshResult result;
    clt.data = &result;
    clt.token_cb = [](oidc_client_t *c, enum oidc_status status, const void *data) {
        auto *r = (RefreshResult *) c->data;
        r->called = true;
        r->status = status;
        if (status == OIDC_TOKEN_OK && data) r->token = (const char *) data;
    };

    // Skip discovery/login entirely: hand-populate exactly what
    // oidc_client_refresh/refresh_time_cb read - config's token_endpoint,
    // and a refresh_token that isn't expired.
    std::string tokenUrl = "http://127.0.0.1:" + std::to_string(server.port) + "/token";
    json_object *cfg = json_object_new_object();
    json_object_object_add(cfg, "token_endpoint", json_object_new_string(tokenUrl.c_str()));
    clt.config = cfg;
    REQUIRE(zt_jwt_parse(FAKE_REFRESH_TOKEN, &clt.refresh_token) == 0);
    REQUIRE(zt_jwt_parse(FAKE_ACCESS_TOKEN_1, &clt.current) == 0);

    // 1) First refresh attempt: the server accepts the connection and then
    // just sits on it - no response, no close. This is what a refresh
    // request looks like mid-network-partition.
    REQUIRE(oidc_client_refresh(&clt) == 0);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        uv_run(loop, UV_RUN_NOWAIT);
    }
    CHECK_FALSE(result.called); // still hung - nothing has responded yet
    REQUIRE(clt.refresh_req != nullptr); // confirms the scenario: a request really is stuck in flight

    // 2) Network "heals": the endpoint starts responding, and something
    // upstream (in production, ziti.c's ziti_re_auth/force_refresh) asks
    // for another refresh - exactly what happens every services-refresh
    // interval after an outage. Before the fix, oidc_client_refresh saw
    // clt->refresh_req still set (from the still-hung first attempt) and
    // returned UV_EALREADY without ever issuing a new request, so `result`
    // would never be populated no matter how long the loop ran.
    server.hang = false;
    int rc = oidc_client_refresh(&clt);

    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!result.called && std::chrono::steady_clock::now() < deadline) {
        uv_run(loop, UV_RUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    CHECK(rc == 0);
    REQUIRE(result.called);
    CHECK(result.status == OIDC_TOKEN_OK);
    CHECK(result.token == FAKE_ACCESS_TOKEN_2);

    oidc_client_close(&clt, [](oidc_client_t *) {});
    for (int i = 0; i < 10 && uv_run(loop, UV_RUN_ONCE) != 0; i++) {}
    // uv_loop_close() only tears down the loop's internal resources - the
    // uv_loop_t itself was heap-allocated by uv_loop_new() and needs
    // uv_loop_delete() (close + free) or it leaks, which LeakSanitizer
    // catches even on an otherwise fully-passing run.
    uv_loop_delete(loop);
    tls->free_ctx(tls);
}
