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
// Covers the "identity was just enrolled" failure mode: on an HA controller the
// new identity may not have replicated to the node the SDK reached yet, so the
// OIDC authorize/login leg rejects perfectly good credentials with 401/403/404.
//
// Before the fix, every failure in the auth chain funneled through
// failed_auth_req() straight to OIDC_TOKEN_FAILED -> ZitiAuthStateUnauthenticated
// -> ztx_set_unauthenticated(), which schedules no retry. On a first-ever
// authentication there is no services-refresh timer running either (that is only
// armed once auth succeeds), so the context stayed unauthenticated until the
// process restarted. library/oidc.c now treats such a failure as temporary for a
// bounded window (clt->auth_retry_window), retrying the whole flow with
// full-jitter backoff and staying silent - no auth_cb, so no session teardown or
// event churn - until either the flow succeeds or the window closes.
//
// Like tests/oidc_recovery_tests.cpp, these tests drive library/oidc.c's
// oidc_client_t directly against a local fake HTTP endpoint. Discovery is skipped
// by hand-populating clt.config's authorization_endpoint/token_endpoint, which is
// all oidc_client_start() reads. There is no HTTP-mocking seam in this codebase -
// every "mock" here is a real loopback socket server.

#include "catch2_includes.hpp"

#include "oidc.h"
#include <ziti/model_collections.h>
#include <tlsuv/tlsuv.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
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

// Three dot-separated base64url(no padding) segments; zt_jwt_parse only requires
// the payload to be valid base64url JSON carrying a string "iss" (and an integer
// "exp" if present). The signature segment is never decoded or verified.
// exp = 4000000000 is the year 2096, so these never look expired.
constexpr const char *FAKE_JWT =
    "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjo0MDAwMDAwMDAwfQ.sig";

// oidc.c's auth chain, and the fake response each leg needs to advance:
//   POST authorization_endpoint  -> 302 Location: ...?authRequestID=..  (auth_cb)
//   POST /oidc/login/ext-jwt     -> 302 Location: <path>                (login_cb)
//   GET  <that path>             -> 302 Location: ...?code=..           (code_cb)
//   POST token_endpoint          -> 200 {access_token, refresh_token}   (token_cb)
constexpr const char *AUTHORIZE_PATH = "/authorize";
constexpr const char *LOGIN_PATH = "/oidc/login/ext-jwt";
constexpr const char *CODE_PATH = "/oidc/redirect";
constexpr const char *TOKEN_PATH = "/token";

// A local OIDC-ish endpoint. The authorize leg serves a scripted queue of HTTP
// statuses (so a test can say "fail with 401 twice, then let the flow through");
// once the queue is drained it answers with the redirect that advances the flow.
// One thread per connection, independent of the test's uv_loop.
class FakeOidcEndpoint {
public:
    uint16_t port{};
    std::atomic<int> authorize_count{0};
    std::atomic<int> token_count{0};

    // each entry is a full status line + optional JSON body served to one
    // authorize request; empty queue == serve the success redirect
    void scriptAuthorizeFailure(const std::string &statusLine, const std::string &body = "") {
        std::lock_guard<std::mutex> lock(mu_);
        authorize_script_.push_back({statusLine, body});
    }

    FakeOidcEndpoint() {
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

    ~FakeOidcEndpoint() {
        stop_ = true;
        shutdown(listen_fd_, SHUT_BOTH);
        CLOSESOCK(listen_fd_);
        if (accept_thread_.joinable()) accept_thread_.join();
        for (auto &t: workers_) {
            if (t.joinable()) t.join();
        }
#if _WIN32
        WSACleanup();
#endif
    }

    std::string url(const char *path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }

private:
    struct ScriptedResp {
        std::string statusLine;
        std::string body;
    };

    void acceptLoop() {
        while (!stop_) {
            int client = (int) accept(listen_fd_, nullptr, nullptr);
            if (client == INVALID_SOCK) {
                if (stop_) return;
                continue;
            }
            workers_.emplace_back([this, client] { serve(client); });
        }
    }

    // Read the request line + headers, then drain exactly Content-Length bytes of
    // body. Leaving unread bytes in the receive buffer and closing produces an
    // abortive close (RST) on Windows, which can discard the response we already
    // handed to send() - see the same note in oidc_recovery_tests.cpp.
    void serve(int client) {
        char buf[8192];
        std::string received;
        size_t headerEnd;
        while ((headerEnd = received.find("\r\n\r\n")) == std::string::npos) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) { CLOSESOCK(client); return; }
            received.append(buf, (size_t) n);
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

        // route on the exact request path: substring matching is a trap here,
        // since the legs share prefixes with each other
        std::string requestLine = received.substr(0, received.find("\r\n"));
        size_t targetStart = requestLine.find(' ');
        size_t targetEnd = requestLine.rfind(' ');
        std::string target = (targetStart == std::string::npos || targetEnd <= targetStart)
                                 ? std::string()
                                 : requestLine.substr(targetStart + 1, targetEnd - targetStart - 1);
        std::string path = target.substr(0, target.find('?'));
        std::string resp = respondTo(path);
        send(client, resp.data(), resp.size(), 0);
        // shutdown the write side before closing so the client is guaranteed to
        // see the response before the FIN
        shutdown(client, SHUT_SEND);
        CLOSESOCK(client);
    }

    std::string respondTo(const std::string &path) {
        if (path == AUTHORIZE_PATH) {
            authorize_count++;
            ScriptedResp scripted;
            bool haveScripted = false;
            {
                std::lock_guard<std::mutex> lock(mu_);
                if (!authorize_script_.empty()) {
                    scripted = authorize_script_.front();
                    authorize_script_.pop_front();
                    haveScripted = true;
                }
            }
            if (haveScripted) {
                return response(scripted.statusLine, {}, scripted.body);
            }
            return response("302 Found", {{"Location", url(LOGIN_PATH) + "?authRequestID=test-req-1&x=1"}});
        }

        if (path == LOGIN_PATH) {
            return response("302 Found", {{"Location", url(CODE_PATH) + "?state=test-state"}});
        }

        if (path == CODE_PATH) {
            return response("302 Found", {{"Location", url("/auth/callback") + "?code=test-code&state=test-state"}});
        }

        if (path == TOKEN_PATH) {
            token_count++;
            std::string body = std::string("{\"access_token\":\"") + FAKE_JWT +
                               "\",\"refresh_token\":\"" + FAKE_JWT + "\"}";
            return response("200 OK", {{"Content-Type", "application/json"}}, body);
        }

        return response("404 Not Found");
    }

    static std::string response(const std::string &statusLine,
                                const std::vector<std::pair<std::string, std::string>> &headers = {},
                                const std::string &body = "") {
        std::string out = "HTTP/1.1 " + statusLine + "\r\n";
        for (const auto &h: headers) {
            out += h.first + ": " + h.second + "\r\n";
        }
        out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        out += "Connection: close\r\n\r\n";
        out += body;
        return out;
    }

    int listen_fd_{};
    std::atomic<bool> stop_{false};
    std::thread accept_thread_;
    std::vector<std::thread> workers_;
    std::mutex mu_;
    std::deque<ScriptedResp> authorize_script_;
};

struct AuthResult {
    int calls = 0;
    enum oidc_status status{};
    std::string token;
};

// Everything oidc_client_start() and the login leg actually read, wired up
// without going through discovery: the two endpoints from the OIDC config, and
// one non-expired ext token so auth_cb picks the ext-jwt login path (a cert
// would send it to /oidc/login/cert instead, and with neither it bails out with
// "no credentials provided").
struct TestClient {
    uv_loop_t *loop{};
    tls_context *tls{};
    oidc_client_t clt{};
    AuthResult result{};

    TestClient(const FakeOidcEndpoint &server, uint64_t retry_window_ms) {
        loop = uv_loop_new();
        tls = default_tls_context(nullptr, 0);
        REQUIRE(oidc_client_init(loop, &clt, server.url("/oidc").c_str(), tls) == 0);

        clt.auth_retry_window = retry_window_ms;
        clt.data = &result;

        json_object *cfg = json_object_new_object();
        json_object_object_add(cfg, "authorization_endpoint",
                               json_object_new_string(server.url(AUTHORIZE_PATH).c_str()));
        json_object_object_add(cfg, "token_endpoint",
                               json_object_new_string(server.url(TOKEN_PATH).c_str()));
        clt.config = cfg;

        auto *jwt = (zt_jwt *) calloc(1, sizeof(zt_jwt));
        REQUIRE(zt_jwt_parse(FAKE_JWT, jwt) == 0);
        model_map_set(&clt.ext_tokens, cstr_str(&jwt->issuer), jwt);
    }

    ~TestClient() {
        oidc_client_close(&clt, [](oidc_client_t *) {});
        for (int i = 0; i < 10 && uv_run(loop, UV_RUN_ONCE) != 0; i++) {}
        // uv_loop_new() heap-allocates the loop, so uv_loop_close() alone leaks it
        // and LeakSanitizer flags it even on an otherwise passing run.
        uv_loop_delete(loop);
        tls->free_ctx(tls);
    }

    int start() {
        return oidc_client_start(&clt, [](oidc_client_t *c, enum oidc_status status, const void *data) {
            auto *r = (AuthResult *) c->data;
            r->calls++;
            r->status = status;
            if (status == OIDC_TOKEN_OK && data) r->token = (const char *) data;
        });
    }

    // pump the loop until pred() or the timeout elapses
    template<typename Pred>
    void pumpUntil(Pred pred, std::chrono::milliseconds timeout) {
        auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!pred() && std::chrono::steady_clock::now() < deadline) {
            uv_run(loop, UV_RUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    void pumpFor(std::chrono::milliseconds duration) {
        pumpUntil([] { return false; }, duration);
    }
};

} // namespace

// A 401 on the authorize leg - what an unreplicated identity looks like - is
// retried without ever telling the app, and only becomes OIDC_TOKEN_FAILED once
// the window closes. The 3s window guarantees at least one retry: the first
// backoff is next_backoff(0, 5, 1000) == random % 2000, clamped to the window.
TEST_CASE("oidc-auth-retries-transient-401-then-reports-once", "[oidc]") {
    FakeOidcEndpoint server;
    for (int i = 0; i < 20; i++) server.scriptAuthorizeFailure("401 Unauthorized");

    TestClient c(server, 3000);
    REQUIRE(c.start() == 0);

    // while the window is open the app hears nothing at all
    c.pumpUntil([&] { return server.authorize_count.load() >= 2; }, std::chrono::seconds(4));
    CHECK(server.authorize_count.load() >= 2);
    CHECK(c.result.calls == 0);

    // once it closes, the failure surfaces exactly once
    c.pumpUntil([&] { return c.result.calls > 0; }, std::chrono::seconds(6));
    REQUIRE(c.result.calls == 1);
    CHECK(c.result.status == OIDC_TOKEN_FAILED);

    // and nothing keeps retrying afterwards
    int settled = server.authorize_count.load();
    c.pumpFor(std::chrono::milliseconds(500));
    CHECK(server.authorize_count.load() == settled);
    CHECK(c.result.calls == 1);
}

// The window opens *at* the first failure, so the smallest possible window still
// buys exactly one retry; the failure the app sees is the second attempt's.
// Pins the floor of the behavior: the window can never swallow the failure
// entirely, and an exhausted window reports once and stops.
TEST_CASE("oidc-auth-smallest-window-retries-once-then-reports", "[oidc]") {
    FakeOidcEndpoint server;
    for (int i = 0; i < 5; i++) server.scriptAuthorizeFailure("401 Unauthorized");

    TestClient c(server, 1);
    REQUIRE(c.start() == 0);

    c.pumpUntil([&] { return c.result.calls > 0; }, std::chrono::seconds(5));
    REQUIRE(c.result.calls == 1);
    CHECK(c.result.status == OIDC_TOKEN_FAILED);
    CHECK(server.authorize_count.load() == 2);

    c.pumpFor(std::chrono::milliseconds(300));
    CHECK(server.authorize_count.load() == 2);
    CHECK(c.result.calls == 1);
}

// Guards against over-broad classification: a 400 that is not zitadel's generic
// server_error is a real rejection and must fail on the first attempt even with a
// generous window.
TEST_CASE("oidc-auth-does-not-retry-permanent-failure", "[oidc]") {
    FakeOidcEndpoint server;
    for (int i = 0; i < 5; i++) {
        server.scriptAuthorizeFailure("400 Bad Request", R"({"error":"invalid_request"})");
    }

    TestClient c(server, 60000);
    REQUIRE(c.start() == 0);

    c.pumpUntil([&] { return c.result.calls > 0; }, std::chrono::seconds(5));
    REQUIRE(c.result.calls == 1);
    CHECK(c.result.status == OIDC_TOKEN_FAILED);

    c.pumpFor(std::chrono::milliseconds(500));
    CHECK(server.authorize_count.load() == 1);
}

// The bug this whole change exists for: the identity finishes replicating partway
// through the window, the retried flow completes, and the app sees a single
// successful auth rather than a permanent failure.
TEST_CASE("oidc-auth-recovers-once-identity-replicates", "[oidc]") {
    FakeOidcEndpoint server;
    server.scriptAuthorizeFailure("401 Unauthorized");
    server.scriptAuthorizeFailure("404 Not Found");
    // script exhausted: subsequent authorize requests complete the flow

    TestClient c(server, 20000);
    REQUIRE(c.start() == 0);

    c.pumpUntil([&] { return c.result.calls > 0; }, std::chrono::seconds(15));

    REQUIRE(c.result.calls == 1);
    CHECK(c.result.status == OIDC_TOKEN_OK);
    CHECK(c.result.token == FAKE_JWT);
    CHECK(server.authorize_count.load() == 3);
    CHECK(server.token_count.load() == 1);

    // the window is closed out on success, so a later failure gets a fresh one
    CHECK(c.clt.auth_failures == 0);
    CHECK(c.clt.auth_retry_until == 0);
}
