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

// GH-1163: a controller that hands out an API session which is already expired by the clock of this
// machine (the usual reason is a wrong local clock) used to put the context into a loop that
// authenticated every ~20 ms: the legacy auth method asked for the next refresh in 0 s, and
// ztx_prepare() throws out a session token that is past its expiration on every loop iteration.
//
// These tests drive a real ziti_context against a fake legacy controller: a loopback HTTP server
// that answers /version without the OIDC capability, so the context picks legacy authentication,
// and /authenticate with a session whose times the test chooses.

// model_support.h #defines `map`: tls_test_util.h pulls in the standard headers, so it goes first
#include "tls_test_util.h"

#include "catch2_includes.hpp"

#include <uv.h>
#include <ziti/ziti.h>
#include <ziti/errors.h>

#include <atomic>
#include <chrono>
#include <ctime>
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
    std::string iso8601(time_t t) {
        struct tm tm = {};
#if _WIN32
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char buf[40];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000000Z", &tm);
        return buf;
    }

    // A legacy (non-OIDC) controller that answers just enough for a context to authenticate.
    // One thread per connection, independent of the test's uv loop.
    class FakeLegacyController {
    public:
        // `clock_offset`: seconds the controller's clock is ahead of ours (negative: behind).
        // `expires_in`: seconds from "now" on the controller's clock to the expiration of the
        // sessions it issues (negative: already expired when issued).
        FakeLegacyController(int64_t clock_offset, int64_t expires_in)
                : clock_offset_(clock_offset), expires_in_(expires_in) {
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

        ~FakeLegacyController() {
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

        std::string url() const { return "http://127.0.0.1:" + std::to_string(port); }

        uint16_t port{};
        std::atomic<int> authenticate_count{0};

    private:
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

        // Read the request line and headers, then drain exactly Content-Length bytes of body:
        // closing with unread bytes in the receive buffer is an abortive close (RST) on Windows,
        // which can discard a response that was already handed to send().
        void serve(int client) {
            char buf[8192];
            std::string received;
            size_t headerEnd;
            while ((headerEnd = received.find("\r\n\r\n")) == std::string::npos) {
                ssize_t n = recv(client, buf, sizeof(buf), 0);
                if (n <= 0) {
                    CLOSESOCK(client);
                    return;
                }
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
                if (n <= 0) {
                    CLOSESOCK(client);
                    return;
                }
                bodySoFar += (size_t) n;
            }

            std::string requestLine = received.substr(0, received.find("\r\n"));
            size_t targetStart = requestLine.find(' ');
            size_t targetEnd = requestLine.rfind(' ');
            std::string target = (targetStart == std::string::npos || targetEnd <= targetStart)
                                 ? std::string()
                                 : requestLine.substr(targetStart + 1, targetEnd - targetStart - 1);
            std::string path = target.substr(0, target.find('?'));

            std::string resp = respondTo(path);
            send(client, resp.data(), resp.size(), 0);
            // the client has to see the response before the FIN
            shutdown(client, SHUT_SEND);
            CLOSESOCK(client);
        }

        static bool ends_with(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        std::string respondTo(const std::string &path) {
            if (ends_with(path, "/version")) {
                return json("200 OK", R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                                      R"("runtimeVersion":"fake","capabilities":[],"buildFlags":[],)"
                                      R"("apiVersions":{"edge":{"v1":{"path":"/edge/client/v1"}}}},"meta":{}})");
            }
            if (ends_with(path, "/authenticate")) {
                int n = ++authenticate_count;
                time_t ctrl_now = time(nullptr) + (time_t) clock_offset_;
                std::string body =
                        R"({"data":{"id":"fake-session-)" + std::to_string(n) + R"(","token":"fake-token-)" +
                        std::to_string(n) + R"(","identityId":"fake-id",)" +
                        R"("expiresAt":")" + iso8601(ctrl_now + (time_t) expires_in_) + R"(",)" +
                        R"("updatedAt":")" + iso8601(ctrl_now) + R"(",)" +
                        R"("cachedLastActivityAt":")" + iso8601(ctrl_now) + R"(",)" +
                        R"("authQueries":[],"identity":{"id":"fake-id","name":"fake"}},"meta":{}})";
                return json("200 OK", body);
            }
            return json("404 Not Found", R"({"error":{"code":"NOT_FOUND","message":"fake controller","requestId":"x"}})");
        }

        static std::string json(const std::string &statusLine, const std::string &body) {
            return "HTTP/1.1 " + statusLine + "\r\nContent-Type: application/json\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        }

        int64_t clock_offset_;
        int64_t expires_in_;
        int listen_fd_{};
        std::atomic<bool> stop_{false};
        std::thread accept_thread_;
        std::vector<std::thread> workers_;
    };

    // one loop for every case: creating and closing a loop per case trips libuv's fd assertion when
    // the whole suite runs in one process
    uv_loop_t *test_loop() {
        static uv_loop_t *loop = uv_loop_new();
        return loop;
    }

    struct context_run {
        ziti_context ztx = nullptr;
        int fully_authenticated = 0; // ZitiContextEvent with ZITI_OK
        int auth_failed = 0;         // ZitiContextEvent with ZITI_AUTHENTICATION_FAILED
    };

    // Runs a context against the controller for `duration_ms`, then shuts it down.
    context_run run_context(const FakeLegacyController &ctrl, unsigned duration_ms) {
        context_run run;

        std::string key = std::string("pem:") + rsa_key;
        std::string cert = std::string("pem:") + rsa_cert;
        std::string url = ctrl.url();
        ziti_config cfg = {};
        cfg.controller_url = (char *) url.c_str();
        cfg.id.key = (char *) key.c_str();
        cfg.id.cert = (char *) cert.c_str();

        REQUIRE(ziti_context_init(&run.ztx, &cfg) == ZITI_OK);

        ziti_options opts = {};
        opts.app_ctx = &run;
        opts.events = ZitiContextEvent;
        opts.event_cb = [](ziti_context ztx, const ziti_event_t *ev) {
            auto r = (context_run *) ziti_app_ctx(ztx);
            if (ev->type != ZitiContextEvent) return;
            if (ev->ctx.ctrl_status == ZITI_OK) r->fully_authenticated++;
            if (ev->ctx.ctrl_status == ZITI_AUTHENTICATION_FAILED) r->auth_failed++;
        };
        REQUIRE(ziti_context_set_options(run.ztx, &opts) == ZITI_OK);

        uv_loop_t *loop = test_loop();
        // the loop sat idle since the last case, and timers count from its cached time: a stale one
        // would have the stop timer below fire right away
        uv_update_time(loop);
        REQUIRE(ziti_context_run(run.ztx, loop) == ZITI_OK);

        uv_timer_t stop;
        uv_timer_init(loop, &stop);
        stop.data = &run;
        uv_timer_start(&stop, [](uv_timer_t *t) {
            ziti_shutdown(((context_run *) t->data)->ztx);
            uv_close((uv_handle_t *) t, nullptr);
        }, duration_ms, 0);

        // unref'd: it ends a hung shutdown but does not keep a finished loop alive
        uv_timer_t guard;
        uv_timer_init(loop, &guard);
        uv_unref((uv_handle_t *) &guard);
        uv_timer_start(&guard, [](uv_timer_t *t) { uv_stop(t->loop); }, duration_ms + 10000, 0);

        uv_run(loop, UV_RUN_DEFAULT);
        uv_close((uv_handle_t *) &guard, nullptr);
        uv_run(loop, UV_RUN_DEFAULT);
        return run;
    }
}

// control: nothing is wrong with the clocks or the session
TEST_CASE("legacy-auth-healthy-session", "[legacy-auth][GH-1163]") {
    FakeLegacyController ctrl(0, 1800);
    auto run = run_context(ctrl, 3000);

    CHECK(ctrl.authenticate_count.load() == 1);
    CHECK(run.auth_failed == 0);
}

// the controller's clock is a day behind ours: its sessions look expired here, they are not,
// and the context carries on with the session
TEST_CASE("legacy-auth-controller-clock-behind", "[legacy-auth][GH-1163]") {
    FakeLegacyController ctrl(-86400, 1800);
    auto run = run_context(ctrl, 3000);

    CHECK(ctrl.authenticate_count.load() == 1);
    CHECK(run.auth_failed == 0);
}

// the controller issues a session that is already expired on its own clock: that is a failed
// authentication, and the next attempt waits instead of asking right away
TEST_CASE("legacy-auth-controller-issues-expired-session", "[legacy-auth][GH-1163]") {
    FakeLegacyController ctrl(0, -60);
    auto run = run_context(ctrl, 3000);

    CHECK(ctrl.authenticate_count.load() == 1);
    CHECK(run.auth_failed == 1);
}
