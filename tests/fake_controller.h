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

// A fake controller for tests that drive a real ziti_context: a loopback HTTP server that answers what
// the test tells it to, and a harness that runs a context against it. There is no HTTP-mocking seam
// in the SDK, so the server is a real socket, on threads of its own so that it cannot be starved by
// (or interfere with) the loop under test.
#pragma once

// model_support.h #defines `map`: tls_test_util.h pulls in the standard headers, so it goes first
#include "tls_test_util.h"

#include <uv.h>
#include <ziti/ziti.h>
#include <ziti/errors.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace fake_controller {
#if _WIN32
    constexpr int INVALID_SOCK = (int) INVALID_SOCKET;
    inline void close_socket(int s) { closesocket(s); }
    constexpr int SHUT_RD_WR = SD_BOTH;
    constexpr int SHUT_WR_ONLY = SD_SEND;
#else
    constexpr int INVALID_SOCK = -1;
    inline void close_socket(int s) { close(s); }
    constexpr int SHUT_RD_WR = SHUT_RDWR;
    constexpr int SHUT_WR_ONLY = SHUT_WR;
#endif

    using Headers = std::vector<std::pair<std::string, std::string>>;

    // a whole HTTP message: "200 OK", headers and a body
    inline std::string http_response(const std::string &status_line, const Headers &headers = {},
                                const std::string &body = "") {
        std::string out = "HTTP/1.1 " + status_line + "\r\n";
        for (const auto &h: headers) {
            out += h.first + ": " + h.second + "\r\n";
        }
        out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        out += "Connection: close\r\n\r\n";
        out += body;
        return out;
    }

    inline std::string json_response(const std::string &status_line, const std::string &body) {
        return http_response(status_line, {{"Content-Type", "application/json"}}, body);
    }

    // the error body of the controller API: "400 Bad Request", "MFA_INVALID_TOKEN"
    inline std::string api_error(const std::string &status_line, const std::string &code) {
        return json_response(status_line, R"({"error":{"code":")" + code +
                                          R"(","message":"fake controller","requestId":"x"}})");
    }

    inline std::string not_found() {
        return api_error("404 Not Found", "NOT_FOUND");
    }

    // One thread per connection. The handler runs on those threads: what it touches has to be
    // thread safe.
    class FakeHttpServer {
    public:
        // gets the method and the path (without the query) of a request, returns the whole response
        using Handler = std::function<std::string(const std::string &method, const std::string &path)>;

        // `listening` false picks the port and leaves it unused: connections to it are refused until
        // listen() is called, which is what a controller that is down looks like. (A port that is bound
        // but not listening is not the same thing: connecting to one hangs on some systems.)
        explicit FakeHttpServer(Handler handler, bool listening = true) : handler_(std::move(handler)) {
#if _WIN32
            WSADATA wsaData;
            WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
            bind_socket(0);
            if (!listening) {
                close_socket(listen_fd_);
                listen_fd_ = INVALID_SOCK;
            } else {
                listen();
            }
        }

        ~FakeHttpServer() {
            stop_ = true;
            if (listen_fd_ != INVALID_SOCK) {
                shutdown(listen_fd_, SHUT_RD_WR);
                close_socket(listen_fd_);
            }
            if (accept_thread_.joinable()) accept_thread_.join();
            for (auto &t: workers_) {
                if (t.joinable()) t.join();
            }
#if _WIN32
            WSACleanup();
#endif
        }

        void listen() {
            if (accept_thread_.joinable()) return;
            if (listen_fd_ == INVALID_SOCK) {
                bind_socket(port);
            }
            ::listen(listen_fd_, 16);
            accept_thread_ = std::thread([this] { accept_loop(); });
        }

        std::string url() const { return "http://127.0.0.1:" + std::to_string(port); }

        // requests received so far whose path ends with `suffix`
        int count(const std::string &suffix) const {
            std::lock_guard<std::mutex> lock(mu_);
            int n = 0;
            for (const auto &p: paths_) {
                if (has_suffix(p, suffix)) {
                    n++;
                }
            }
            return n;
        }

        // the body of the last request whose path ends with `suffix`, "" when there was none
        std::string last_body(const std::string &suffix) const {
            std::lock_guard<std::mutex> lock(mu_);
            for (size_t i = paths_.size(); i-- > 0;) {
                if (has_suffix(paths_[i], suffix)) {
                    return bodies_[i];
                }
            }
            return "";
        }

        uint16_t port{};

    private:
        static bool has_suffix(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        // takes `want` (0: any free one) on the loopback interface and records it in `port`
        void bind_socket(uint16_t want) {
            listen_fd_ = (int) ::socket(AF_INET, SOCK_STREAM, 0);
            int one = 1;
            setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof(one));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(want);
            // qualified: unqualified bind() silently resolves to std::bind and discards a functor
            REQUIRE(::bind(listen_fd_, (sockaddr *) &addr, sizeof(addr)) == 0);

            socklen_t len = sizeof(addr);
            REQUIRE(getsockname(listen_fd_, (sockaddr *) &addr, &len) == 0);
            port = ntohs(addr.sin_port);
        }

        void accept_loop() {
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
            size_t header_end;
            while ((header_end = received.find("\r\n\r\n")) == std::string::npos) {
                ssize_t n = recv(client, buf, sizeof(buf), 0);
                if (n <= 0) {
                    close_socket(client);
                    return;
                }
                received.append(buf, (size_t) n);
            }

            size_t content_length = 0;
            size_t cl_pos = received.find("Content-Length:");
            if (cl_pos != std::string::npos && cl_pos < header_end) {
                content_length = (size_t) std::strtoul(received.c_str() + cl_pos + strlen("Content-Length:"), nullptr, 10);
            }
            size_t body_so_far = received.size() - (header_end + 4);
            while (body_so_far < content_length) {
                ssize_t n = recv(client, buf, sizeof(buf), 0);
                if (n <= 0) {
                    close_socket(client);
                    return;
                }
                received.append(buf, (size_t) n);
                body_so_far += (size_t) n;
            }

            std::string request_line = received.substr(0, received.find("\r\n"));
            size_t method_end = request_line.find(' ');
            size_t target_end = request_line.rfind(' ');
            std::string method = request_line.substr(0, method_end);
            std::string target = (method_end == std::string::npos || target_end <= method_end)
                                 ? std::string()
                                 : request_line.substr(method_end + 1, target_end - method_end - 1);
            std::string path = target.substr(0, target.find('?'));
            {
                std::lock_guard<std::mutex> lock(mu_);
                paths_.push_back(path);
                bodies_.push_back(received.substr(header_end + 4, content_length));
            }

            std::string resp = handler_(method, path);
            send(client, resp.data(), resp.size(), 0);
            // the client has to see the response before the FIN
            shutdown(client, SHUT_WR_ONLY);
            close_socket(client);
        }

        Handler handler_;
        int listen_fd_{};
        std::atomic<bool> stop_{false};
        std::thread accept_thread_;
        std::vector<std::thread> workers_;
        mutable std::mutex mu_;
        std::vector<std::string> paths_;
        std::vector<std::string> bodies_;   // parallel to paths_
    };

    // A legacy (non-OIDC) controller with the service "svc", which the identity can dial, and a request
    // for a session that it answers only after `session_delay_ms` (with a session that has no edge routers).
    class FakeDialController {
    public:
        explicit FakeDialController(unsigned session_delay_ms)
                : session_delay_ms_(session_delay_ms),
                  server_([this](const std::string &method, const std::string &path) {
                      return respond(method, path);
                  }) {}

        std::string url() const { return server_.url(); }

        // the request for a session has reached the controller
        bool session_requested() const { return requested_; }

        // the delayed answer to the request for a session has been sent
        bool session_answered() const { return answered_; }

    private:
        static bool ends_with(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        static std::string iso8601(time_t t) {
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

        std::string respond(const std::string &method, const std::string &path) {
            if (ends_with(path, "/version")) {
                return json_response("200 OK", R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                                      R"("runtimeVersion":"fake","capabilities":[],"buildFlags":[],)"
                                      R"("apiVersions":{"edge":{"v1":{"path":"/edge/client/v1"}}}},"meta":{}})");
            }
            if (ends_with(path, "/authenticate")) {
                time_t now = time(nullptr);
                return json_response("200 OK",
                                     R"({"data":{"id":"fake-session","token":"fake-token","identityId":"fake-id",)"
                                     R"("expiresAt":")" + iso8601(now + 1800) + R"(",)" +
                                     R"("updatedAt":")" + iso8601(now) + R"(",)" +
                                     R"("cachedLastActivityAt":")" + iso8601(now) + R"(",)" +
                                     R"("authQueries":[],"identity":{"id":"fake-id","name":"fake"}},"meta":{}})");
            }
            if (ends_with(path, "/services")) {
                return json_response("200 OK", R"({"data":[{"id":"svc-id","name":"svc","permissions":["Dial"],)"
                                      R"("encryptionRequired":false}],"meta":{}})");
            }
            if (method == "POST" && ends_with(path, "/sessions")) {
                requested_ = true;
                std::this_thread::sleep_for(std::chrono::milliseconds(session_delay_ms_));
                answered_ = true;
                return json_response("201 Created", R"({"data":{"id":"dial-session","token":"dial-token",)"
                                      R"("apiSessionId":"fake-session","serviceId":"svc-id","edgeRouters":[]},"meta":{}})");
            }
            return not_found();
        }

        const unsigned session_delay_ms_;
        std::atomic<bool> requested_{false};
        std::atomic<bool> answered_{false};
        FakeHttpServer server_;
    };

    // one loop for every case: creating and closing a loop per case trips libuv's fd assertion when
    // the whole suite runs in one process
    inline uv_loop_t *test_loop() {
        static uv_loop_t *loop = uv_loop_new();
        return loop;
    }

    struct context_run {
        ziti_context ztx = nullptr;
        int fully_authenticated = 0; // ZitiContextEvent with ZITI_OK
        int auth_failed = 0;         // ZitiContextEvent with ZITI_AUTHENTICATION_FAILED
    };

    // Runs a context, with the identity of tls_test_util.h, against the controller at `url` until
    // `done` says so (it is asked every 50 ms, with the state of the run) or `timeout_ms` have passed, then shuts it down.
    inline context_run run_context(const std::string &url, unsigned timeout_ms,
                                   const std::function<bool(const context_run &)> &done = nullptr) {
        context_run run;

        // FAKE_CTRL_LOG=<level> prints the SDK log of the context to stderr
        if (const char *level = getenv("FAKE_CTRL_LOG")) {
            ziti_log_set_logger([](int lvl, const char *loc, const char *msg, size_t len) {
                fprintf(stderr, "%d %s %.*s\n", lvl, loc, (int) len, msg);
            });
            ziti_log_set_level(atoi(level), nullptr);
        }

        std::string key = std::string("pem:") + rsa_key;
        std::string cert = std::string("pem:") + rsa_cert;
        std::string controller = url;
        ziti_config cfg = {};
        cfg.controller_url = (char *) controller.c_str();
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
        // would have the timers below fire right away
        uv_update_time(loop);
        REQUIRE(ziti_context_run(run.ztx, loop) == ZITI_OK);

        struct poll_state {
            context_run *run;
            const std::function<bool(const context_run &)> *done;
            uint64_t deadline;
        } state = {&run, &done, uv_now(loop) + timeout_ms};

        uv_timer_t poll;
        uv_timer_init(loop, &poll);
        poll.data = &state;
        uv_timer_start(&poll, [](uv_timer_t *t) {
            auto s = (poll_state *) t->data;
            if (uv_now(t->loop) >= s->deadline || (*s->done && (*s->done)(*s->run))) {
                ziti_shutdown(s->run->ztx);
                uv_close((uv_handle_t *) t, nullptr);
            }
        }, 50, 50);

        // unref'd: it ends a hung shutdown but does not keep a finished loop alive
        uv_timer_t guard;
        uv_timer_init(loop, &guard);
        uv_unref((uv_handle_t *) &guard);
        uv_timer_start(&guard, [](uv_timer_t *t) { uv_stop(t->loop); }, timeout_ms + 10000, 0);

        uv_run(loop, UV_RUN_DEFAULT);
        uv_close((uv_handle_t *) &guard, nullptr);
        uv_run(loop, UV_RUN_DEFAULT);
        return run;
    }
}
