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

// Reproduces the "api_session_cb bare return" bug: ztx_set_fully_authenticated()
// fires ca_bundle_cb/update_identity_data/api_session_cb as one-shot,
// fire-and-forget requests right after login. Unlike update_identity_data
// (retried by the recurring services-refresh timer), api_session_cb has no
// periodic counterpart. Before the fix, a single transient failure of
// GET /current-api-session left ztx->session permanently NULL - silently,
// with no further error ever logged - for the life of the process. That
// exact signature (a burst of controller requests failing with -3008 a few
// ms after a successful request to the same host) is what two independent
// customer devices hit within ~2s of boot; see
// journalctl-ziti.out / justin-2-journalctl-ziti.log discussed on the
// ctrl_next_ep underflow investigation.
//
// This test drives a real ziti_context through a real login against a real
// controller, but through a toggleable TCP relay instead of talking to the
// controller directly. The moment login succeeds (ziti_auth_success), the
// relay is told to refuse new connections for a short window, then allowed
// through again - reproducing "one transient failure right after auth"
// without needing to touch any process-clock trickery. Requires the
// `test_client` env var (path to an enrolled identity file for the target
// controller) - see enroll_test_helpers.h / sample_enroll for how to
// produce one.

#include "fixtures.h"
#include "zt_internal.h"

#include <atomic>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace {

// A dumb byte-splicing TCP relay that can be told to refuse new connections
// on demand, without touching connections already established. Runs on raw
// blocking POSIX sockets on background threads, independent of the test's
// uv_loop, so it can't be starved by (or interfere with) the ziti_context
// under test.
class TogglableRelay {
public:
    std::atomic<bool> refuse{false};
    uint16_t port{};

    TogglableRelay(std::string upstream_host, uint16_t upstream_port)
        : upstream_host_(std::move(upstream_host)), upstream_port_(upstream_port) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        // Qualified with :: - unqualified bind() silently resolves to
        // std::bind (via <functional>, pulled in transitively) and just
        // constructs-and-discards a functor instead of calling the syscall.
        int rc = ::bind(listen_fd_, (sockaddr *) &addr, sizeof(addr));
        REQUIRE(rc == 0);

        socklen_t len = sizeof(addr);
        REQUIRE(getsockname(listen_fd_, (sockaddr *) &addr, &len) == 0);
        port = ntohs(addr.sin_port);

        listen(listen_fd_, 16);
        accept_thread_ = std::thread([this] { acceptLoop(); });
    }

    ~TogglableRelay() {
        stop_ = true;
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        if (accept_thread_.joinable()) accept_thread_.join();
    }

private:
    void acceptLoop() {
        while (!stop_) {
            int client = accept(listen_fd_, nullptr, nullptr);
            if (client < 0) {
                if (stop_) return;
                continue;
            }
            if (refuse.load()) {
                // SO_LINGER=0 forces an RST on close instead of a graceful
                // FIN, so the client's TLS handshake fails immediately
                // instead of sitting on a read timeout.
                linger lin{1, 0};
                setsockopt(client, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
                close(client);
                continue;
            }
            std::thread(&TogglableRelay::serveConnection, this, client).detach();
        }
    }

    void serveConnection(int client) {
        int upstream = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(upstream_port_);
        inet_pton(AF_INET, upstream_host_.c_str(), &addr.sin_addr);
        if (connect(upstream, (sockaddr *) &addr, sizeof(addr)) != 0) {
            close(client);
            return;
        }
        std::thread c2u(&TogglableRelay::pump, this, client, upstream);
        pump(upstream, client);
        c2u.join();
        close(client);
        close(upstream);
    }

    void pump(int from, int to) {
        char buf[8192];
        ssize_t n;
        while ((n = recv(from, buf, sizeof(buf), 0)) > 0) {
            if (send(to, buf, n, 0) <= 0) break;
        }
        shutdown(to, SHUT_WR);
    }

    std::string upstream_host_;
    uint16_t upstream_port_;
    int listen_fd_{};
    std::atomic<bool> stop_{false};
    std::thread accept_thread_;
};

std::string read_file(const std::string &path) {
    std::ifstream f(path);
    REQUIRE(f.good());
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Finds the host:port in the identity file's first "ztAPI":"https://HOST:PORT..."
// occurrence - that's the real controller this identity would otherwise talk to.
struct HostPort {
    std::string host;
    uint16_t port{};

    std::string str() const { return host + ":" + std::to_string(port); }
};

HostPort find_ztapi_hostport(const std::string &content) {
    auto marker = content.find("\"ztAPI\":\"https://");
    REQUIRE(marker != std::string::npos);
    auto hostStart = marker + strlen("\"ztAPI\":\"https://");
    auto hostEnd = content.find_first_of(":/\"", hostStart);
    REQUIRE(hostEnd != std::string::npos);
    std::string host = content.substr(hostStart, hostEnd - hostStart);

    uint16_t port = 443;
    if (content[hostEnd] == ':') {
        auto portStart = hostEnd + 1;
        auto portEnd = content.find_first_of("/\"", portStart);
        port = (uint16_t) std::stoi(content.substr(portStart, portEnd - portStart));
    }
    return {host, port};
}

// Replaces every occurrence of oldHostPort (covers both ztAPI and ztAPIs[])
// with newHostPort.
std::string rewrite_hostport(const std::string &content, const std::string &oldHostPort,
                              const std::string &newHostPort) {
    std::string rewritten = content;
    size_t pos = 0;
    while ((pos = rewritten.find(oldHostPort, pos)) != std::string::npos) {
        rewritten.replace(pos, oldHostPort.length(), newHostPort);
        pos += newHostPort.length();
    }
    return rewritten;
}

} // namespace

// Drives a real ziti_context through the relay. This intentionally does
// NOT reuse ZitiTestCase (fixtures.h): it needs a chance to redirect the
// identity's ztAPI through the relay before ziti_context_run(), and its own
// event_cb to flip the relay off/on around the auth-success transition.
class ApiSessionRetryTestCase : public LoopTestCase {
protected:
    ziti_config config{};
    ziti_context ztx{};
    ziti_auth_action lastAuthAction{};
    int ctrlStatus{};

    ~ApiSessionRetryTestCase() {
        if (ztx) ziti_shutdown(ztx);
        free_ziti_config(&config);
    }

    static void event_cb(ziti_context ztx, const ziti_event_t *ev) {
        auto self = (ApiSessionRetryTestCase *) ziti_app_ctx(ztx);
        switch (ev->type) {
            case ZitiAuthEvent:
                self->lastAuthAction = ev->auth.action;
                break;
            case ZitiContextEvent:
                self->ctrlStatus = ev->ctx.ctrl_status;
                break;
            default:
                break;
        }
    }

    static const char *test_client() { return BaseTestCase::checkENV("test_client"); }
};

TEST_CASE_METHOD(ApiSessionRetryTestCase, "api-session-recovers-after-transient-failure", "[integ][api-session]") {
    // Discover the real controller's host:port from the enrolled identity,
    // stand up a relay pointed at it, and redirect the identity through the
    // relay instead.
    std::string original = read_file(test_client());
    HostPort realCtrl = find_ztapi_hostport(original);
    TogglableRelay relay(realCtrl.host, realCtrl.port);
    std::string redirected = rewrite_hostport(original, realCtrl.str(), "127.0.0.1:" + std::to_string(relay.port));

    char tmpPath[] = "/tmp/api_session_retry_identity.XXXXXX";
    int fd = mkstemp(tmpPath);
    REQUIRE(fd >= 0);
    REQUIRE(write(fd, redirected.data(), redirected.size()) == (ssize_t) redirected.size());
    close(fd);
    DEFER { unlink(tmpPath); };

    REQUIRE_ZITI_OK(ziti_load_config(&config, tmpPath));
    REQUIRE_ZITI_OK(ziti_context_init(&ztx, &config));

    ziti_options options{
        .config_types = (const char **) ALL_CONFIGS,
        .app_ctx = this,
        .events = ZitiContextEvent | ZitiAuthEvent,
        .event_cb = event_cb,
    };
    REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &options));
    REQUIRE_ZITI_OK(ziti_context_run(ztx, loop()));

    // Wait for login to succeed, then immediately break the relay for a
    // short, transient window - the same shape as the DNS blip in the field
    // logs, just forced deterministically instead of by luck at boot.
    REQUIRE(run(UNTIL(lastAuthAction == ziti_auth_success), 15000));
    relay.refuse = true;
    run(WHILE(true), 800); // hold the outage briefly with the loop still spinning
    relay.refuse = false;

    // ztx->session is only ever set by api_session_cb's success path. Before
    // the fix, a failure here (from the relay outage above) leaves it NULL
    // forever - this is the exact "partially authenticated" symptom from
    // ziti_send_posture_data()'s ztx->session == NULL check. After the fix,
    // api_session_retry() re-issues the request ~5s later and it succeeds.
    bool recovered = run(UNTIL(ztx->session != nullptr), 15000);
    CHECK(recovered);
    CHECK(ztx->session != nullptr);
}
