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

// GH-1165: a listener whose lookup of the edge routers of its service fails (the request is lost on
// the way to the controller) was left without terminators for good: the Bind session is created and
// the app is told ZITI_OK, but with no routers nothing binds, nothing looks the routers up again, and
// an edge router connecting cancelled the retry that there might have been.
//
// These tests drive a real ziti_context against a fake legacy controller that hosts one service the
// identity can bind, and drops the first requests for the routers of that service.

#include "fake_controller.h"

#include "catch2_includes.hpp"

#include <ctime>

using namespace fake_controller;

// internal: the api session token, which the context has only while it is authenticated
extern "C" const char *ziti_get_api_session_token(ziti_context ztx);
// internal: bind.c, what an edge router connecting does to the listeners
extern "C" void conn_update_bindings(ziti_connection conn, bool force_rebind);
// ztx_test_helper.c: a re-bind of the listener is scheduled
extern "C" bool ztx_test_rebind_pending(ziti_connection conn);

namespace {
    const char *const ROUTERS_OF_SVC = "/services/svc-id/edge-routers";

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

    // A legacy (non-OIDC) controller with the service "svc", which the identity can bind. A lookup of
    // the routers of the service gets no response at all, which the SDK sees as the controller being
    // unavailable, the first `failed_lookups` times; after that the service has no routers.
    class FakeBindController {
    public:
        explicit FakeBindController(int failed_lookups)
                : failed_lookups_(failed_lookups),
                  server_([this](const std::string &method, const std::string &path) {
                      return respond(method, path);
                  }) {}

        std::string url() const { return server_.url(); }

        // lookups of the routers of the service received so far
        int lookups() const { return server_.count(ROUTERS_OF_SVC); }

    private:
        static bool ends_with(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
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
                return json_response("200 OK", R"({"data":[{"id":"svc-id","name":"svc","permissions":["Bind"],)"
                                      R"("encryptionRequired":false}],"meta":{}})");
            }
            if (ends_with(path, ROUTERS_OF_SVC)) {
                // the request is already counted
                if (server_.count(ROUTERS_OF_SVC) <= failed_lookups_) return "";
                return json_response("200 OK", R"({"data":{"edgeRouters":[]},"meta":{}})");
            }
            if (method == "POST" && ends_with(path, "/sessions")) {
                return json_response("201 Created", R"({"data":{"id":"bind-session","token":"bind-token",)"
                                      R"("apiSessionId":"fake-session","serviceId":"svc-id","edgeRouters":[]},"meta":{}})");
            }
            return not_found();
        }

        const int failed_lookups_;
        FakeHttpServer server_;
    };

    // Runs a context against `ctrl` and has it listen on "svc" as soon as it is authenticated. `tick` is
    // asked every 50 ms with the listener, and returns true to end the run (the listener is closed first).
    template<typename Tick>
    void run_listener(FakeBindController &ctrl, Tick tick) {
        ziti_connection conn = nullptr;
        bool closed = false;

        run_context(ctrl.url(), 10000, [&](const context_run &run) {
            if (conn == nullptr) {
                if (ziti_get_api_session_token(run.ztx) == nullptr) return false;
                REQUIRE(ziti_conn_init(run.ztx, &conn, nullptr) == ZITI_OK);
                REQUIRE(ziti_listen(conn, "svc",
                                    [](ziti_connection, int) {},
                                    [](ziti_connection, ziti_connection, int, const ziti_client_ctx *) {}) == ZITI_OK);
                return false;
            }
            if (!closed && tick(conn)) {
                // the context disposes of the closed listener on its next turn, before it is shut down
                ziti_close(conn, [](ziti_connection) {});
                closed = true;
                return false;
            }
            return closed;
        });
    }
}

TEST_CASE("a listener looks the routers of its service up again when the lookup failed", "[bind][GH-1165]") {
    FakeBindController ctrl(1);

    run_listener(ctrl, [&](ziti_connection) { return ctrl.lookups() >= 2; });

    CHECK(ctrl.lookups() >= 2);
}

TEST_CASE("an edge router connecting leaves the retry of a failed router lookup in place", "[bind][GH-1165]") {
    // true: what the context does when it is told to rebind all its listeners
    bool force = GENERATE(false, true);
    CAPTURE(force);

    // enough failures for a tick to catch a retry that is waiting
    FakeBindController ctrl(3);

    bool updated = false;
    bool pending_after = false;
    int lookups_at_update = 0;
    run_listener(ctrl, [&](ziti_connection conn) {
        if (!updated && ztx_test_rebind_pending(conn)) {
            lookups_at_update = ctrl.lookups();
            conn_update_bindings(conn, force);
            pending_after = ztx_test_rebind_pending(conn);
            updated = true;
        }
        return updated && ctrl.lookups() > lookups_at_update;
    });

    REQUIRE(updated);
    CHECK(pending_after);
    CHECK(ctrl.lookups() > lookups_at_update);
}
