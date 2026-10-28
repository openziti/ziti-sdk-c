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

// GH-1181: ziti_listen() and ziti_dial() refuse a disabled context with ZITI_DISABLED before they
// give the connection its type and its disposer. The app is left with a connection that it
// cannot release: closing it had the reaper of the context call a NULL disposer.

#include "fake_controller.h"

#include "catch2_includes.hpp"

using namespace fake_controller;

namespace {
    struct rejected_conn {
        int rc = ZITI_OK;
        int closed = 0;
        int ticks = 0;
        ziti_connection conn = nullptr;
    };

    // Runs a context that the app disables, starts a connection on it with `start` (which the context
    // refuses) and closes that connection, as an app that got ZITI_DISABLED would.
    template<typename Start>
    rejected_conn close_rejected_conn(Start start) {
        FakeHttpServer ctrl([](const std::string &, const std::string &) { return not_found(); });

        rejected_conn t;
        auto done = [&](const context_run &run) {
            switch (++t.ticks) {
                case 1:
                    ziti_set_enabled(run.ztx, false);
                    return false;
                case 4:
                    // the context has had its turns to stop
                    CHECK(ziti_conn_init(run.ztx, &t.conn, &t) == ZITI_OK);
                    t.rc = start(t.conn);
                    ziti_close(t.conn, [](ziti_connection c) {
                        static_cast<rejected_conn *>(ziti_conn_data(c))->closed++;
                    });
                    return false;
                default:
                    // the reaper of the context disposes of the closed connection on its next turn
                    return t.ticks > 4 && (t.closed > 0 || t.ticks > 20);
            }
        };
        run_context(ctrl.url(), 10000, done);
        return t;
    }
}

TEST_CASE("a connection that ziti_listen refused on a disabled context can be closed", "[conn][GH-1181]") {
    rejected_conn t = close_rejected_conn([](ziti_connection conn) {
        return ziti_listen(conn, "svc",
                           [](ziti_connection, int) {},
                           [](ziti_connection, ziti_connection, int, const ziti_client_ctx *) {});
    });

    CHECK(t.rc == ZITI_DISABLED);
    CHECK(t.closed == 1);
}

TEST_CASE("a connection that ziti_dial refused on a disabled context can be closed", "[conn][GH-1181]") {
    rejected_conn t = close_rejected_conn([](ziti_connection conn) {
        return ziti_dial(conn, "svc",
                         [](ziti_connection, int) {},
                         [](ziti_connection, const uint8_t *, ssize_t) -> ssize_t { return 0; });
    });

    CHECK(t.rc == ZITI_DISABLED);
    CHECK(t.closed == 1);
}

// internal: the api session token, which the context has only while it is authenticated
extern "C" const char *ziti_get_api_session_token(ziti_context ztx);

// A dial that the app closes while the controller is still creating its session: the answer of the
// controller comes back to the connection, so the connection has to be there to get it, and the app
// hears nothing more of the dial.
TEST_CASE("a dial that was closed while the controller creates its session", "[conn]") {
    FakeDialController ctrl(500);

    struct dial {
        ziti_connection conn = nullptr;
        bool close_called = false;
        int conn_cb = 0;
        int closed = 0;
        int closed_before_answer = 0;
        int ticks_after_answer = 0;
    } t;

    run_context(ctrl.url(), 10000, [&](const context_run &run) {
        if (t.conn == nullptr) {
            if (ziti_get_api_session_token(run.ztx) == nullptr) return false;

            CHECK(ziti_conn_init(run.ztx, &t.conn, &t) == ZITI_OK);
            CHECK(ziti_dial(t.conn, "svc",
                            [](ziti_connection c, int) { static_cast<dial *>(ziti_conn_data(c))->conn_cb++; },
                            [](ziti_connection, const uint8_t *, ssize_t) -> ssize_t { return 0; }) == ZITI_OK);
            return false;
        }

        if (!t.close_called && ctrl.session_requested()) {
            t.close_called = true;
            ziti_close(t.conn, [](ziti_connection c) { static_cast<dial *>(ziti_conn_data(c))->closed++; });
            return false;
        }

        if (!ctrl.session_answered()) {
            t.closed_before_answer += t.closed;
            return false;
        }

        // the context has had its turns to dispose of the connection
        return ++t.ticks_after_answer > 5;
    });

    CHECK(t.closed_before_answer == 0);
    CHECK(t.closed == 1);
    CHECK(t.conn_cb == 0);
}
