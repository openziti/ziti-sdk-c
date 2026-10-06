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

#include "catch2_includes.hpp"

// model_support.h #defines `map`: the standard headers go first
#include <string>
#include <vector>

// same include order as multipart_tests.cpp, see the note there
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}

#include "connect.h"
#include "edge_protocol.h"
#include "endian_internal.h"
#include "zt_internal.h"

extern "C" void connect_reply_cb(void *ctx, message *msg, int err);

namespace {
    // stands in for a tls 1.2 session: not ready until a decrypt brings in the peer's last flight
    struct fake_e2ee {
        e2ee_t api{};
        bool ready = false;
        bool fail_decrypt = false;
        int decrypts = 0;
    };

    fake_e2ee *as_fake(e2ee_t *e) { return (fake_e2ee *) e; }

    int fake_init(e2ee_t *, const uint8_t *, size_t, bool) { return 0; }
    ssize_t fake_get_header(e2ee_t *, uint8_t *) { return 0; }
    bool fake_ready(e2ee_t *e) { return as_fake(e)->ready; }
    void fake_free(e2ee_t *) {}

    ssize_t fake_decrypt(e2ee_t *e, const uint8_t *, size_t, uint8_t *, size_t) {
        auto f = as_fake(e);
        f->decrypts++;
        if (f->fail_decrypt) {
            return -1;
        }
        f->ready = true;
        return 0;
    }

    void install(fake_e2ee &f, ziti_connection conn) {
        f.api.method = conn->e2ee ? conn->e2ee->method : ziti_crypto_none;
        f.api.init = fake_init;
        f.api.get_header = fake_get_header;
        f.api.decrypt = fake_decrypt;
        f.api.ready = fake_ready;
        f.api.free = fake_free;
        if (conn->e2ee) {
            conn->e2ee->free(conn->e2ee);
        }
        conn->e2ee = &f.api;
    }

    // ztx_process_deadlines is static: run the due deadlines the same way
    void run_due(ziti_context ztx) {
        std::vector<deadline_t *> expired;
        deadline_t *d;
        while ((d = LIST_FIRST(&ztx->deadlines)) != nullptr && uv_now(ztx->loop) >= d->expiration) {
            LIST_REMOVE(d, _next);
            d->_next.le_prev = nullptr;
            expired.push_back(d);
        }
        for (auto e: expired) {
            if (e->expire_cb == nullptr || e->_next.le_prev != nullptr) {
                continue;
            }
            auto cb = e->expire_cb;
            e->expire_cb = nullptr;
            cb(e->ctx);
        }
    }

    // flushers re-arm at the same time: run until only future deadlines are left
    void run_all_due(ziti_context ztx) {
        for (int i = 0; i < 16; i++) {
            deadline_t *d = LIST_FIRST(&ztx->deadlines);
            if (d == nullptr || uv_now(ztx->loop) < d->expiration) {
                return;
            }
            run_due(ztx);
        }
        FAIL("deadlines keep firing");
    }

    message *conn_msg(uint32_t content, uint32_t rt_conn_id, const std::string &body) {
        int32_t conn_id = (int32_t) htole32(rt_conn_id);
        hdr_t hdrs[] = {
            {ConnIdHeader, sizeof(conn_id), (const uint8_t *) &conn_id},
        };
        message *m = message_new(nullptr, content, hdrs, 1, body.size());
        memcpy(m->body, body.data(), body.size());
        return m;
    }

    struct app_recorder {
        std::vector<int> conn_cb;
        std::vector<ssize_t> data_cb;
        std::vector<ssize_t> write_cb;
    };

    app_recorder *app_of(ziti_connection conn) { return (app_recorder *) ziti_conn_data(conn); }

    void on_conn(ziti_connection conn, int status) { app_of(conn)->conn_cb.push_back(status); }

    ssize_t on_data(ziti_connection conn, const uint8_t *data, ssize_t len) {
        if (data == nullptr) {
            app_of(conn)->data_cb.push_back(len);
        }
        return len;
    }

    void on_write(ziti_connection conn, ssize_t status, void *) { app_of(conn)->write_cb.push_back(status); }

    struct ztx_fixture {
        // needed only so uv_now() has a loop->time, never inited
        uv_loop_t loop{};
        ziti_ctx ztx{};
        app_recorder app;
        fake_e2ee e2ee;

        ztx_fixture() {
            ztx.loop = &loop;
            ztx.enabled = true;
            ztx.auth_state = ZitiAuthStateFullyAuthenticated;
        }

        void flush(ziti_connection conn) {
            // setting the data_cb with a queued message arms the flusher
            REQUIRE(ziti_conn_set_data_cb(conn, conn->data_cb) == ZITI_OK);
            run_all_due(&ztx);
        }

        void receive(ziti_connection conn, uint32_t content, const std::string &body) {
            // TAILQ_INSERT_TAIL evaluates the element more than once
            message *m = conn_msg(content, conn->rt_conn_id, body);
            TAILQ_INSERT_TAIL(&conn->in_q, m, _next);
            flush(conn);
        }

        void dispose(ziti_connection conn) {
            // ziti_close would send StateClosed over the channel
            conn->channel = nullptr;
            conn->state = Closed;
            CHECK(conn->disposer(conn) == 1);
        }
    };

    // a dial with no edge router channel: the conn_req timer is the real one process_connect arms
    struct dial_fixture : ztx_fixture {
        ziti_edge_router er{};
        ziti_session session{};
        ziti_service service{};
        ziti_connection conn;

        dial_fixture() {
            er.name = (char *) "er";
            session.id = (char *) "session";
            model_list_append(&session.edge_routers, &er);
            service.name = (char *) "svc";
            service.id = (char *) "svc-id";
            service.perm_flags = ZITI_CAN_DIAL;
            model_map_set(&ztx.services, service.name, &service);
            model_map_set(&ztx.sessions, service.id, &session);

            conn = (ziti_connection) calloc(1, sizeof(*conn));
            conn->ziti_ctx = &ztx;
            ziti_conn_set_data(conn, &app);
            REQUIRE(ziti_dial(conn, "svc", on_conn, on_data) == ZITI_OK);
            REQUIRE(conn->state == Connecting);
            conn->rt_conn_id = 7;
            install(e2ee, conn);

            int32_t conn_id = (int32_t) htole32(conn->rt_conn_id);
            hdr_t hdrs[] = {
                {ConnIdHeader, sizeof(conn_id), (const uint8_t *) &conn_id},
                {PublicKeyHeader, 4, (const uint8_t *) "peer"},
            };
            message *m = message_new(nullptr, ContentTypeStateConnected, hdrs, 2, 0);
            connect_reply_cb(conn, m, 0);
            pool_return_obj(m);
            run_all_due(&ztx);
        }

        ~dial_fixture() {
            dispose(conn);
            model_map_clear(&ztx.services, nullptr);
            model_map_clear(&ztx.sessions, nullptr);
            model_map_clear(&ztx.waiting_connections, nullptr);
            model_list_clear(&session.edge_routers, nullptr);
        }

        void advance(uint64_t ms) {
            loop.time += ms;
            run_all_due(&ztx);
        }
    };
}

TEST_CASE("tls 1.2 dial waits for the e2ee handshake", "[e2ee]") {
    dial_fixture f;

    // the host's last flight has not arrived: Connected so data gets processed, but no conn cb yet
    REQUIRE(f.conn->state == Connected);
    REQUIRE(f.app.conn_cb.empty());

    SECTION("the conn cb fires when a decrypt completes the handshake") {
        f.advance(ZITI_DEFAULT_TIMEOUT / 2);
        CHECK(f.app.conn_cb.empty());

        f.receive(f.conn, ContentTypeData, "flight");
        CHECK(f.e2ee.decrypts == 1);
        CHECK(f.app.conn_cb == std::vector<int>{ZITI_OK});
        CHECK(f.conn->state == Connected);
        CHECK(TAILQ_EMPTY(&f.conn->wreqs));

        // the dial timer is gone with the conn cb
        f.advance(ZITI_DEFAULT_TIMEOUT);
        CHECK(f.app.conn_cb == std::vector<int>{ZITI_OK});
        CHECK(f.conn->state == Connected);
        CHECK(f.app.data_cb.empty());
    }

    SECTION("a host that never sends its last flight times out the dial") {
        f.advance(ZITI_DEFAULT_TIMEOUT);
        CHECK(f.app.conn_cb == std::vector<int>{ZITI_TIMEOUT});
        CHECK(f.conn->data_cb == nullptr);
        CHECK(f.conn->state == Disconnected);
    }

    SECTION("a failed decrypt fails the dial, not the data cb") {
        f.e2ee.fail_decrypt = true;
        f.receive(f.conn, ContentTypeData, "flight");
        CHECK(f.app.conn_cb == std::vector<int>{ZITI_CRYPTO_FAIL});
        CHECK(f.app.data_cb.empty());

        f.advance(ZITI_DEFAULT_TIMEOUT);
        CHECK(f.app.conn_cb == std::vector<int>{ZITI_CRYPTO_FAIL});
    }

    SECTION("StateClosed before the handshake fails the dial") {
        f.receive(f.conn, ContentTypeStateClosed, "closed");
        CHECK(f.app.conn_cb == std::vector<int>{ZITI_CONN_CLOSED});
        CHECK(f.app.data_cb.empty());
        CHECK(f.conn->state == Disconnected);

        f.advance(ZITI_DEFAULT_TIMEOUT);
        CHECK(f.app.conn_cb == std::vector<int>{ZITI_CONN_CLOSED});
    }
}

TEST_CASE("tls 1.3 dial completes on the connect reply", "[e2ee]") {
    // a tls 1.3 client is ready once establish_crypto returns
    ztx_fixture f;
    ziti_edge_router er{};
    er.name = (char *) "er";
    ziti_session session{};
    session.id = (char *) "session";
    model_list_append(&session.edge_routers, &er);
    ziti_service service{};
    service.name = (char *) "svc";
    service.id = (char *) "svc-id";
    service.perm_flags = ZITI_CAN_DIAL;
    model_map_set(&f.ztx.services, service.name, &service);
    model_map_set(&f.ztx.sessions, service.id, &session);

    auto conn = (ziti_connection) calloc(1, sizeof(struct ziti_conn));
    conn->ziti_ctx = &f.ztx;
    ziti_conn_set_data(conn, &f.app);
    REQUIRE(ziti_dial(conn, "svc", on_conn, on_data) == ZITI_OK);
    install(f.e2ee, conn);
    f.e2ee.ready = true;

    message *m = conn_msg(ContentTypeStateConnected, 7, "");
    connect_reply_cb(conn, m, 0);
    pool_return_obj(m);
    CHECK(f.app.conn_cb == std::vector<int>{ZITI_OK});
    CHECK(conn->state == Connected);

    f.loop.time += ZITI_DEFAULT_TIMEOUT;
    run_all_due(&f.ztx);
    CHECK(f.app.conn_cb == std::vector<int>{ZITI_OK});

    f.dispose(conn);
    model_map_clear(&f.ztx.services, nullptr);
    model_map_clear(&f.ztx.sessions, nullptr);
    model_map_clear(&f.ztx.waiting_connections, nullptr);
    model_list_clear(&session.edge_routers, nullptr);
}

TEST_CASE("host holds writes until the e2ee handshake completes", "[e2ee]") {
    ztx_fixture f;
    auto conn = (ziti_connection) calloc(1, sizeof(struct ziti_conn));
    conn->ziti_ctx = &f.ztx;
    conn->rt_conn_id = 7;
    init_transport_conn(conn);
    install(f.e2ee, conn);
    conn->state = Connected;
    conn->data_cb = on_data;
    ziti_conn_set_data(conn, &f.app);
    // flush_to_service only needs it non-NULL to get to the hold, nothing on this path reads it
    conn->channel = (ziti_channel_t *) &f;

    REQUIRE(ziti_write(conn, (const uint8_t *) "one", 3, on_write, nullptr) == ZITI_OK);
    REQUIRE(ziti_write(conn, (const uint8_t *) "two", 3, on_write, nullptr) == ZITI_OK);
    run_all_due(&f.ztx);
    CHECK(f.app.write_cb.empty());
    CHECK(!TAILQ_EMPTY(&conn->wreqs));
    // no timer keeps the hold
    CHECK(LIST_EMPTY(&f.ztx.deadlines));

    // the dialer timed out or failed and the circuit closed
    f.receive(conn, ContentTypeStateClosed, "closed");
    CHECK(conn->state == Disconnected);
    CHECK(f.app.data_cb == std::vector<ssize_t>{ZITI_CONN_CLOSED});
    CHECK(f.app.write_cb == std::vector<ssize_t>{ZITI_INVALID_STATE, ZITI_INVALID_STATE});
    CHECK(TAILQ_EMPTY(&conn->wreqs));

    f.dispose(conn);
}
