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

// stc/cstr.h declares _cstr_init as plain `extern`, which mangles under C++; common.h first, then cstr.h
// under C linkage, satisfies both without wrapping connect.h (that breaks stc's C++ templates).
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}

#include "connect.h"
#include "edge_protocol.h"
#include "endian_internal.h"
#include "zt_internal.h"

namespace {
    std::string drain(buffer *b) {
        std::string out;
        uint8_t *chunk;
        ssize_t n;
        while ((n = buffer_get_next(b, SIZE_MAX, &chunk)) > 0) {
            out.append((const char *) chunk, n);
        }
        return out;
    }

    // the payload sits at the front of a buffer larger than any part length, so a parser that reads
    // past len stays inside memory the test owns and the test fails instead of crashing
    ssize_t parse(buffer *b, const std::string &payload) {
        std::vector<uint8_t> mem(UINT16_MAX + 16, 0);
        memcpy(mem.data(), payload.data(), payload.size());
        return conn_parse_multipart(b, mem.data(), payload.size());
    }
}

TEST_CASE("multipart payload parsing", "[multipart]") {
    buffer *b = new_buffer();

    SECTION("parts are appended in order") {
        CHECK(parse(b, std::string("\x03\x00" "abc" "\x02\x00" "de", 9)) == 5);
        CHECK(drain(b) == "abcde");
    }

    SECTION("an empty last part is valid") {
        CHECK(parse(b, std::string("\x01\x00" "a" "\x00\x00", 5)) == 1);
        CHECK(drain(b) == "a");
    }

    SECTION("a part length past the payload is rejected") {
        CHECK(parse(b, std::string("\xff\xff" "A", 3)) == -1);
        CHECK(buffer_available(b) == 0);
    }

    SECTION("a payload shorter than a length prefix is rejected") {
        CHECK(parse(b, std::string("\x01", 1)) == -1);
        CHECK(buffer_available(b) == 0);
    }

    SECTION("a truncated second length prefix is rejected with nothing appended") {
        CHECK(parse(b, std::string("\x01\x00" "a" "\x05", 4)) == -1);
        CHECK(buffer_available(b) == 0);
    }

    free_buffer(b);
}

namespace {
    struct app_recorder {
        std::string data;
        std::vector<ssize_t> errors;
    };

    // closes on the first error, as an app does
    ssize_t on_app_data(ziti_connection conn, const uint8_t *data, ssize_t len) {
        auto *app = (app_recorder *) ziti_conn_data(conn);
        if (data == nullptr) {
            app->errors.push_back(len);
            ziti_close(conn, nullptr);
            return 0;
        }
        app->data.append((const char *) data, len);
        return len;
    }

    // a Connected conn with no channel: inbound messages take the real in_q -> flush_to_client path
    struct conn_fixture {
        // needed only so uv_now() has a loop->time when a deadline is armed, never inited
        uv_loop_t loop{};
        ziti_ctx ztx{};
        ziti_connection conn;
        app_recorder app;

        conn_fixture() {
            ztx.loop = &loop;
            conn = (ziti_connection) calloc(1, sizeof(*conn));
            conn->ziti_ctx = &ztx;
            conn->rt_conn_id = 7;
            init_transport_conn(conn);
            conn->e2ee = create_e2ee(ziti_crypto_none, false, nullptr);
            conn->state = Connected;
            ziti_conn_set_data(conn, &app);
        }

        ~conn_fixture() {
            // ziti_close on a Connected conn would send StateClosed over the channel
            conn->state = Closed;
            CHECK(conn->disposer(conn) == 1);
        }

        void receive(const std::string &payload) {
            int32_t conn_id = (int32_t) htole32(conn->rt_conn_id);
            int32_t flags = (int32_t) htole32(EDGE_MULTIPART_MSG);
            hdr_t hdrs[] = {
                {ConnIdHeader, sizeof(conn_id), (const uint8_t *) &conn_id},
                {FlagsHeader, sizeof(flags), (const uint8_t *) &flags},
            };
            message *m = message_new(nullptr, ContentTypeData, hdrs, 2, payload.size());
            memcpy(m->body, payload.data(), payload.size());
            TAILQ_INSERT_TAIL(&conn->in_q, m, _next);

            // setting the data_cb with a queued message arms the flusher
            REQUIRE(ziti_conn_set_data_cb(conn, on_app_data) == ZITI_OK);

            // ztx_process_deadlines is static: run the due deadlines the same way
            deadline_t *d;
            while ((d = LIST_FIRST(&ztx.deadlines)) != nullptr) {
                LIST_REMOVE(d, _next);
                auto cb = d->expire_cb;
                d->expire_cb = nullptr;
                cb(d->ctx);
            }
        }
    };
}

TEST_CASE("multipart message delivery", "[multipart]") {
    conn_fixture f;

    SECTION("a valid message reaches the app") {
        f.receive(std::string("\x03\x00" "abc" "\x02\x00" "de", 9));
        CHECK(f.app.data == "abcde");
        CHECK(f.app.errors.empty());
        CHECK(f.conn->received == 5);
        CHECK(f.conn->state == Connected);
    }

    SECTION("a malformed message ends the conn with nothing delivered") {
        f.receive(std::string("\xff\xff" "A", 3));
        CHECK(f.app.data.empty());
        CHECK(f.app.errors == std::vector<ssize_t>{ZITI_INVALID_STATE});
        CHECK(f.conn->received == 0);
        CHECK(f.conn->state == Closed);
        CHECK(buffer_available(f.conn->inbound) == 0);
    }
}
