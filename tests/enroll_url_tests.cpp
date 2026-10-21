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

// GH-795: enrolling from a URL whose certificate the OS does not trust reported the failure as
// "software caused connection abort", the libuv text for any failed TLS handshake, and said nothing
// about the certificate. The "controller" here is a TLS listener with the self-signed certificate of
// tls_test_util.h, which the default trust store does not know.

#include "fake_controller.h"

#include "catch2_includes.hpp"

#include <ziti/enroll.h>
#include <tlsuv/listener.h>
#include <tlsuv/tlsuv.h>

using namespace fake_controller;

namespace {
    // runs the loop until `cond` holds or `timeout_ms` have passed
    template<typename Cond>
    bool run_until(uv_loop_t *loop, Cond cond, uint64_t timeout_ms) {
        // the tick keeps uv_run() from blocking while nothing happens
        uv_timer_t tick;
        uv_timer_init(loop, &tick);
        uv_timer_start(&tick, [](uv_timer_t *) {}, 20, 20);

        uv_update_time(loop);
        uint64_t deadline = uv_now(loop) + timeout_ms;
        while (!cond() && uv_now(loop) < deadline) {
            uv_run(loop, UV_RUN_ONCE);
        }

        uv_close((uv_handle_t *) &tick, nullptr);
        uv_run(loop, UV_RUN_NOWAIT); // the close callback of `tick` runs here
        return cond();
    }

    // The client turns the certificate down, so the handshake never completes on this side either:
    // the listener only has to close what it accepts.
    tlsuv_stream_t *accept_conn(tlsuv_listener_t *, const struct sockaddr *, int status) {
        return status == 0 ? tlsuv_stream_new() : nullptr;
    }

    void handshake_done(tlsuv_stream_t *stream, int) {
        tlsuv_stream_close(stream, [](uv_handle_t *h) { tlsuv_stream_delete((tlsuv_stream_t *) h); });
    }

    // TLS server on a loopback port, with the self-signed identity of tls_test_util.h
    struct tls_server {
        uv_loop_t *loop;
        tls_context *tls = default_tls_context();
        tlsuv_private_key_t key = nullptr;
        tlsuv_certificate_t cert = nullptr;
        tlsuv_listener_t *listener = tlsuv_listener_new();
        bool bound = false;
        bool closed = false;

        explicit tls_server(uv_loop_t *l) : loop(l) {
            tlsuv_listener_set_data(listener, this);
        }

        tls_server(const tls_server &) = delete;

        // returns the port, or a libuv error: UV_ENOTSUP when the TLS backend has no server engine
        int start() {
            if (tls->load_key(&key, rsa_key, strlen(rsa_key)) != 0 ||
                tls->load_cert(&cert, rsa_cert, strlen(rsa_cert)) != 0 ||
                tls->set_own_cert(tls, key, cert) != 0) {
                return UV_EINVAL;
            }

            int rc = tlsuv_listener_init(loop, listener, tls);
            if (rc != 0) return rc;

            sockaddr_in addr{};
            uv_ip4_addr("127.0.0.1", 0, &addr);
            rc = tlsuv_listener_bind(listener, (const sockaddr *) &addr, 0);
            if (rc != 0) return rc;
            bound = true;

            rc = tlsuv_listener_start_listen(listener, 8, accept_conn, handshake_done);
            if (rc != 0) return rc;

            sockaddr_storage name{};
            int len = sizeof(name);
            rc = tlsuv_listener_getsockname(listener, (sockaddr *) &name, &len);
            return rc != 0 ? rc : ntohs(((sockaddr_in *) &name)->sin_port);
        }

        ~tls_server() {
            if (bound) {
                tlsuv_listener_close(listener, [](uv_handle_t *h) {
                    static_cast<tls_server *>(uv_handle_get_data(h))->closed = true;
                });
                run_until(loop, [this] { return closed; }, 5000);
            }
            // streams and the client side of the connection finish closing
            for (int i = 0; i < 5; i++) uv_run(loop, UV_RUN_NOWAIT);

            tlsuv_listener_delete(listener);
            if (cert) cert->free(cert);
            if (key) key->free(key);
            tls->free_ctx(tls);
        }
    };

    struct enroll_outcome {
        bool called = false;
        int status = ZITI_OK;
        std::string message;
    };
}

TEST_CASE("enroll from a URL with an untrusted certificate", "[enroll][GH-795]") {
    persisted_key_cleanup key_cleanup;
    uv_loop_t *loop = test_loop();

    tls_server server(loop);
    int port = server.start();
    if (port == UV_ENOTSUP) {
        SKIP("the TLS backend has no server engine");
    }
    REQUIRE(port > 0);

    std::string url = "https://127.0.0.1:" + std::to_string(port);
    ziti_enroll_opts opts{};
    opts.url = url.c_str();

    enroll_outcome outcome;
    REQUIRE(ziti_enroll(&opts, loop, [](const ziti_config *, int status, const char *err, void *ctx) {
        auto o = static_cast<enroll_outcome *>(ctx);
        o->called = true;
        o->status = status;
        o->message = err ? err : "";
    }, &outcome) == ZITI_OK);

    REQUIRE(run_until(loop, [&] { return outcome.called; }, 10000));

    INFO("message: " << outcome.message);
    CHECK(outcome.status == ZITI_CONTROLLER_UNAVAILABLE);
    CHECK_FALSE(outcome.message.empty());
    // what libuv says about any failed handshake: nothing about the certificate
    CHECK(outcome.message != uv_strerror(UV_ECONNABORTED));
}
