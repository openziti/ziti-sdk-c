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
//


#include <catch2/catch_all.hpp>

#include <tlsuv/tlsuv.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>

// stc/cstr.h declares _cstr_init as plain `extern`, which mangles under C++; common.h first, then cstr.h
// under C linkage, satisfies both without wrapping zt_internal.h (that breaks stc's C++ templates).
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}

#include "crypto.h"
#include "fixtures.h"
#include "zt_internal.h"

namespace {

class E2EBase : public LoopTestCase {
  protected:
    ziti_config client_config{};
    ziti_config server_config{};
    E2EBase() {
        REQUIRE_ZITI_OK(ziti_load_config(&client_config, test_client()));
        REQUIRE_ZITI_OK(ziti_load_config(&server_config, test_server()));
    }
    ~E2EBase() {
        free_ziti_config(&client_config);
        free_ziti_config(&server_config);
    }
    static const char *test_client() { return checkENV("test_client"); }
    static const char *test_server() { return checkENV("test_server"); }
    static const char *test_service() { return checkENV("test_service"); }
};

class E2ETest: public E2EBase {
  protected:
    ziti_options options{
        .config_types = (const char**)ALL_CONFIGS,
        .app_ctx = this,
        .events = ZitiContextEvent | ZitiAuthEvent | ZitiRouterEvent,
        .event_cb = event_cb,
    };

    static void event_cb(ziti_context ztx, const ziti_event_t *ev) {
        auto self = (E2ETest*)ziti_app_ctx(ztx);
        ZITI_LOG(INFO, "got event: %d", ev->type);
        switch (ev->type) {
        case ZitiContextEvent:
            ZITI_LOG(INFO, "got context event: ctrl_status=%d", ev->ctx.ctrl_status);
            if (ztx == self->server) {
                self->server_load_error = ev->ctx.ctrl_status;
                if (ev->ctx.ctrl_status == ZITI_OK) {
                    self->server_loaded = true;
                }
            } else {
                self->clt_load_error = ev->ctx.ctrl_status;
                if (ev->ctx.ctrl_status == ZITI_OK) {
                    self->clt_loaded = true;
                }
            }
            break;
        case ZitiAuthEvent:
            ZITI_LOG(INFO, "got auth event: %d => %s", ev->auth.action, ev->auth.detail);
            break;

        default:
            break;
        }
    }

public:
    E2ETest() {
        ziti_log_init(loop(), 5, nullptr);

        REQUIRE_ZITI_OK(ziti_context_init(&client, &client_config));
        REQUIRE_ZITI_OK(ziti_context_set_options(client, &options));

        REQUIRE_ZITI_OK(ziti_context_init(&server, &server_config));
        REQUIRE_ZITI_OK(ziti_context_set_options(server, &options));

        REQUIRE_ZITI_OK(ziti_context_run(client, loop()));
        REQUIRE_ZITI_OK(ziti_context_run(server, loop()));

        REQUIRE(run(UNTIL(server_loaded || server_load_error != ZITI_OK)));
        REQUIRE_ZITI_OK(server_load_error);

        REQUIRE(run(UNTIL(clt_loaded || clt_load_error != ZITI_OK)));
        REQUIRE_ZITI_OK(clt_load_error);
    }

    ~E2ETest() {
        ziti_shutdown(client);
        ziti_shutdown(server);
    }

    ziti_context client{};
    ziti_context server{};
    bool clt_loaded = false;
    int clt_load_error = 0;
    bool server_loaded = false;
    int server_load_error = 0;

    const ziti_service* ensureService(ziti_context ztx, const char* name = test_service()) {
        struct ctx_t {
            const ziti_service* srv{};
            int status{};
        } c;
        int rc = ziti_service_available(
            ztx, name,
            [](ziti_context ztx, const ziti_service *srv, int status, void *ctx) {
              auto c = (struct ctx_t*)ctx;
              c->srv = srv;
              c->status = status;
            },
            &c);
        REQUIRE_ZITI_OK(rc);
        REQUIRE(run(UNTIL(c.srv != nullptr || c.status != 0)));
        REQUIRE_ZITI_OK(c.status);
        REQUIRE(c.srv);
        return c.srv;
    }

};
}

TEST_CASE_METHOD(E2EBase, "e2ee test", "[e2ee]") {
    tls_context *srv_tls = nullptr;
    auto clt_tls = default_tls_context(client_config.id.ca, strlen(client_config.id.ca));
    // non-NULL creds is what makes load_tls() call init_tls_from_config() and set the
    // server's own cert on srv_tls; the struct itself is only held so it can be dropped
    zt_x509 creds{};
    DEFER {
        zt_x509_drop(&creds);
        if (srv_tls) srv_tls->free_ctx(srv_tls);
        if (clt_tls) clt_tls->free_ctx(clt_tls);
    };
    REQUIRE_ZITI_OK(load_tls(&server_config, &srv_tls, &creds));

    auto method = GENERATE(ziti_crypto_none, ziti_crypto_libsodium, ziti_crypto_tls);

    WHEN("method: " << e2ee_method_id(method)) {
        auto clt_e2ee = create_e2ee(method, false, clt_tls);
        auto srv_e2ee = create_e2ee(method, true, srv_tls);
        DEFER {
            clt_e2ee->free(clt_e2ee);
            srv_e2ee->free(srv_e2ee);
        };
        uint8_t ciphertext[16 * 1024];
        uint8_t plaintext[16 * 1024];
        ssize_t plaintext_len;

        {
            INFO("handshake");
            auto clt1 = clt_e2ee->pub(clt_e2ee);

            uint8_t clt_header[E2EE_MAX_HEADER_LEN], srv_header[E2EE_MAX_HEADER_LEN];
            ssize_t clt_header_len;
            REQUIRE_ZITI_OK(srv_e2ee->init(srv_e2ee, clt1.key, clt1.key_len, true));
            auto srv1 = srv_e2ee->pub(srv_e2ee);
            ssize_t srv_header_len = srv_e2ee->get_header(srv_e2ee, srv_header);
            REQUIRE(srv_header_len >= 0);

            REQUIRE_ZITI_OK(clt_e2ee->init(clt_e2ee, srv1.key, srv1.key_len, false));
            clt_header_len = clt_e2ee->get_header(clt_e2ee, clt_header);
            REQUIRE(clt_header_len >= 0);


            plaintext_len = clt_e2ee->decrypt(clt_e2ee, srv_header, srv_header_len, plaintext, sizeof(plaintext));
            REQUIRE(plaintext_len == 0);
            plaintext_len = srv_e2ee->decrypt(srv_e2ee, clt_header, clt_header_len, plaintext, sizeof(plaintext));
            REQUIRE(plaintext_len == 0);
        }

        uint8_t data[8 * 1024];
        ssize_t cipher_len;
        for (int i = 0; i < 32; i++) {
            {
                INFO("clt -> srv:" << i);
                randombytes_buf(data, sizeof(data));
                cipher_len = clt_e2ee->encrypt(clt_e2ee, data, sizeof(data), ciphertext, sizeof(ciphertext));
                REQUIRE(cipher_len >= 0);
                plaintext_len = srv_e2ee->decrypt(srv_e2ee, ciphertext, cipher_len, plaintext, sizeof(plaintext));
                REQUIRE(plaintext_len == sizeof(data));
                REQUIRE(memcmp(data, plaintext, sizeof(data)) == 0);
            }
            {
                INFO ("srv -> clt: " << i);
                randombytes_buf(data, sizeof(data));
                cipher_len = srv_e2ee->encrypt(srv_e2ee, data, sizeof(data), ciphertext, sizeof(ciphertext));
                REQUIRE(cipher_len >= 0);

                plaintext_len = clt_e2ee->decrypt(clt_e2ee, ciphertext, cipher_len, plaintext, sizeof(plaintext));
                REQUIRE(plaintext_len == sizeof(data));
                REQUIRE(memcmp(data, plaintext, sizeof(data)) == 0);
            }
        }
    }
}

TEST_CASE_METHOD(E2ETest, "e2ee connection test", "[e2ee]") {
    auto method = GENERATE(ziti_crypto_libsodium, ziti_crypto_tls);
    WHEN("crypto: " << e2ee_method_id(method)) {
        client->opts.e2ee_mode = method;
        server->opts.e2ee_mode = method;

        const char *ctrl_version = server->ctrl.version.version;
        INFO("controller version: " << (ctrl_version ? ctrl_version : "<null>"));
        REQUIRE(ctrl_version != nullptr);

        // reported as "v2.0.5"; tolerate a missing 'v'. an unparseable version must fail
        // the test rather than silently skip and hide a regression
        int major{}, minor{}, patch{};
        int parsed = sscanf(ctrl_version, "v%d.%d.%d", &major, &minor, &patch);
        if (parsed != 3) {
            parsed = sscanf(ctrl_version, "%d.%d.%d", &major, &minor, &patch);
        }
        REQUIRE(parsed == 3);

        if (method == ziti_crypto_tls &&
            (major < 2 || (major == 2 && minor == 0 && patch < 5))) {
            SKIP("TLS crypto exchange won't work before 2.0.5, controller is " << ctrl_version);
        }

        ensureService(server);
        struct srv_ctx_s {
            bool bound = false;
            int bound_res{0};
            ziti_connection srv_conn{};
            std::vector<uint8_t> received;
            int received_error{};
            bool srv_closed{false};
        } srv_ctx;
        ziti_connection srv{};
        ziti_conn_init(server, &srv, &srv_ctx);

        REQUIRE_ZITI_OK(ziti_listen(
            srv, test_service(),
            [](ziti_connection s, int status) {
                auto s_ctx = static_cast<struct srv_ctx_s*>(ziti_conn_data(s));
                if (status == ZITI_OK) {
                    s_ctx->bound = true;
                } else {
                    s_ctx->bound_res = status;
                }
            },
            [](ziti_connection s, ziti_connection c, int status, const ziti_client_ctx* clt_ctx) {
                auto s_ctx = static_cast<struct srv_ctx_s*>(ziti_conn_data(s));
                s_ctx->srv_conn = c;
                ziti_conn_set_data(c, s_ctx);
                ziti_accept(
                    c, [](ziti_connection c, int status){},
                    [](ziti_connection c, const uint8_t* data, ssize_t len) {
                        auto s_ctx = static_cast<struct srv_ctx_s*>(ziti_conn_data(c));
                        if (len < 0) {
                            s_ctx->received_error = (int)len;
                            ziti_close(c, nullptr);
                        } else {
                            s_ctx->received.insert(s_ctx->received.end(), data, data + len);
                            ziti_write(c, s_ctx->received.data(), s_ctx->received.size(), nullptr, nullptr);
                        }
                    return len;
                });
            }));

        bool bound_done = run(UNTIL(srv_ctx.bound || srv_ctx.bound_res != ZITI_OK));
        INFO("bound result: " << ziti_errorstr(srv_ctx.bound_res));
        REQUIRE(bound_done);
        REQUIRE(srv_ctx.bound);

        ziti_connection clt_conn{};
        struct clt_ctx_s {
            bool connected{false};
            int connect_res{0};

            size_t write_len{0};
            int write_res{0};

            int receive_error{0};
            std::vector<uint8_t> received;
            bool closed{false};
        } clt_ctx;
        REQUIRE_ZITI_OK(ziti_conn_init(client, &clt_conn, &clt_ctx));
        REQUIRE_ZITI_OK(ziti_dial(
            clt_conn, test_service(),
            [](ziti_connection c, int status) {
                auto c_ctx = static_cast<struct clt_ctx_s*>(ziti_conn_data(c));
                c_ctx->connect_res = status;
                if (status == ZITI_OK) {
                    c_ctx->connected = true;
                }
            },
            [](ziti_connection c, const uint8_t *data, ssize_t len) {
                auto c_ctx = static_cast<struct clt_ctx_s*>(ziti_conn_data(c));
                if (len < 0) {
                    c_ctx->receive_error = (int)len;
                    ziti_close(c, nullptr);
                    return (ssize_t)0;
                }
                c_ctx->received.insert(c_ctx->received.end(), data, data + len);
                return len;
            }));

        // race condition
        // bound returned success but terminator is established async
        uv_sleep(1000);

        bool connect_done = run(UNTIL(clt_ctx.connected || clt_ctx.connect_res != ZITI_OK ));
        INFO("connected result: " << ziti_errorstr(clt_ctx.connect_res));
        REQUIRE(connect_done);
        REQUIRE(clt_ctx.connect_res == ZITI_OK);

        for (int i = 0; i < 100; i++) {
            clt_ctx.write_len = 0;
            clt_ctx.write_res = 0;
            clt_ctx.received.clear();
            srv_ctx.received_error = 0;
            srv_ctx.received.clear();

            INFO("iteration " << i);
            uint8_t data[1024];
            randombytes_buf(data, sizeof(data));
            ziti_write(clt_conn, data, sizeof(data), [](ziti_connection c, ssize_t res, void* wr_ctx) {
                auto c_ctx = static_cast<struct clt_ctx_s*>(ziti_conn_data(c));
                if (res < 0) c_ctx->write_res = res;
                else c_ctx->write_len += res;
            }, &clt_ctx);

            bool write_done = run(UNTIL(clt_ctx.write_len > 0 || clt_ctx.write_res != ZITI_OK ));
            INFO("write_result: " << ziti_errorstr(clt_ctx.write_res));
            REQUIRE(write_done);
            REQUIRE(clt_ctx.write_res == ZITI_OK);

            bool srv_recv_done = run(UNTIL(!srv_ctx.received.empty() || srv_ctx.received_error != ZITI_OK ));
            INFO("srv received result: " << ziti_errorstr(srv_ctx.received_error));
            REQUIRE(srv_recv_done);
            REQUIRE(srv_ctx.received_error == ZITI_OK);

            bool clt_recv_done = run(UNTIL(!clt_ctx.received.empty() || clt_ctx.receive_error != ZITI_OK ));
            INFO("clt received result: " << ziti_errorstr(clt_ctx.receive_error));
            REQUIRE(clt_recv_done);
            REQUIRE(clt_ctx.receive_error == ZITI_OK);

            REQUIRE(clt_ctx.received.size() == sizeof(data));
            REQUIRE(srv_ctx.received.size() == sizeof(data));
            REQUIRE(memcmp(clt_ctx.received.data(), data, clt_ctx.received.size()) == 0);
            REQUIRE(memcmp(srv_ctx.received.data(), data, srv_ctx.received.size()) == 0);
        }
        ziti_close(clt_conn, [](ziti_connection c) {
            auto c_ctx = static_cast<struct clt_ctx_s*>(ziti_conn_data(c));
            c_ctx->closed = true;
        });

        ziti_close(srv_ctx.srv_conn, [](ziti_connection c) {
            auto s_ctx = static_cast<struct srv_ctx_s*>(ziti_conn_data(c));
            s_ctx->srv_closed = true;
        });

        ziti_close(srv, [](ziti_connection c) {
            auto s_ctx = static_cast<struct srv_ctx_s*>(ziti_conn_data(c));
            s_ctx->bound = false;
        });

        // nothing is asserted after this, so an unchecked timeout here would pass silently
        INFO("srv_closed: " << srv_ctx.srv_closed << " clt_closed: " << clt_ctx.closed
             << " still bound: " << srv_ctx.bound);
        REQUIRE(run(UNTIL(srv_ctx.srv_closed && clt_ctx.closed && !srv_ctx.bound)));
        ZITI_LOG(INFO, "test is done");
    }
}
