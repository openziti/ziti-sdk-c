// Copyright (c) 2023-2026.  NetFoundry Inc
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

#ifndef ZITI_SDK_FIXTURES_H
#define ZITI_SDK_FIXTURES_H

#include <uv.h>
#include <cstdlib>
#include "ziti_ctrl.h"
#include "auth_method.h"
#include <ziti/ziti_log.h>
#include <ziti/ziti.h>
#include <ziti/zitilib.h>

#ifndef line_var
#define concat_1(a, b) a ## b
#define concat_2(a, b) concat_1(a, b)
#define line_var(name) concat_2(name, __LINE__)
#endif

#define UNTIL(c) [&](){ return !(c); }
#define WHILE(c) [&](){ return (c); }

#define t_ZITI_OK(op, expr) do { \
    int line_var(rc) = (expr);             \
    INFO("result[" << #expr << "]: " << ziti_errorstr(line_var(rc))); \
    op(line_var(rc) == ZITI_OK); \
} while(0)

#define CHECK_ZITI_OK(expr) t_ZITI_OK(CHECK, expr)
#define REQUIRE_ZITI_OK(expr) t_ZITI_OK(REQUIRE, expr)

class LoopTestCase {
    uv_loop_t *m_loop;

protected:
    LoopTestCase():
        m_loop(uv_loop_new()) {
    }

    ~LoopTestCase() {
        for (int i = 0; i < 10; i++) {
            ZITI_LOG(INFO, "loop close pass %d", i);
            if (uv_run(loop(), UV_RUN_ONCE) == 0) break;
        }
        int rc = uv_loop_close(loop());
        INFO("uv_loop_close() => " << (rc == 0 ? "success" : uv_strerror(rc)));
        CHECK(rc == 0);
        free(m_loop);
    }

    uv_loop_t *loop() { return m_loop; }

    bool run(std::function<bool()> cond, int timeout_ms = 10000) {
        auto deadline = uv_now(loop()) + timeout_ms;

        while(uv_now(loop()) < deadline) {
            if (!cond()) {
                return true;
            }
            uv_run(loop(), UV_RUN_NOWAIT);
        }
        ZITI_LOG(INFO, "loop paused");
        return false;
    }
};

inline constexpr const char* ALL_CONFIGS[] = {
    "all", nullptr,
};

class ZitiTestCase : public LoopTestCase {
  protected:
    ziti_config config{};
    ziti_context ztx{};
    bool loaded{};
    int load_error{};

    ZitiTestCase() {
        ziti_log_init(loop(), 5, nullptr);
        auto test_client = ZitiTestCase::test_client();
        if (!test_client) {
            FAIL("test_client environment variable must be set to run this test");
        }
        REQUIRE_ZITI_OK(ziti_load_config(&config, test_client));
        REQUIRE_ZITI_OK(ziti_context_init(&ztx, &config));

        const ziti_options opts {
            .config_types = (const char**)ALL_CONFIGS,
            .app_ctx = this,
            .events = ZitiContextEvent,
            .event_cb = [](ziti_context ztx, const ziti_event_t *ev) {
                auto self = (ZitiTestCase*)ziti_app_ctx(ztx);
                if (ev->type == ZitiContextEvent) {
                    if (ev->ctx.ctrl_status == ZITI_OK) {
                        self->loaded = true;
                    } else {
                        self->load_error = ev->ctx.ctrl_status;
                    }
                }
            },
        };
        REQUIRE_ZITI_OK(ziti_context_set_options(ztx, &opts));
        REQUIRE_ZITI_OK(ziti_context_run(ztx, loop()));
        REQUIRE(run(UNTIL(loaded || load_error != 0)));
        REQUIRE_ZITI_OK(load_error);
        REQUIRE(loaded);
    }

    ~ZitiTestCase() {
        ziti_shutdown(ztx);
        free_ziti_config(&config);
    }

    static const char* test_client() {
        return getenv("test_client");
    }

    static const char* test_service() {
        return getenv("test_service");
    }

    const ziti_service* ensureService(const char* name = test_service()) {
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

template <class T>
class resp_capture {
public:
    T resp{};
    ziti_error error;
    resp_capture(): error{}, resp{} {
    }

    void set_error(const ziti_error * e) {
        error.message = strdup(e->message);
        error.code = strdup(e->code);
        error.err = e->err;
        error.http_code = e->http_code;
    }

    ~resp_capture() {
        free_ziti_error(&error);
    }
};

template<class T>
void resp_cb(T r, const ziti_error *err, void *ctx) {
    auto *rc = static_cast<resp_capture<T> *>(ctx);
    if (err) { rc->set_error(err); }
    rc->resp = r;
}

template<class T>
T ctrl_get(ziti_controller &ctrl,
            void (*method)(ziti_controller *, void (*cb)(T, const ziti_error *err, void *), void *)) {
    resp_capture<T> resp;
    method(&ctrl, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    CHECK(resp.error.err == 0);
    return resp.resp;
}


template<class T, class A>
T ctrl_get1(
        ziti_controller &ctrl,
        void (*method)(ziti_controller *, A, void (*cb)(T, const ziti_error *err, void *), void *), A arg) {
    resp_capture<T> resp;
    method(&ctrl, arg, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    if (resp.error.err != 0) { throw resp.error; }
    return resp.resp;
}

template<class T, class A1, class A2>
T ctrl_get2(
        ziti_controller &ctrl,
        void (*method)(ziti_controller *, A1, A2, void (*cb)(T, const ziti_error *err, void *), void *), A1 arg1,
        A2 arg2) {
    resp_capture<T> resp;
    method(&ctrl, arg1, arg2, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    if (resp.error.err != 0) { throw resp.error; }
    return resp.resp;
}

static inline std::string auth_login(ziti_auth_method_t *m, uv_loop_t *loop) {
    resp_capture<std::string> session;
    m->start(m, [](void *ctx, ziti_auth_state state, const void* data){
        auto rc = static_cast<resp_capture<std::string> *>(ctx);
        if (state == ZitiAuthStateFullyAuthenticated) {
            rc->resp = (const char*)data;
        } else if (state == ZitiAuthStateUnauthenticated) {
            rc->set_error((const ziti_error*)data);
        }
    }, &session);
    while(session.resp.empty() && session.error.err == 0) {
        uv_run(loop, UV_RUN_ONCE);
    }
    if (session.error.err != 0) { throw session.error; }

    return session.resp;
}

struct deferer {
    deferer() = default;
    std::function<void()> cb{[](){}};
    ~deferer() { cb(); }
};

#define DEFER deferer line_var(deferer); line_var(deferer).cb = [&]()

class ZitilibTestCase {
protected:
    ZitilibTestCase() {
#if _WIN32
        WSADATA wsaData;
        int wsaErr = WSAStartup(MAKEWORD(2, 2), &wsaData);
        REQUIRE(wsaErr == 0);
#endif
        ZITI_LOG(INFO, "starting test case: %s", Catch::getResultCapture().getCurrentTestName().c_str());
        Ziti_lib_init();
    }
    ~ZitilibTestCase() {
        Ziti_lib_shutdown();
        ZITI_LOG(INFO, "finished test case: %s", Catch::getResultCapture().getCurrentTestName().c_str());
    }
};


#endif // ZITI_SDK_FIXTURES_H
