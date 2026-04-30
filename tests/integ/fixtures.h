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

#define UNTIL(c) [&](){ return !(c); }
#define WHILE(c) [&](){ return (c); }

class LoopTestCase {
    uv_loop_t *m_loop;
    uv_idle_t m_check;

protected:
    LoopTestCase():
        m_loop(uv_loop_new()), m_check() {
        uv_idle_init(m_loop, &m_check);
        uv_unref((uv_handle_t*)&m_check);
    }

    ~LoopTestCase() {
        uv_close((uv_handle_t*)&m_check, nullptr);
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
        auto timer = new uv_timer_t;
        uv_timer_init(loop(), timer);

        struct checker_s {
            bool timeout{false};
            std::function<bool()>& condition;
        } checker { .condition = cond };

        timer->data = &checker;
        if (timeout_ms > 0) {
            uv_timer_start(timer, [](uv_timer_t *t){
                auto c = (checker_s*)(t->data);
                c->timeout = true;
            }, timeout_ms, 0);
        }
        m_check.data = &checker;
        uv_ref((uv_handle_t*)&m_check);
        uv_idle_start(&m_check, [](uv_idle_t *ch){
            auto c = (checker_s*)(ch->data);
            bool b = c->condition();
            if (!b) {
                ch->data = nullptr;
                uv_stop(ch->loop);
            }
        });

        uv_run(loop(), UV_RUN_DEFAULT);
        uv_idle_stop(&m_check);
        uv_unref((uv_handle_t*)&m_check);
        uv_close((uv_handle_t*)timer, [](uv_handle_t *t){
            delete (uv_timer_t*)t;
        });
        ZITI_LOG(INFO, "loop paused");
        return !checker.timeout;
    }
};

class ZitiTestCase : public LoopTestCase {
  protected:
    ziti_intercept_cfg_v1 intercept_cfg{};
    ZitiTestCase() {
        auto cfg = getenv("test_service_intercept");
        if (cfg) {
            parse_ziti_intercept_cfg_v1(&intercept_cfg, cfg, strlen(cfg));
        }
        ziti_log_init(loop(), 5, nullptr);
    }

    ~ZitiTestCase() {
        free_ziti_intercept_cfg_v1(&intercept_cfg);
    }
    
    static const char* test_client() {
        return getenv("test_client");
    }

    static const char* test_service() {
        return getenv("test_service");
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
    std::function<void()> cb{};
    ~deferer() { cb(); }
};

#define DEFER deferer line_var(deferer); line_var(deferer).cb = [&]()

#endif // ZITI_SDK_FIXTURES_H
