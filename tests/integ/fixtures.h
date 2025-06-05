// Copyright (c) 2023. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
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

class LoopTestCase {
    uv_loop_t *m_loop;

protected:
    LoopTestCase():
                     m_loop(uv_loop_new())
    {}

    ~LoopTestCase() {
        int rc = uv_loop_close(loop());
        INFO("uv_loop_close() => " << uv_strerror(rc));
        CHECK(rc == 0);
        free(m_loop);
    }

    uv_loop_t *loop() { return m_loop; }
};

template <class T>
class resp_capture {
public:
    T *resp;
    ziti_error error;
    resp_capture(): error{} {
        resp = nullptr;
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
void resp_cb(T *r, const ziti_error *err, void *ctx) {
    auto *rc = static_cast<resp_capture<T> *>(ctx);
    if (err) { rc->set_error(err); }
    rc->resp = r;
}

template<class T>
T *ctrl_get(ziti_controller &ctrl,
            void (*method)(ziti_controller *, void (*cb)(T *, const ziti_error *err, void *), void *)) {
    resp_capture<T> resp;
    method(&ctrl, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    CHECK(resp.error.err == 0);
    return resp.resp;
}


template<class T, class A>
T *ctrl_get1(
        ziti_controller &ctrl,
        void (*method)(ziti_controller *, A, void (*cb)(T *, const ziti_error *err, void *), void *), A arg) {
    resp_capture<T> resp;
    method(&ctrl, arg, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    if (resp.error.err != 0) { throw resp.error; }
    return resp.resp;
}

template<class T, class A1, class A2>
T *ctrl_get2(
        ziti_controller &ctrl,
        void (*method)(ziti_controller *, A1, A2, void (*cb)(T *, const ziti_error *err, void *), void *), A1 arg1,
        A2 arg2) {
    resp_capture<T> resp;
    method(&ctrl, arg1, arg2, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    if (resp.error.err != 0) { throw resp.error; }
    return resp.resp;
}

static inline ziti_api_session *ctrl_login(ziti_controller &ctrl) {
    resp_capture<ziti_api_session> session;
    model_list l = {nullptr};
    auto s = ctrl_get1(ctrl, ziti_ctrl_login, &l);
    return s;
}


#endif // ZITI_SDK_FIXTURES_H
