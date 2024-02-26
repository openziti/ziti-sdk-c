// Copyright (c) 2019-2024. NetFoundry Inc.
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

#include "../catch2_includes.hpp"

#include <iostream>
#include <zt_internal.h>
#include <ziti_ctrl.h>
#include <utils.h>

#include "test-data.h"

static const char *const SERVICE_NAME = TEST_SERVICE;

using namespace std;
using namespace Catch::Matchers;

template <class T>
class resp_capture {
public:
    T *resp;
    ziti_error error;
    resp_capture() { resp = nullptr;
        memset(&error, 0, sizeof(error));}

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
T *do_get(ziti_controller &ctrl,
          void (*method)(ziti_controller *, void (*cb)(T *, const ziti_error *err, void *), void *)) {
    resp_capture<T> resp;
    method(&ctrl, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    REQUIRE(resp.error.err == 0);
    return resp.resp;
}


template<class T, class A>
T *do_get1(
        ziti_controller &ctrl,
        void (*method)(ziti_controller *, A, void (*cb)(T *, const ziti_error *err, void *), void *), A arg) {
    resp_capture<T> resp;
    method(&ctrl, arg, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    if (resp.error.err != 0) { throw resp.error; }
    return resp.resp;
}

template<class T, class A1, class A2>
T *do_get2(
        ziti_controller &ctrl,
        void (*method)(ziti_controller *, A1, A2, void (*cb)(T *, const ziti_error *err, void *), void *), A1 arg1,
        A2 arg2) {
    resp_capture<T> resp;
    method(&ctrl, arg1, arg2, resp_cb, &resp);
    uv_run(ctrl.loop, UV_RUN_DEFAULT);
    if (resp.error.err != 0) { throw resp.error; }
    return resp.resp;
}


auto logout_cb = [](void *, const ziti_error *err, void *ctx) {
    auto logout = static_cast<resp_capture<const char> *>(ctx);
    logout->set_error(err);
    logout->resp = "logout called";
};

static ziti_api_session *do_login(ziti_controller &ctrl) {
    resp_capture<ziti_api_session> session;
    model_list l = {nullptr};
    auto s = do_get1(ctrl, ziti_ctrl_login, &l);
    return s;
}

TEST_CASE("invalid_controller", "[controller][GH-44]") {
    ziti_controller ctrl;
    uv_loop_t *loop = uv_default_loop();
    resp_capture<ziti_version> version;

    PREP(ziti);
    TRY(ziti, ziti_ctrl_init(loop, &ctrl, "https://not.a.ziti.controll.er", nullptr));
    WHEN("get version") {
        ziti_ctrl_get_version(&ctrl, resp_cb, &version);
        uv_run(loop, UV_RUN_DEFAULT);

        THEN("callback with proper error") {
            REQUIRE(version.error.err != 0);
            REQUIRE_THAT(version.error.code, Equals("CONTROLLER_UNAVAILABLE"));
        }
    }


    CATCH(ziti) {
        FAIL("unexpected error");
    }

    ziti_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
}

TEST_CASE("controller_test","[integ]") {
    const char *conf = TEST_CLIENT;

    ziti_config config;
    tls_context *tls;
    ziti_controller ctrl;
    uv_loop_t *loop = uv_default_loop();

    resp_capture<ziti_version> version;
    resp_capture<ziti_api_session> session;
    resp_capture<ziti_service> service;


    PREP(ziti);
    TRY(ziti, ziti_load_config(&config, conf));
    TRY(ziti, load_tls(&config, &tls));
    TRY(ziti, ziti_ctrl_init(loop, &ctrl, config.controller_url, tls));

    WHEN("get version and login") {
        ziti_version *v = do_get(ctrl, ziti_ctrl_get_version);
        REQUIRE(v != nullptr);
        free_ziti_version(v);

        auto s = do_login(ctrl);
        free_ziti_api_session_ptr(s);
    }

    WHEN("try to get services before login") {
        REQUIRE_THROWS(do_get1(ctrl, ziti_ctrl_get_service, SERVICE_NAME));
    }

    WHEN("try to login and get non-existing service") {
        auto api_sesh = do_login(ctrl);

        auto s = do_get1(ctrl, ziti_ctrl_get_service, "this-service-should-not-exist");
        THEN("should NOT get non-existent service") {
            REQUIRE(s == nullptr);
        }
        free_ziti_api_session_ptr(api_sesh);
    }

    WHEN("try to login, get service, and session") {
        auto api_session = do_login(ctrl);

        auto services = do_get(ctrl, ziti_ctrl_get_services);
        ziti_service *s = services[0];

        THEN("should get service") {
            REQUIRE(s != nullptr);
        }AND_THEN("should get api_session") {
            auto ns = do_get2(ctrl, ziti_ctrl_create_session, (const char *) s->id, *s->permissions[0]);
            REQUIRE(ns != nullptr);
            REQUIRE(ns->token != nullptr);
            free_ziti_session_ptr(ns);
            free_ziti_service_array(&services);
        }
        AND_THEN("logout should succeed") {
            do_get(ctrl, ziti_ctrl_logout);
        }

        free_ziti_api_session_ptr(api_session);
    }

    CATCH(ziti) {
        FAIL(ziti_errorstr(ERR(ziti)));
    }


    free_ziti_version(version.resp);
    free_ziti_api_session(session.resp);

    ziti_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
    tls->free_ctx(tls);
    free_ziti_config(&config);
}

TEST_CASE("ztx-legacy-auth", "[integ]") {
    const char *zid = TEST_CLIENT;

    ziti_config cfg;
    REQUIRE(ziti_load_config(&cfg, zid) == ZITI_OK);

    ziti_context ztx;
    REQUIRE(ziti_context_init(&ztx, &cfg) == ZITI_OK);

    struct test_context_s {
        int event;
        std::string data;
    } test_context = {
        .event = 0,
    };


    ziti_options opts = {
        .app_ctx = &test_context,
        .events = ZitiContextEvent,
        .event_cb = [](ziti_context ztx, const ziti_event_t *event){
            printf("got event: %d => %s \n", event->type, event->event.ctx.err);
            auto test_ctx = (test_context_s*)ziti_app_ctx(ztx);
            test_ctx->event = event->type;
        },
    };

    ziti_context_set_options(ztx, &opts);

    auto l = uv_loop_new();
    ziti_context_run(ztx, l);

    while (test_context.event == 0) {
        uv_run(l, UV_RUN_ONCE);
    }

    ziti_shutdown(ztx);
    uv_run(l, UV_RUN_DEFAULT);

    free_ziti_config(&cfg);
}