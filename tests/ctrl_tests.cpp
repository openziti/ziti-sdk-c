/*
Copyright (c) 2019 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "catch2/catch.hpp"
#include <iostream>
#include <zt_internal.h>
#include <ziti_ctrl.h>
#include <utils.h>

using namespace std;
using namespace Catch::Matchers;

template <class T>
class resp_capture {
public:
    T *resp;
    ziti_error *error;
    resp_capture() { resp = nullptr; error = nullptr;}

    ~resp_capture() {
        if (error != nullptr) {
            free_ziti_error(error);
            error = nullptr;
        }
    }
};

template <class T> void resp_cb(T* r, ziti_error *err, void* ctx) {
    auto *rc = static_cast<resp_capture<T> *>(ctx);
    rc->error = err;
    rc->resp = r;
}

auto logout_cb = [](void*, ziti_error* err, void* ctx) {
    auto logout = static_cast<resp_capture<const char> *>(ctx);
    logout->error = err;
    logout->resp = "logout called";
};

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
            REQUIRE(version.error != nullptr);
            REQUIRE_THAT(version.error->code, Equals("CONTROLLER_UNAVAILABLE"));
        }
    }


    CATCH(ziti) {
        FAIL("unexpected error");
    }

    ziti_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
}

TEST_CASE("controller_test","[integ]") {
    char *conf = getenv("ZITI_SDK_CONFIG");
    if (conf == nullptr) {
        FAIL("ZITI_SDK_CONFIG environment variable is not set");
        return;
    }

    ziti_config *config;
    tls_context *tls;
    ziti_controller ctrl;
    uv_loop_t *loop = uv_default_loop();

    resp_capture<ziti_version> version;
    resp_capture<ziti_session> session;
    resp_capture<ziti_service> service;


    PREP(ziti);
    TRY(ziti,load_config(conf, &config));
    TRY(ziti, load_tls(config, &tls));
    TRY(ziti, ziti_ctrl_init(loop, &ctrl, config->controller_url, tls));

    WHEN("get version and login") {

        ziti_ctrl_get_version(&ctrl, resp_cb, &version);
        ziti_ctrl_login(&ctrl, nullptr, resp_cb, &session);

        uv_run(loop, UV_RUN_DEFAULT);

        THEN("should get version") {
            REQUIRE(version.error == nullptr);
            REQUIRE(version.resp != nullptr);
        }
        AND_THEN("login should get session") {
            REQUIRE(session.error == nullptr);
            REQUIRE(session.resp != nullptr);
            REQUIRE(ctrl.session != nullptr);
        }
    }

    WHEN("try to get services before login") {

        ziti_ctrl_get_service(&ctrl, "wttr.in", resp_cb, &service);

        uv_run(loop, UV_RUN_DEFAULT);
        THEN("should get error") {
            REQUIRE(service.resp == nullptr);
            REQUIRE(service.error != nullptr);
            REQUIRE_THAT(service.error->code, Equals("UNAUTHORIZED"));
        }
    }

    WHEN("try to login and get non-existing service") {
        resp_capture<ziti_service> service2;

        ziti_ctrl_login(&ctrl, nullptr, resp_cb, &session);
        ziti_ctrl_get_service(&ctrl, "this-service-should-not-exist", resp_cb, &service2);

        int rc = uv_run(loop, UV_RUN_DEFAULT);
        THEN("should NOT get non-existent service") {
            REQUIRE(service2.error == nullptr);
            REQUIRE(service2.resp == nullptr);
        }
    }

    WHEN("try to login, get service, and network session") {
        struct uber_resp_s {
            resp_capture<ziti_session> session;
            resp_capture<ziti_service> service;
            resp_capture<ziti_net_session> ns;

            resp_capture<const char> logout;

            ziti_controller *c;
        } r;
        r.c = &ctrl;

        auto serv_cb = [](ziti_service *s, ziti_error* e, void* ctx) {
            auto *re = static_cast<struct uber_resp_s *>(ctx);
            resp_cb(s, e, &re->service);
            if (e == nullptr) {
                ziti_ctrl_get_net_session(re->c, s->id, "Dial", resp_cb, &re->ns);
            }
            ziti_ctrl_logout(re->c, logout_cb, &re->logout);

        };
        ziti_ctrl_login(&ctrl, nullptr, resp_cb, &r.session);
        ziti_ctrl_get_service(&ctrl, "wttr.in", serv_cb, &r);

        int rc = uv_run(loop, UV_RUN_DEFAULT);
        THEN("should get service") {
            REQUIRE(r.service.error == nullptr);
            REQUIRE(r.service.resp != nullptr);
            REQUIRE_THAT(r.service.resp->name, Equals("wttr.in"));
        }
        AND_THEN("should get network session") {
            REQUIRE(r.ns.error == nullptr);
            REQUIRE(r.ns.resp != nullptr);
            REQUIRE(r.ns.resp->token != nullptr);
        }
        AND_THEN("logout should succeed") {
            REQUIRE(r.logout.error == nullptr);
            REQUIRE_THAT(r.logout.resp, Equals("logout called"));
        }

        free_ziti_session(r.session.resp);
        free_ziti_service(r.service.resp);
        free_ziti_net_session(r.ns.resp);
    }

    CATCH(ziti) {
        FAIL(ziti_errorstr(ERR(ziti)));
    }


    free_ziti_version(version.resp);
    free_ziti_session(session.resp);

    ziti_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
    tls->api->free_ctx(tls);
    free_ziti_config(config);
}
