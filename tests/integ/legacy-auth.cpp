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
#include "fixtures.h"

static const char *const SERVICE_NAME = TEST_SERVICE;

using namespace std;
using namespace Catch::Matchers;


TEST_CASE("invalid_controller", "[controller][GH-44]") {
    ziti_controller ctrl;
    uv_loop_t *loop = uv_default_loop();
    resp_capture<ziti_version> version;

    PREP(ziti);
    model_list endpoints = {nullptr};
    model_list_append(&endpoints, (void*)"https://not.a.ziti.controll.er");
    TRY(ziti, ziti_ctrl_init(loop, &ctrl, &endpoints, nullptr));
    model_list_clear(&endpoints, nullptr);

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

    ziti_config config{};
    tls_credentials creds{};
    tls_context *tls = nullptr;
    ziti_controller ctrl{};
    uv_loop_t *loop = uv_default_loop();

    REQUIRE(ziti_load_config(&config, conf) == ZITI_OK);
    REQUIRE(load_tls(&config, &tls, &creds) == ZITI_OK);
    REQUIRE(ziti_ctrl_init(loop, &ctrl, &config.controllers, tls) == ZITI_OK);

    resp_capture<ziti_version> version;
    resp_capture<ziti_api_session> session;
    resp_capture<ziti_service> service;

    WHEN("get version and login") {
        auto v = ctrl_get(ctrl, ziti_ctrl_get_version);
        REQUIRE(v != nullptr);

        auto v1 = (const char*)model_map_get(&v->api_versions->edge, "v1");
        CHECK(v1 != nullptr);

        auto s = ctrl_login(ctrl);
        free_ziti_api_session_ptr(s);
    }

    WHEN("try to get services before login") {
        REQUIRE_THROWS(ctrl_get1(ctrl, ziti_ctrl_get_service, SERVICE_NAME));
    }

    WHEN("try to login and get non-existing service") {
        auto api_sesh = ctrl_login(ctrl);

        auto s = ctrl_get1(ctrl, ziti_ctrl_get_service, "this-service-should-not-exist");
        THEN("should NOT get non-existent service") {
            REQUIRE(s == nullptr);
        }
        free_ziti_api_session_ptr(api_sesh);
    }

    WHEN("try to login, get service, and session") {
        auto api_session = ctrl_login(ctrl);

        auto services = ctrl_get(ctrl, ziti_ctrl_get_services);
        ziti_service *s = services[0];

        THEN("should get service") {
            REQUIRE(s != nullptr);
        }AND_THEN("should get api_session") {
            auto ns = ctrl_get2(ctrl, ziti_ctrl_create_session, (const char *) s->id, *s->permissions[0]);
            REQUIRE(ns != nullptr);
            REQUIRE(ns->token != nullptr);
            free_ziti_session_ptr(ns);
            free_ziti_service_array(&services);
        }
        AND_THEN("logout should succeed") {
            ctrl_get(ctrl, ziti_ctrl_logout);
        }

        free_ziti_api_session_ptr(api_session);
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


    ziti_options opts = {};
    opts.app_ctx = &test_context;
    opts.events = ZitiContextEvent;
    opts.event_cb = [](ziti_context ztx, const ziti_event_t *event){
            printf("got event: %d => %s \n", event->type, event->ctx.err);
            auto test_ctx = (test_context_s*)ziti_app_ctx(ztx);
            test_ctx->event = event->type;
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