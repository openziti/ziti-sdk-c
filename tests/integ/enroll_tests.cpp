/*
 Copyright 2025 NetFoundry Inc.

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

#include "../catch2_includes.hpp"
#include "fixtures.h"

#include <ziti/ziti.h>

TEST_CASE_METHOD(LoopTestCase, "enroll-invalid-url", "[enroll][integration]") {
    ziti_enroll_opts opts {
        .url = "not a valid url",
    };

    struct test_ctx_t {
        bool called{false};
        int status{INT32_MAX};
        std::string error;

    } test_ctx;
    auto rc = ziti_enroll(&opts, loop(), [](const ziti_config *cfg, int status, const char *err_message, void *enroll_ctx){
        auto tctx = (test_ctx_t*)enroll_ctx;
        tctx->called = true;
        tctx->status = status;
        tctx->error = err_message ? err_message : "OK";
    }, &test_ctx);

    uv_run(loop(), UV_RUN_DEFAULT);

    CHECK(rc == ZITI_INVALID_CONFIG);
    CHECK(!test_ctx.called);
}

TEST_CASE_METHOD(LoopTestCase, "enroll-unknown-url", "[enroll][integration]") {
    ziti_enroll_opts opts {
            .url = "https://this.is.not.a.valid.address:18443",
    };

    struct test_ctx_t {
        bool called{false};
        int status{INT32_MAX};
        std::string error;

    } test_ctx;
    auto rc = ziti_enroll(&opts, loop(), [](const ziti_config *cfg, int status, const char *err_message, void *enroll_ctx){
        auto tctx = (test_ctx_t*)enroll_ctx;
        tctx->called = true;
        tctx->status = status;
        tctx->error = err_message ? err_message : "OK";
    }, &test_ctx);

    uv_run(loop(), UV_RUN_DEFAULT);

    CHECK(rc == ZITI_OK);
    CHECK(test_ctx.called);
    CHECK(test_ctx.status == ZITI_CONTROLLER_UNAVAILABLE);
    CHECK(test_ctx.error == uv_strerror(UV_EAI_NONAME));
}

TEST_CASE_METHOD(LoopTestCase, "enroll-nonziti-url", "[enroll][integration]") {
    ziti_enroll_opts opts {
            .url = "https://google.com",
    };

    struct test_ctx_t {
        bool called{false};
        int status{INT32_MAX};
        std::string error;

    } test_ctx;
    auto rc = ziti_enroll(&opts, loop(), [](const ziti_config *cfg, int status, const char *err_message, void *enroll_ctx){
        auto tctx = (test_ctx_t*)enroll_ctx;
        tctx->called = true;
        tctx->status = status;
        tctx->error = err_message ? err_message : "OK";
    }, &test_ctx);

    uv_run(loop(), UV_RUN_DEFAULT);

    CHECK(rc == ZITI_OK);
    CHECK(test_ctx.called);
    CHECK(test_ctx.status == ZITI_INVALID_STATE);
    INFO(test_ctx.error);
    CHECK(test_ctx.error != "OK");
}