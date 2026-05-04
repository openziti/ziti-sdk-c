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
#include <format>

#include "fixtures.h"
#include <ziti/zitilib.h>

class ZitilibTestCase {
  protected:
    ZitilibTestCase() {
        Ziti_lib_init();
    }
    ~ZitilibTestCase() {
        Ziti_lib_shutdown();
    }
};

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: init", "[zitilib]") {
    auto error = Ziti_last_error();
    INFO("error: " << error << ": " << ziti_errorstr(error));
    REQUIRE(error == ZITI_OK);
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load context", "[zitilib]") {
    auto params = GENERATE(
        std::pair((const char*)nullptr, ZITI_INVALID_CONFIG),
        std::pair("invalid", ZITI_CONFIG_NOT_FOUND),
        std::pair(getenv("test_client"), ZITI_OK)
        );

    WHEN(std::format("context[{}]", params.first ? params.first : "(null)")) {
        ziti_handle_t ztx{};
        auto error = Ziti_load_context(&ztx, params.first);
        INFO(std::format("error[{}]: {}/{}", params.first ? params.first : "(null)", error, ziti_errorstr(error)));
        CHECK(error == params.second);
        CHECK(Ziti_last_error() == params.second);
        if (params.second == ZITI_OK) {
            CHECK(ztx != ZITI_INVALID_HANDLE);
        } else {
            CHECK(ztx == ZITI_INVALID_HANDLE);
        }
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load after shutdown", "[zitilib]") {
    Ziti_lib_shutdown();
    ziti_handle_t ztx{};
    auto cfg = getenv("test_client");
    WHEN("with timeout") {
        auto error = Ziti_load_context_with_timeout(&ztx, cfg, 1000);
        INFO(std::format("error: {}/{}", error, ziti_errorstr(error)));
        CHECK(error == ZITI_INVALID_STATE);
        CHECK(Ziti_last_error() == ZITI_INVALID_STATE);
    }
    WHEN("without timeout") {
        auto error = Ziti_load_context(&ztx, cfg);
        INFO(std::format("error: {}/{}", error, ziti_errorstr(error)));
        CHECK(error == ZITI_INVALID_STATE);
        CHECK(Ziti_last_error() == ZITI_INVALID_STATE);
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: load context with timeout", "[zitilib]") {
    auto params = GENERATE(
        std::tuple((const char*)nullptr, -1, ZITI_INVALID_CONFIG),
        std::tuple("invalid", -1, ZITI_CONFIG_NOT_FOUND),
        std::tuple(getenv("test_client"), 2000, ZITI_OK),
        std::tuple(getenv("test_client"), 1, ZITI_TIMEOUT)
        );

    WHEN(std::format("context[{}] with timeout[{}]", std::get<0>(params) ? std::get<0>(params) : "(null)", std::get<1>(params))) {
        ziti_handle_t ztx{};
        auto error = Ziti_load_context_with_timeout(&ztx, std::get<0>(params), std::get<1>(params));
        INFO(std::format("error[{}]: {}/{}", std::get<0>(params) ? std::get<0>(params) : "(null)", error, ziti_errorstr(error)));
        CHECK(error == std::get<2>(params));
        CHECK(Ziti_last_error() == std::get<2>(params));
        if (std::get<2>(params) == ZITI_OK) {
            CHECK(ztx != ZITI_INVALID_HANDLE);
        } else {
            CHECK(ztx == ZITI_INVALID_HANDLE);
        }
    }
}

TEST_CASE_METHOD(ZitilibTestCase, "zitilib: connect", "[zitilib]") {
    ziti_handle_t ztx{};
    auto error = Ziti_load_context(&ztx, getenv("test_client"));
    REQUIRE(error == ZITI_OK);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);
    REQUIRE(Ziti_last_error() == ZITI_OK);

    
}
