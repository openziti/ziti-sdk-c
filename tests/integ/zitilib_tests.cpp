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
