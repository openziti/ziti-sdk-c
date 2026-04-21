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

#include <catch2/catch_all.hpp>
#include <ziti/zitilib.h>
#include <ziti/ziti.h>

class ZitilibManager: public Catch::EventListenerBase{

public:
    using Catch::EventListenerBase::EventListenerBase;

    void testCaseStarting(Catch::TestCaseInfo const &info) override {
        std::string name(info.name);
        fprintf(stderr, "Test[%s] starting\n", name.c_str());
        fflush(stderr);
    }

    void testCaseEnded(const Catch::TestCaseStats &testRunStats) override {
        fprintf(stderr, "Test run ended[%s]: %" PRIu64 " assertions, %" PRIu64" failed out of %" PRIu64 "\n",
                testRunStats.testInfo->name.c_str(),
                testRunStats.totals.assertions.total(),
                testRunStats.totals.testCases.failed,
                testRunStats.totals.testCases.total()
        );
        fflush(stderr);
    }
};

CATCH_REGISTER_LISTENER(ZitilibManager)

TEST_CASE("version", "[basic]") {
    const ziti_version *version = ziti_get_version();
    REQUIRE(version != nullptr);
}