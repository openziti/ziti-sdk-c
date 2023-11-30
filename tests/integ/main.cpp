//
// 	Copyright NetFoundry Inc.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

#include <catch2/catch_all.hpp>
#include <ziti/zitilib.h>
#include <ziti/ziti.h>

class ZitilibManager: public Catch::EventListenerBase{

public:
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const &) override {
        Ziti_lib_init();
    }

    void testRunEnded(const Catch::TestRunStats &testRunStats) override {
        Ziti_lib_shutdown();
    }
};

CATCH_REGISTER_LISTENER(ZitilibManager)

TEST_CASE("version", "[integ]") {
    const ziti_version *version = ziti_get_version();
    REQUIRE(version != nullptr);
}