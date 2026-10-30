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

// GH-1147: where the posture data of a context goes. The routers keep it by the token of an OIDC api session; the
// controller is what checks a legacy api session, so its posture data has to reach the controller, whatever the routers
// can do. The decision used to be left to the routers: with no router connected (a dial asks for its session before any
// router is there) nothing was sent, and with a router that takes posture data the controller never got it.
//
// A real ziti_context runs against a fake controller of the legacy kind (it is the one that gets a context to full
// authentication without an OIDC login), and the controller counts what it is sent. There is no router in a test, so what
// a router that takes posture data would be sent is not looked at: it is the same decision as with no router.
//
// The same fake serves the services of the controller, with the posture queries of a service left out in the ways a
// controller can leave them out.

#include "fake_controller.h"

#include "catch2_includes.hpp"

#include <ctime>

using namespace fake_controller;

// internal (zt_internal.h cannot be included from C++)
extern "C" const char *ziti_get_api_session_token(ziti_context ztx);
extern "C" void ziti_send_posture_data(ziti_context ztx);
// ztx_test_helper.c
extern "C" int ztx_test_service_count(ziti_context ztx);

namespace {
    const char *POSTURE_PATH = "/posture-response-bulk";

    // a service that its policy lets an identity dial if the OS is the right one
    const char *OS_SERVICE = R"({"data":[{"id":"svc-os","name":"os-service","permissions":["Dial"],)"
                             R"("encryptionRequired":false,"postureQueries":[{"policyId":"p1","isPassing":false,)"
                             R"("policyType":"Dial","postureQueries":[{"id":"q-os","isPassing":false,"queryType":"OS",)"
                             R"("timeout":-1}]}]}],"meta":{}})";

    class FakeLegacyController {
    public:
        FakeLegacyController()
                : server_([this](const std::string &method, const std::string &path) { return respond(method, path); }) {}

        // the whole body of the answer to GET /services; set before the context runs
        std::string services = OS_SERVICE;

        std::string url() const { return server_.url(); }

        int posted() const { return server_.count(POSTURE_PATH); }

        std::string posted_body() const { return server_.last_body(POSTURE_PATH); }

    private:
        static bool ends_with(const std::string &s, const std::string &suffix) {
            return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        static std::string iso8601(time_t t) {
            struct tm tm = {};
#if _WIN32
            gmtime_s(&tm, &t);
#else
            gmtime_r(&t, &tm);
#endif
            char buf[40];
            strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000000Z", &tm);
            return buf;
        }

        std::string respond(const std::string &, const std::string &path) {
            if (ends_with(path, "/version")) {
                return json_response("200 OK", R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                                      R"("runtimeVersion":"fake","capabilities":[],"buildFlags":[],)"
                                      R"("apiVersions":{"edge":{"v1":{"path":"/edge/client/v1"}}}},"meta":{}})");
            }
            // the api session of the login, and the same again for the context asking what its session is: posture
            // data goes out only once the context has that session
            if (ends_with(path, "/authenticate") || ends_with(path, "/current-api-session")) {
                time_t now = time(nullptr);
                return json_response("200 OK",
                                     R"({"data":{"id":"sess-1","token":"fake-token","identityId":"fake-id",)"
                                     R"("expiresAt":")" + iso8601(now + 1800) + R"(",)" +
                                     R"("updatedAt":")" + iso8601(now) + R"(",)" +
                                     R"("cachedLastActivityAt":")" + iso8601(now) + R"(",)" +
                                     R"("authQueries":[],"identity":{"id":"fake-id","name":"fake"}},"meta":{}})");
            }
            // the context fetches the services once the controller says that they changed
            if (ends_with(path, "/current-api-session/service-updates")) {
                return json_response("200 OK", R"({"data":{"lastChangeAt":"2026-10-30T12:00:00.000Z"},"meta":{}})");
            }
            if (ends_with(path, "/services")) {
                return json_response("200 OK", services);
            }
            if (ends_with(path, POSTURE_PATH)) {
                return json_response("200 OK", R"({"data":{"services":[]},"meta":{}})");
            }
            return not_found();
        }

        FakeHttpServer server_;
    };
}

TEST_CASE("a legacy api session sends its posture data to the controller", "[posture][GH-1147]") {
    FakeLegacyController ctrl;

    // the tick of the context and every dial send posture data; a test cannot tell when the services of the
    // controller arrive, so it asks as the context would, until the controller has been told
    run_context(ctrl.url(), 8000, [&](const context_run &run) {
        if (ziti_get_api_session_token(run.ztx) != nullptr) {
            ziti_send_posture_data(run.ztx);
        }
        return ctrl.posted() > 0;
    });

    REQUIRE(ctrl.posted() >= 1);
    CHECK(ctrl.posted_body().find("\"typeId\":\"OS\"") != std::string::npos);
}

// A controller can leave the array of posture queries out of a service (the model has it as null then), or send only the
// map of the newer API. The posture queries of such a service are the only thing missing: the context keeps the service.
TEST_CASE("a service without an array of posture queries is loaded", "[posture][GH-1147]") {
    const std::string policy = R"({"policyId":"p1","isPassing":false,"policyType":"Dial","postureQueries":)"
                               R"([{"id":"q-os","isPassing":false,"queryType":"OS","timeout":-1}]})";
    auto posture = GENERATE_COPY(as<std::string>{},
                                 "",
                                 R"(,"postureQueries":null)",
                                 R"(,"posturePolicies":{"p1":)" + policy + "}");
    CAPTURE(posture);

    FakeLegacyController ctrl;
    ctrl.services = R"({"data":[{"id":"svc-1","name":"svc","permissions":["Dial"],"encryptionRequired":false)" +
                    posture + R"(}],"meta":{}})";

    int loaded = 0;
    run_context(ctrl.url(), 8000, [&](const context_run &run) {
        loaded = ztx_test_service_count(run.ztx);
        return loaded > 0;
    });

    CHECK(loaded == 1);
}
