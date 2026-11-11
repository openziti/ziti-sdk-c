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

// Ziti_wait_for_auth is what an app calls before it uses the services of its context, so the authentication is not
// over for it until the initial services are there. The window between the two is short on a real controller, so a fake
// one (legacy, with an MFA code to give) holds the answer to the request for the services back.

#include "fake_controller.h"

#include "catch2_includes.hpp"

#include <ziti/zitilib.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <string>
#include <thread>

using namespace fake_controller;

namespace {
    // a legacy controller that wants a TOTP code from the identity, and that answers the request for the services after
    // `services_delay_ms`
    class FakeSlowServicesController {
    public:
        explicit FakeSlowServicesController(unsigned services_delay_ms)
                : services_delay_ms_(services_delay_ms),
                  server_([this](const std::string &method, const std::string &path) { return respond(method, path); }) {}

        std::string url() const { return server_.url(); }

        // the delayed answer to the request for the services has been sent
        bool services_answered() const { return services_answered_; }

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

        // the api session; it carries the MFA query until a code is taken
        std::string api_session() const {
            time_t now = time(nullptr);
            const char *queries = code_pending_
                    ? R"([{"id":"mfa-1","typeId":"MFA","provider":"ziti","isTotpEnrolled":true,)"
                      R"("httpMethod":"POST","httpUrl":"./authenticate/mfa","minLength":4,"maxLength":8,)"
                      R"("format":"numeric"}])"
                    : "[]";
            return json_response("200 OK",
                                 R"({"data":{"id":"sess-1","token":"fake-token","identityId":"fake-id",)"
                                 R"("expiresAt":")" + iso8601(now + 1800) + R"(",)" +
                                 R"("updatedAt":")" + iso8601(now) + R"(",)" +
                                 R"("cachedLastActivityAt":")" + iso8601(now) + R"(",)" +
                                 R"("authQueries":)" + queries + R"(,"identity":{"id":"fake-id","name":"fake"}},"meta":{}})");
        }

        std::string respond(const std::string &, const std::string &path) {
            if (ends_with(path, "/version")) {
                return json_response("200 OK", R"({"data":{"version":"v0.0.0-fake","revision":"fake","buildDate":"never",)"
                                      R"("runtimeVersion":"fake","capabilities":[],"buildFlags":[],)"
                                      R"("apiVersions":{"edge":{"v1":{"path":"/edge/client/v1"}}}},"meta":{}})");
            }
            if (ends_with(path, "/authenticate") || ends_with(path, "/current-api-session")) {
                return api_session();
            }
            if (ends_with(path, "/authenticate/mfa")) {
                code_pending_ = false;
                return json_response("200 OK", R"({"data":{},"meta":{}})");
            }
            if (ends_with(path, "/current-api-session/service-updates")) {
                return json_response("200 OK", R"({"data":{"lastChangeAt":"2026-10-30T12:00:00.000Z"},"meta":{}})");
            }
            if (ends_with(path, "/services")) {
                std::this_thread::sleep_for(std::chrono::milliseconds(services_delay_ms_));
                services_answered_ = true;
                return json_response("200 OK", R"({"data":[{"id":"svc-id","name":"svc","permissions":["Dial"],)"
                                      R"("encryptionRequired":false}],"meta":{}})");
            }
            if (ends_with(path, "/posture-response-bulk")) {
                return json_response("200 OK", R"({"data":{"services":[]},"meta":{}})");
            }
            return not_found();
        }

        const unsigned services_delay_ms_;
        std::atomic<bool> code_pending_{true};
        std::atomic<bool> services_answered_{false};
        FakeHttpServer server_;
    };

    // the identity of tls_test_util.h, as the JSON of an identity file, for the controller at `url`
    std::string identity_json(const std::string &url) {
        auto escaped = [](const std::string &pem) {
            std::string out;
            for (char c: pem) {
                if (c == '\n') out += "\\n";
                else out += c;
            }
            return out;
        };
        return R"({"ztAPI":")" + url + R"(","id":{"key":"pem:)" + escaped(rsa_key) +
               R"(","cert":"pem:)" + escaped(rsa_cert) + R"("}})";
    }

    // the library shuts down however the case ends
    struct ZitilibScope {
        ZitilibScope() { Ziti_lib_init(); }
        ~ZitilibScope() { Ziti_lib_shutdown(); }
    };
}

TEST_CASE("Ziti_wait_for_auth waits for the initial services", "[zitilib][wait-for-auth]") {
    FakeSlowServicesController ctrl(1500);
    ZitilibScope zitilib;

    // the identity has to give a code: the load ends with a context that waits for it
    ziti_handle_t ztx = ZITI_INVALID_HANDLE;
    std::string identity = identity_json(ctrl.url());
    REQUIRE(Ziti_load_context(&ztx, identity.c_str()) == ZITI_PARTIALLY_AUTHENTICATED);
    REQUIRE(ztx != ZITI_INVALID_HANDLE);

    // the code is taken: from here on the context is authenticated, and its services are 1.5 s away
    REQUIRE(Ziti_login_totp(ztx, "123456") == ZITI_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    REQUIRE_FALSE(ctrl.services_answered());

    int rc = Ziti_wait_for_auth(ztx, 10000);
    INFO("wait for auth: " << rc << "/" << ziti_errorstr(rc));
    CHECK(rc == ZITI_OK);
    CHECK(ctrl.services_answered());

    // the services are there: there is nothing to wait for any more
    auto before = std::chrono::steady_clock::now();
    CHECK(Ziti_wait_for_auth(ztx, 1000) == ZITI_OK);
    CHECK(std::chrono::steady_clock::now() - before < std::chrono::milliseconds(500));
}
