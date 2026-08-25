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

// An entry is registered before the work that answers it runs, so info->obj is NULL while process collection
// sits on the threadpool. A router asks for posture inside that window and ziti_send_posture_er collects with
// collect_all, which used to sweep the empty entry into create_posture_resp's info->obj->typeId.

#include "catch2_includes.hpp"

// stc/cstr.h declares _cstr_init as plain `extern`, which mangles under C++; common.h first, then cstr.h
// under C linkage, satisfies both without wrapping zt_internal.h (that breaks stc's C++ templates).
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}

#include "posture.h"
#include "zt_internal.h"

namespace {

    const char *SERVICE_JSON = R"({"id":"svc-1","name":"test-service","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":true,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":true,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";

    bool answer_process_query = false;

    // stands in for the threadpool collection: withholding the callback leaves the entry pending with no obj
    extern "C" void stub_pq_process(ziti_context ztx, const char *id, const char *path,
                                    ziti_pr_process_cb response_cb) {
        if (answer_process_query) {
            response_cb(ztx, id, path, true, "deadbeef", nullptr, 0);
        }
    }

    struct posture_fixture {
        uv_loop_t loop{};
        ziti_ctx ztx{};
        ziti_api_session session{};
        ziti_service *service = nullptr;

        explicit posture_fixture(bool answer) {
            answer_process_query = answer;

            uv_loop_init(&loop);
            ztx.loop = &loop;

            // ziti_send_posture_data collects nothing unless the context is fully authenticated
            ztx.auth_state = ZitiAuthStateFullyAuthenticated;
            session.id = "session-1";
            ztx.session = &session;
            ztx.opts.pq_process_cb = stub_pq_process;

            REQUIRE(parse_ziti_service_ptr(&service, SERVICE_JSON, strlen(SERVICE_JSON)) > 0);
            model_map_set(&ztx.services, service->name, service);

            ziti_posture_init(&ztx, 60);
            ziti_send_posture_data(&ztx);
        }

        ~posture_fixture() {
            ziti_posture_checks_free(ztx.posture_checks);
            ztx.posture_checks = nullptr;
            model_map_clear(&ztx.services, (_free_f) free_ziti_service_ptr);
            uv_loop_close(&loop);
            answer_process_query = false;
        }

        size_t registered() const { return model_map_size(&ztx.posture_checks->responses); }

        size_t collect_all() {
            model_list send_prs = {};
            ziti_collect_posture(&ztx, &send_prs, true);
            const size_t n = model_list_size(&send_prs);
            model_list_clear(&send_prs, nullptr);
            return n;
        }
    };
}

TEST_CASE("posture response still pending is not collected", "[posture]") {
    posture_fixture f(false);

    REQUIRE(f.registered() == 1);
    CHECK(f.collect_all() == 0);
}

TEST_CASE("posture response with an answer is collected", "[posture]") {
    posture_fixture f(true);

    REQUIRE(f.registered() == 1);
    CHECK(f.collect_all() == 1);
}
