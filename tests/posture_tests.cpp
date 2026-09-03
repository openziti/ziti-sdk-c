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

#include <string>
#include <vector>

namespace {

    const char *SERVICE_JSON = R"({"id":"svc-1","name":"test-service","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":true,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":true,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";

    // capturing the callback leaves the entry pending, and keeps the answer out of ziti_send_posture_data,
    // whose trailing ziti_pr_send would drive a real controller send
    struct captured_query {
        ziti_pr_process_cb cb = nullptr;
        std::string id;
        std::string path;
    };

    captured_query captured;

    struct pb_holder {
        Ziti__EdgeClient__Pb__PostureResponses *resp = nullptr;
        ~pb_holder() {
            if (resp) ziti__edge_client__pb__posture_responses__free_unpacked(resp, nullptr);
        }
    };

    extern "C" void stub_pq_process(ziti_context, const char *id, const char *path,
                                    ziti_pr_process_cb response_cb) {
        captured = {response_cb, id, path};
    }

    struct posture_fixture {
        // needed only so uv_now() has a loop->time when ziti_posture_init arms its deadline, never inited
        uv_loop_t loop{};
        ziti_ctx ztx{};
        ziti_api_session session{};
        ziti_service *service = nullptr;

        posture_fixture() {
            captured = {};

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
            captured = {};
        }

        void answer() {
            REQUIRE(captured.cb != nullptr);
            captured.cb(&ztx, captured.id.c_str(), captured.path.c_str(), true, "deadbeef", nullptr, 0);
        }

        // get_signers() only reports fingerprints on Windows, so the answer is handed back directly
        void answer_with_signers(std::vector<const char *> signers) {
            REQUIRE(captured.cb != nullptr);
            captured.cb(&ztx, captured.id.c_str(), captured.path.c_str(), true, "deadbeef",
                        (char **) signers.data(), (int) signers.size());
        }

        size_t registered() const { return model_map_size(&ztx.posture_checks->responses); }

        size_t collect_all() {
            model_list send_prs = {};
            ztx_collect_posture(&ztx, &send_prs, true);
            const size_t n = model_list_size(&send_prs);
            model_list_clear(&send_prs, nullptr);
            return n;
        }

        // the single process response of the protobuf message the ER would receive
        const Ziti__EdgeClient__Pb__PostureResponse__Process *collect_pb(pb_holder &holder) {
            model_list send_prs = {};
            ztx_collect_posture(&ztx, &send_prs, true);
            holder.resp = ztx_posture_resp_pb(&ztx, &send_prs);
            model_list_clear(&send_prs, nullptr);

            REQUIRE(holder.resp != nullptr);
            REQUIRE(holder.resp->n_responses == 1);
            const Ziti__EdgeClient__Pb__PostureResponse *r = holder.resp->responses[0];
            REQUIRE(r->type_case == ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_PROCESS_LIST);
            REQUIRE(r->processlist->n_processes == 1);
            return r->processlist->processes[0];
        }
    };
}

TEST_CASE("posture response still pending is not collected", "[posture]") {
    posture_fixture f;

    REQUIRE(f.registered() == 1);
    CHECK(f.collect_all() == 0);
}

TEST_CASE("posture response with an answer is collected", "[posture]") {
    posture_fixture f;
    f.answer();

    REQUIRE(f.registered() == 1);
    CHECK(f.collect_all() == 1);
}

// signer fingerprints were collected and then dropped on the protobuf path, so a process check
// declaring fingerprints failed against an ER while the same identity passed against the controller
TEST_CASE("process posture response carries signer fingerprints", "[posture]") {
    posture_fixture f;
    f.answer_with_signers({"aabbcc", "ddeeff"});

    pb_holder holder;
    const Ziti__EdgeClient__Pb__PostureResponse__Process *proc = f.collect_pb(holder);

    REQUIRE(proc->n_signerfingerprints == 2);
    CHECK(std::string(proc->signerfingerprints[0]) == "aabbcc");
    CHECK(std::string(proc->signerfingerprints[1]) == "ddeeff");
}

TEST_CASE("process posture response without signers reports none", "[posture]") {
    posture_fixture f;
    f.answer();

    pb_holder holder;
    const Ziti__EdgeClient__Pb__PostureResponse__Process *proc = f.collect_pb(holder);

    CHECK(proc->n_signerfingerprints == 0);
    CHECK(proc->signerfingerprints == nullptr);
}
