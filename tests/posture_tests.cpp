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

// model_support.h #defines `map` as a DSL macro, which mangles libc++'s own <map> if it's
// included afterward -- pull the real std::map in first, before any project header can do that.
#include <map>
#include <string>
#include <vector>

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

    const char *SERVICE_JSON_MULTI = R"({"id":"svc-2","name":"multi-service","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":false,"queryType":"PROCESS_MULTI",
      "timeout":-1,"processes":[{"path":"/a"},{"path":"/b"}]}]}}})";

    // capturing the callback leaves the entry pending, and keeps the answer out of ziti_send_posture_data,
    // whose trailing ziti_pr_send would drive a real controller send
    struct captured_query {
        ziti_pr_process_cb cb = nullptr;
        std::string id;
        std::string path;
    };

    captured_query captured;
    // same callbacks, keyed by path -- lets a multi-process rule answer each path independently
    std::map<std::string, captured_query> captured_by_path;

    struct pb_holder {
        Ziti__EdgeClient__Pb__PostureResponses *resp = nullptr;
        ~pb_holder() {
            if (resp) ziti__edge_client__pb__posture_responses__free_unpacked(resp, nullptr);
        }
    };

    extern "C" void stub_pq_process(ziti_context, const char *id, const char *path,
                                    ziti_pr_process_cb response_cb) {
        captured = {response_cb, id, path};
        captured_by_path[path] = captured;
    }

    struct posture_fixture {
        // needed only so uv_now() has a loop->time when ziti_posture_init arms its deadline, never inited
        uv_loop_t loop{};
        ziti_ctx ztx{};
        ziti_api_session session{};
        ziti_service *service = nullptr;

        explicit posture_fixture(const char *json = SERVICE_JSON) {
            captured = {};
            captured_by_path.clear();

            ztx.loop = &loop;

            // ziti_send_posture_data collects nothing unless the context is fully authenticated
            ztx.auth_state = ZitiAuthStateFullyAuthenticated;
            session.id = "session-1";
            ztx.session = &session;
            ztx.opts.pq_process_cb = stub_pq_process;

            REQUIRE(parse_ziti_service_ptr(&service, json, strlen(json)) > 0);
            model_map_set(&ztx.services, service->name, service);

            ziti_posture_init(&ztx, 60);
            ziti_send_posture_data(&ztx);
        }

        ~posture_fixture() {
            ziti_posture_checks_free(ztx.posture_checks);
            ztx.posture_checks = nullptr;
            model_map_clear(&ztx.services, (_free_f) free_ziti_service_ptr);
            captured = {};
            captured_by_path.clear();
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

        // answers one path of a multi-process rule independently of the others
        void answer_path(const std::string &path, bool running) {
            auto it = captured_by_path.find(path);
            REQUIRE(it != captured_by_path.end());
            it->second.cb(&ztx, it->second.id.c_str(), path.c_str(), running, "deadbeef", nullptr, 0);
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

        // the lone posture query on the given policy (defaults to "p1"'s first query)
        ziti_posture_query *query(const char *policy_id = "p1", int idx = 0) const {
            auto *set = (ziti_posture_query_set *) model_map_get(&service->posture_query_map, policy_id);
            REQUIRE(set != nullptr);
            return set->posture_queries[idx];
        }
    };

    struct captured_posture_event {
        int count = 0;
        bool captured = false;
        ziti_posture_query_type query_type{};
        bool passing = false;
        std::vector<std::string> paths;
        std::vector<std::string> failing_paths;
        std::vector<std::string> service_names;
    };

    captured_posture_event captured_event;

    extern "C" void stub_event_cb(ziti_context, const ziti_event_t *ev) {
        REQUIRE(ev->type == ZitiPostureCheckEvent);
        captured_event.count++;
        captured_event.captured = true;
        captured_event.query_type = ev->posture_check.query_type;
        captured_event.passing = ev->posture_check.passing;
        captured_event.paths.clear();
        captured_event.failing_paths.clear();
        captured_event.service_names.clear();
        for (const char **p = ev->posture_check.process.paths; p && *p; p++) {
            captured_event.paths.emplace_back(*p);
        }
        for (const char **p = ev->posture_check.process.failing_paths; p && *p; p++) {
            captured_event.failing_paths.emplace_back(*p);
        }
        for (ziti_service **s = ev->posture_check.services; s && *s; s++) {
            captured_event.service_names.emplace_back((*s)->name);
        }
    }

    bool contains(const std::vector<std::string> &v, const std::string &s) {
        for (auto &e: v) {
            if (e == s) return true;
        }
        return false;
    }

    // bare enough to run notify_process_posture_check_changes() -- it only needs
    // posture_checks initialized, never a registered service or a pq_process_cb
    struct diff_fixture {
        uv_loop_t loop{};
        ziti_ctx ztx{};

        diff_fixture() {
            ztx.loop = &loop;
            ziti_posture_init(&ztx, 60);
            ztx.opts.events = ZitiPostureCheckEvent;
            ztx.opts.event_cb = stub_event_cb;
            captured_event = {};
        }

        ~diff_fixture() {
            ziti_posture_checks_free(ztx.posture_checks);
            ztx.posture_checks = nullptr;
        }
    };

    ziti_service *parse_service(const char *json) {
        ziti_service *svc = nullptr;
        REQUIRE(parse_ziti_service_ptr(&svc, json, strlen(json)) > 0);
        return svc;
    }
}

TEST_CASE("process posture check event reports a failing path with no local answer", "[posture]") {
    posture_fixture f;
    captured_event = {};
    f.ztx.opts.events = ZitiPostureCheckEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    ziti_pr_notify_process_check(&f.ztx, f.query(), false);

    REQUIRE(captured_event.captured);
    CHECK(captured_event.query_type == ziti_posture_query_type_PC_Process);
    CHECK_FALSE(captured_event.passing);
    REQUIRE(captured_event.paths.size() == 1);
    CHECK(captured_event.paths[0] == "/does/not/matter");
    REQUIRE(captured_event.failing_paths.size() == 1);
    CHECK(captured_event.failing_paths[0] == "/does/not/matter");
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "test-service");
}

TEST_CASE("process posture check event omits a path once it's confirmed running", "[posture]") {
    posture_fixture f;
    f.answer();
    captured_event = {};
    f.ztx.opts.events = ZitiPostureCheckEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    ziti_pr_notify_process_check(&f.ztx, f.query(), true);

    REQUIRE(captured_event.captured);
    CHECK(captured_event.passing);
    REQUIRE(captured_event.paths.size() == 1);
    CHECK(captured_event.failing_paths.empty());
}

TEST_CASE("process posture check event is not sent when not subscribed", "[posture]") {
    posture_fixture f;
    captured_event = {};
    // f.ztx.opts.events left at 0 -- ziti_send_event must not invoke the callback
    f.ztx.opts.event_cb = stub_event_cb;

    ziti_pr_notify_process_check(&f.ztx, f.query(), false);

    CHECK_FALSE(captured_event.captured);
}

TEST_CASE("process posture check event reports only the still-failing path in a multi-process rule", "[posture]") {
    posture_fixture f(SERVICE_JSON_MULTI);
    f.answer_path("/a", true);
    f.answer_path("/b", false);
    captured_event = {};
    f.ztx.opts.events = ZitiPostureCheckEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    ziti_pr_notify_process_check(&f.ztx, f.query(), false);

    REQUIRE(captured_event.captured);
    CHECK(captured_event.query_type == ziti_posture_query_type_PC_Process_Multi);
    REQUIRE(captured_event.paths.size() == 2);
    REQUIRE(captured_event.failing_paths.size() == 1);
    CHECK(captured_event.failing_paths[0] == "/b");
}

// notify_process_posture_check_changes() is the ziti.c-side half of this feature: it's what
// update_services() calls to decide *whether* to notify at all, by diffing is_passing per query.
TEST_CASE("a service seen for the first time reports its process check's current state", "[posture]") {
    diff_fixture f;
    ziti_service *svc = parse_service(SERVICE_JSON_MULTI); // isPassing:false in both queries
    model_map_set(&f.ztx.services, svc->name, svc);

    model_map notified = {0};
    notify_process_posture_check_changes(&f.ztx, svc, nullptr, &notified);
    model_map_clear(&notified, nullptr);

    REQUIRE(captured_event.captured);
    CHECK_FALSE(captured_event.passing);

    model_map_clear(&f.ztx.services, (_free_f) free_ziti_service_ptr);
}

TEST_CASE("a process check that flips from failing to passing fires the event", "[posture]") {
    diff_fixture f;

    const char *old_json = R"({"id":"svc-1","name":"test-service","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":false,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";

    ziti_service *old_svc = parse_service(old_json);
    ziti_service *new_svc = parse_service(SERVICE_JSON); // isPassing:true
    model_map_set(&f.ztx.services, new_svc->name, new_svc);

    model_map notified = {0};
    notify_process_posture_check_changes(&f.ztx, new_svc, old_svc, &notified);
    model_map_clear(&notified, nullptr);

    REQUIRE(captured_event.captured);
    CHECK(captured_event.passing);

    free_ziti_service_ptr(old_svc);
    model_map_clear(&f.ztx.services, (_free_f) free_ziti_service_ptr);
}

TEST_CASE("a process check with no is_passing change does not fire the event", "[posture]") {
    diff_fixture f;

    ziti_service *old_svc = parse_service(SERVICE_JSON);
    ziti_service *new_svc = parse_service(SERVICE_JSON); // identical is_passing on both sides
    model_map_set(&f.ztx.services, new_svc->name, new_svc);

    model_map notified = {0};
    notify_process_posture_check_changes(&f.ztx, new_svc, old_svc, &notified);
    model_map_clear(&notified, nullptr);

    CHECK_FALSE(captured_event.captured);

    free_ziti_service_ptr(old_svc);
    model_map_clear(&f.ztx.services, (_free_f) free_ziti_service_ptr);
}

// the fix this test exists for: a posture check is defined on a policy, and a policy can
// govern more than one service. Before this, notify_process_posture_check_changes() fired
// once per service in update_services()'s loop, so a check shared by two services fired
// two ZitiPostureCheckEvents for what is really one transition.
TEST_CASE("a check shared by two services fires one event, listing both services", "[posture]") {
    diff_fixture f;

    const char *svc_a_json = R"({"id":"svc-a","name":"service-a","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":false,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";
    const char *svc_b_json = R"({"id":"svc-b","name":"service-b","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":false,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";

    ziti_service *svc_a = parse_service(svc_a_json);
    ziti_service *svc_b = parse_service(svc_b_json);
    model_map_set(&f.ztx.services, svc_a->name, svc_a);
    model_map_set(&f.ztx.services, svc_b->name, svc_b);

    // one update_services() cycle processing both services -- same policy_id/query_id, same
    // is_passing, on a single shared dedup set, exactly as update_services() itself does
    model_map notified = {0};
    notify_process_posture_check_changes(&f.ztx, svc_a, nullptr, &notified);
    notify_process_posture_check_changes(&f.ztx, svc_b, nullptr, &notified);
    model_map_clear(&notified, nullptr);

    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.service_names.size() == 2);
    CHECK(contains(captured_event.service_names, "service-a"));
    CHECK(contains(captured_event.service_names, "service-b"));

    model_map_clear(&f.ztx.services, (_free_f) free_ziti_service_ptr);
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
