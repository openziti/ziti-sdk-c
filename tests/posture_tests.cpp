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

#include "totp_jwt.h"

// stc/cstr.h declares _cstr_init as plain `extern`, which mangles under C++; common.h first, then cstr.h
// under C linkage, satisfies both without wrapping zt_internal.h (that breaks stc's C++ templates).
#include <stc/common.h>
extern "C" {
#include <stc/cstr.h>
}

#include "posture.h"
#include "zt_internal.h"

// glob_match.c is pure, dependency-free logic with no linkage this test needs from the
// library -- pulling it in under its own namespace (same technique as e2ee_tests.cpp's
// backend-specific includes) reaches its static-in-spirit helpers without the library
// exporting them just for tests.
namespace glob {
#include "../library/glob_match.c"
}

namespace {

    const char *SERVICE_JSON = R"({"id":"svc-1","name":"test-service","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":true,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":true,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";

    const char *SERVICE_JSON_MULTI = R"({"id":"svc-2","name":"multi-service","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":false,"queryType":"PROCESS_MULTI",
      "timeout":-1,"processes":[{"path":"/a"},{"path":"/b"}]}]}}})";

    // an MFA check as the controller describes it: the SDK reads only the id and the timeout of it
    const char *SERVICE_JSON_MFA = R"({"id":"svc-3","name":"mfa-service","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q-mfa","isPassing":false,"queryType":"MFA",
      "timeout":300,"timeoutRemaining":-1}]}}})";

    // the same check (same id) on another service
    const char *SERVICE_JSON_MFA_2 = R"({"id":"svc-4","name":"mfa-service-2","posturePolicies":{"p2":{"policyId":"p2",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q-mfa","isPassing":false,"queryType":"MFA",
      "timeout":300,"timeoutRemaining":-1}]}}})";

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

        void answer(bool running = true) {
            REQUIRE(captured.cb != nullptr);
            captured.cb(&ztx, captured.id.c_str(), captured.path.c_str(), running, "deadbeef", nullptr, 0);
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
        std::vector<std::string> paths;
        std::vector<std::string> missing_paths;
        std::vector<std::string> service_names;
        // PC_MFA; the defaults are values the SDK never reports
        int64_t mfa_timeout = -2;
        int64_t mfa_last_code_at = -1;
        int mfa_expiring = -1;
    };

    captured_posture_event captured_event;

    extern "C" void stub_event_cb(ziti_context, const ziti_event_t *ev) {
        REQUIRE(ev->type == ZitiPostureStatusEvent);
        captured_event.count++;
        captured_event.captured = true;
        captured_event.query_type = ev->posture_status.query_type;
        captured_event.paths.clear();
        captured_event.missing_paths.clear();
        captured_event.service_names.clear();
        if (ev->posture_status.query_type == ziti_posture_query_type_PC_MFA) {
            captured_event.mfa_timeout = ev->posture_status.mfa.timeout;
            captured_event.mfa_last_code_at = ev->posture_status.mfa.last_code_at;
            captured_event.mfa_expiring = ev->posture_status.mfa.expiring;
        } else {
            for (const char **p = ev->posture_status.process.paths; p && *p; p++) {
                captured_event.paths.emplace_back(*p);
            }
            for (const char **p = ev->posture_status.process.missing_paths; p && *p; p++) {
                captured_event.missing_paths.emplace_back(*p);
            }
        }
        for (ziti_service **s = ev->posture_status.services; s && *s; s++) {
            captured_event.service_names.emplace_back((*s)->name);
        }
    }

    bool contains(const std::vector<std::string> &v, const std::string &s) {
        for (auto &e: v) {
            if (e == s) return true;
        }
        return false;
    }

    ziti_service *parse_service(const char *json) {
        ziti_service *svc = nullptr;
        REQUIRE(parse_ziti_service_ptr(&svc, json, strlen(json)) > 0);
        return svc;
    }
}

TEST_CASE("process posture check event reports a failing path with no local answer", "[posture]") {
    posture_fixture f;
    captured_event = {};
    f.ztx.opts.events = ZitiPostureStatusEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    ziti_pr_notify_process_status(&f.ztx, f.query());

    REQUIRE(captured_event.captured);
    CHECK(captured_event.query_type == ziti_posture_query_type_PC_Process);
    REQUIRE(captured_event.paths.size() == 1);
    CHECK(captured_event.paths[0] == "/does/not/matter");
    REQUIRE(captured_event.missing_paths.size() == 1);
    CHECK(captured_event.missing_paths[0] == "/does/not/matter");
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "test-service");
}

TEST_CASE("process posture check event omits a path once it's confirmed running", "[posture]") {
    posture_fixture f;
    f.answer();
    captured_event = {};
    f.ztx.opts.events = ZitiPostureStatusEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    ziti_pr_notify_process_status(&f.ztx, f.query());

    REQUIRE(captured_event.captured);
    REQUIRE(captured_event.paths.size() == 1);
    CHECK(captured_event.missing_paths.empty());
}

TEST_CASE("process posture check event reports only the still-missing path in a multi-process rule", "[posture]") {
    posture_fixture f(SERVICE_JSON_MULTI);
    f.answer_path("/a", true);
    f.answer_path("/b", false);
    captured_event = {};
    f.ztx.opts.events = ZitiPostureStatusEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    ziti_pr_notify_process_status(&f.ztx, f.query());

    REQUIRE(captured_event.captured);
    CHECK(captured_event.query_type == ziti_posture_query_type_PC_Process_Multi);
    REQUIRE(captured_event.paths.size() == 2);
    REQUIRE(captured_event.missing_paths.size() == 1);
    CHECK(captured_event.missing_paths[0] == "/b");
}

// ziti_pr_handle_process() is the real trigger: it's the response_cb every pq_process_cb
// implementation (built-in or the app's own) calls with a path's freshly checked is_running.
// It fires only when that local fact changes -- not on every periodic re-check -- and never
// looks at is_passing, which the controller can no longer be relied on to keep current.
TEST_CASE("a path's first answer fires the event, regardless of which way it answers", "[posture]") {
    posture_fixture f;
    captured_event = {};
    f.ztx.opts.events = ZitiPostureStatusEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    f.answer(false); // nothing to diff against yet -- still worth telling the app

    REQUIRE(captured_event.captured);
    REQUIRE(captured_event.missing_paths.size() == 1);
}

TEST_CASE("answering with the same running state again does not re-fire", "[posture]") {
    posture_fixture f;
    f.answer(true); // establishes the prior state
    captured_event = {};
    f.ztx.opts.events = ZitiPostureStatusEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    f.answer(true); // same fact reported again on the next check cycle

    CHECK_FALSE(captured_event.captured);
}

TEST_CASE("a path flipping from running to not running fires again", "[posture]") {
    posture_fixture f;
    f.answer(true);
    captured_event = {};
    f.ztx.opts.events = ZitiPostureStatusEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    f.answer(false);

    REQUIRE(captured_event.captured);
    CHECK(captured_event.missing_paths.size() == 1);
}

TEST_CASE("process posture check event is not sent when not subscribed", "[posture]") {
    posture_fixture f;
    captured_event = {};
    // f.ztx.opts.events left at 0 -- ziti_send_event must not invoke the callback
    f.ztx.opts.event_cb = stub_event_cb;

    f.answer(false);

    CHECK_FALSE(captured_event.captured);
}

// a posture check is defined on a policy, and a policy can govern more than one service.
// ztx_posture_checks() already dedups the pq_process_cb dispatch by path, so a shared check
// only ever gets one is_running answer to react to -- this confirms that answer still fans
// the event's `services` out to every service the check applies to.
TEST_CASE("a check shared by two services lists both services when the process is not running", "[posture]") {
    const char *svc_a_json = R"({"id":"svc-a","name":"service-a","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":false,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";
    const char *svc_b_json = R"({"id":"svc-b","name":"service-b","posturePolicies":{"p1":{"policyId":"p1",
      "isPassing":false,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":false,"queryType":"PROCESS",
      "timeout":-1,"process":{"path":"/does/not/matter"}}]}}})";

    uv_loop_t loop{};
    ziti_ctx ztx{};
    ziti_api_session session{};
    ztx.loop = &loop;
    ztx.auth_state = ZitiAuthStateFullyAuthenticated;
    session.id = "session-1";
    ztx.session = &session;
    ztx.opts.pq_process_cb = stub_pq_process;

    ziti_service *svc_a = parse_service(svc_a_json);
    ziti_service *svc_b = parse_service(svc_b_json);
    model_map_set(&ztx.services, svc_a->name, svc_a);
    model_map_set(&ztx.services, svc_b->name, svc_b);

    captured = {};
    captured_by_path.clear();
    ziti_posture_init(&ztx, 60);
    ziti_send_posture_data(&ztx); // one pq_process_cb dispatch for the shared path

    captured_event = {};
    ztx.opts.events = ZitiPostureStatusEvent;
    ztx.opts.event_cb = stub_event_cb;

    REQUIRE(captured.cb != nullptr);
    captured.cb(&ztx, captured.id.c_str(), captured.path.c_str(), false, "deadbeef", nullptr, 0);

    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.missing_paths.size() == 1);
    REQUIRE(captured_event.service_names.size() == 2);
    CHECK(contains(captured_event.service_names, "service-a"));
    CHECK(contains(captured_event.service_names, "service-b"));

    ziti_posture_checks_free(ztx.posture_checks);
    model_map_clear(&ztx.services, (_free_f) free_ziti_service_ptr);
}

namespace {
    using totp_test::totp_jwt;

    // the batch the routers would receive when no other response is due
    Ziti__EdgeClient__Pb__PostureResponses *pb_without_responses(ziti_context ztx) {
        model_list none = {};
        return ztx_posture_resp_pb(ztx, &none);
    }
}

TEST_CASE("a TOTP token is sent as a TotpToken posture response", "[posture][totp]") {
    posture_fixture f;
    const std::string token = totp_jwt("session-1");
    REQUIRE(ztx_posture_set_totp_token(&f.ztx, token.c_str()) == ZITI_OK);

    pb_holder holder;
    holder.resp = pb_without_responses(&f.ztx);

    REQUIRE(holder.resp != nullptr);
    REQUIRE(holder.resp->n_responses == 1);
    const Ziti__EdgeClient__Pb__PostureResponse *r = holder.resp->responses[0];
    REQUIRE(r->type_case == ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_TOTP_TOKEN);
    CHECK(std::string(r->totptoken->token) == token);
}

TEST_CASE("a TOTP token of another api session is not sent until the session matches", "[posture][totp]") {
    posture_fixture f;
    const std::string token = totp_jwt("session-2");
    REQUIRE(ztx_posture_set_totp_token(&f.ztx, token.c_str()) == ZITI_OK);

    // the context is still on session-1: a token for another session is worth nothing to the router
    pb_holder none;
    none.resp = pb_without_responses(&f.ztx);
    CHECK(none.resp == nullptr);

    // the reply of a token request can beat the refresh of the api session: it goes out once they agree
    f.session.id = "session-2";
    pb_holder sent;
    sent.resp = pb_without_responses(&f.ztx);
    REQUIRE(sent.resp != nullptr);
    REQUIRE(sent.resp->n_responses == 1);
    CHECK(sent.resp->responses[0]->type_case == ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_TOTP_TOKEN);
}

TEST_CASE("a TOTP token comes along with the other responses", "[posture][totp]") {
    posture_fixture f;
    f.answer(true);
    REQUIRE(ztx_posture_set_totp_token(&f.ztx, totp_jwt("session-1").c_str()) == ZITI_OK);

    model_list send_prs = {};
    ztx_collect_posture(&f.ztx, &send_prs, true);
    pb_holder holder;
    holder.resp = ztx_posture_resp_pb(&f.ztx, &send_prs);
    model_list_clear(&send_prs, nullptr);

    REQUIRE(holder.resp != nullptr);
    REQUIRE(holder.resp->n_responses == 2);
    int process_lists = 0, totp_tokens = 0;
    for (size_t i = 0; i < holder.resp->n_responses; i++) {
        switch (holder.resp->responses[i]->type_case) {
            case ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_PROCESS_LIST: process_lists++; break;
            case ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_TOTP_TOKEN: totp_tokens++; break;
            default: break;
        }
    }
    CHECK(process_lists == 1);
    CHECK(totp_tokens == 1);
}

TEST_CASE("a token that is not a JWT with z_asid is refused", "[posture][totp]") {
    posture_fixture f;

    CHECK(ztx_posture_set_totp_token(&f.ztx, "garbage") == ZITI_JWT_INVALID);
    CHECK(ztx_posture_set_totp_token(&f.ztx, "") == ZITI_JWT_INVALID);
    CHECK(ztx_posture_set_totp_token(&f.ztx, totp_jwt(nullptr).c_str()) == ZITI_JWT_INVALID);

    // a refused token leaves nothing to send
    pb_holder holder;
    holder.resp = pb_without_responses(&f.ztx);
    CHECK(holder.resp == nullptr);

    // no posture state (the endpoint is disabled): nowhere to keep it
    ziti_ctx disabled{};
    CHECK(ztx_posture_set_totp_token(&disabled, totp_jwt("session-1").c_str()) == ZITI_INVALID_STATE);
}

// An MFA check is decided by the routers, from the TOTP token the SDK sends them and the timeout of the check, and the
// controller no longer knows whether it passes: the event says what the SDK itself knows of the code, when the check
// last had one from this api session and how long the check lets a code count, and fires when that changes.
namespace {
    void watch(posture_fixture &f) {
        captured_event = {};
        f.ztx.opts.events = ZitiPostureStatusEvent;
        f.ztx.opts.event_cb = stub_event_cb;
    }

    // keeps the token as the context does when the controller issues it, then tells the app, as totp_token_cb() does once
    // the token is sent to the routers: the routers apply it on their own time, so the event is no promise that they have it
    int give_token(ziti_ctx *ztx, const char *token) {
        int rc = ztx_posture_set_totp_token(ztx, token);
        if (rc == ZITI_OK) {
            ztx_posture_notify_mfa(ztx);
        }
        return rc;
    }
}

TEST_CASE("an MFA check is reported with the timeout of the check and no code before a code is given", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);

    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.query_type == ziti_posture_query_type_PC_MFA);
    CHECK(captured_event.mfa_timeout == 300);
    CHECK(captured_event.mfa_last_code_at == 0);
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "mfa-service");
}

TEST_CASE("an MFA check is reported once while nothing about its code changes", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);

    ztx_posture_notify_mfa(&f.ztx);
    ztx_posture_notify_mfa(&f.ztx);

    CHECK(captured_event.count == 1);
}

TEST_CASE("keeping a TOTP token does not report it, the app is told once the token is sent to the routers", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);

    REQUIRE(ztx_posture_set_totp_token(&f.ztx, totp_jwt("session-1", 1700000123).c_str()) == ZITI_OK);
    CHECK(captured_event.count == 1);

    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_last_code_at == 1700000123);
}

TEST_CASE("a TOTP token of the api session reports when its code was given", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);

    REQUIRE(give_token(&f.ztx, totp_jwt("session-1", 1700000123).c_str()) == ZITI_OK);

    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_last_code_at == 1700000123);
    CHECK(captured_event.mfa_timeout == 300);

    // a later code is a change again, the same code is not
    REQUIRE(give_token(&f.ztx, totp_jwt("session-1", 1700000456).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 3);
    CHECK(captured_event.mfa_last_code_at == 1700000456);

    REQUIRE(give_token(&f.ztx, totp_jwt("session-1", 1700000456).c_str()) == ZITI_OK);
    CHECK(captured_event.count == 3);
}

TEST_CASE("a TOTP token of another api session is no code of this one", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);

    REQUIRE(give_token(&f.ztx, totp_jwt("session-2", 1700000123).c_str()) == ZITI_OK);
    CHECK(captured_event.count == 1);

    // the context learns of that api session later (the reply of the token request came first)
    f.session.id = "session-2";
    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_last_code_at == 1700000123);
}

TEST_CASE("a code that the api session loses is reported as no code", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);
    REQUIRE(give_token(&f.ztx, totp_jwt("session-1", 1700000123).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.mfa_last_code_at == 1700000123);

    // a new login, a new api session: the token belongs to the old one
    f.session.id = "session-3";
    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_last_code_at == 0);
}

TEST_CASE("a change of the timeout of an MFA check fires again", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);

    f.query()->timeout = 600;
    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_timeout == 600);
}

// A code starts to expire 5 minutes before the end of its timeout (half the timeout, when that is less than 5 minutes),
// which the SDK finds out with the posture cycle. The tests give the code the age they need: it was given `age` seconds ago.
namespace {
    // a TOTP token of session-1 for a code that was given `age` seconds ago
    std::string aged_token(long long age) {
        return totp_jwt("session-1", (long long) time(nullptr) - age);
    }
}

TEST_CASE("a code far from the end of its timeout is not expiring", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = 3600;
    watch(f);

    REQUIRE(give_token(&f.ztx, aged_token(60).c_str()) == ZITI_OK);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_last_code_at != 0);
    CHECK(captured_event.mfa_expiring == 0);
}

TEST_CASE("a code in the last 5 minutes of its timeout is expiring", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = 3600;
    watch(f);

    // 3200 s old is 400 s from the end: more than 5 minutes, although it is past half of the timeout
    REQUIRE(give_token(&f.ztx, aged_token(3200).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_expiring == 0);

    // 3400 s old is 200 s from the end
    REQUIRE(give_token(&f.ztx, aged_token(3400).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_expiring == 1);
}

TEST_CASE("the posture cycle finds out that a code starts to expire as time passes", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = 3600;
    watch(f);
    REQUIRE(give_token(&f.ztx, aged_token(3200).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 1);

    // nothing changed: the cycle says nothing
    ztx_posture_tick(&f.ztx);
    CHECK(captured_event.count == 1);

    // 200 s later
    f.ztx.posture_checks->totp.issued_at -= 200;
    ztx_posture_tick(&f.ztx);
    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_expiring == 1);

    // and it says it once
    ztx_posture_tick(&f.ztx);
    CHECK(captured_event.count == 2);
}

TEST_CASE("the posture data sent by a dial does not run the handler of the MFA event", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = 3600;
    watch(f);
    REQUIRE(give_token(&f.ztx, aged_token(3200).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 1);

    // the code starts to expire; ziti_dial() sends posture data, and the app must not hear of it from inside the dial
    f.ztx.posture_checks->totp.issued_at -= 200;
    ziti_send_posture_data(&f.ztx);
    CHECK(captured_event.count == 1);

    // the timer tells it
    ztx_posture_tick(&f.ztx);
    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_expiring == 1);
}

TEST_CASE("a timeout under 10 minutes warns from half of it", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = 60;
    watch(f);

    REQUIRE(give_token(&f.ztx, aged_token(20).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_expiring == 0);

    REQUIRE(give_token(&f.ztx, aged_token(40).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_expiring == 1);
}

TEST_CASE("a new code ends the warning", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = 3600;
    watch(f);
    REQUIRE(give_token(&f.ztx, aged_token(3500).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.mfa_expiring == 1);

    REQUIRE(give_token(&f.ztx, aged_token(0).c_str()) == ZITI_OK);

    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_expiring == 0);
}

TEST_CASE("a code never expires when the check has no timeout", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = -1;
    watch(f);

    REQUIRE(give_token(&f.ztx, aged_token(100000).c_str()) == ZITI_OK);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_timeout == -1);
    CHECK(captured_event.mfa_expiring == 0);
}

TEST_CASE("no code is not an expiring code", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);

    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_last_code_at == 0);
    CHECK(captured_event.mfa_expiring == 0);
}

TEST_CASE("an MFA check shared by two services is reported once, for both", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    ziti_service *second = parse_service(SERVICE_JSON_MFA_2);
    model_map_set(&f.ztx.services, second->name, second);
    watch(f);

    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.service_names.size() == 2);
    CHECK(contains(captured_event.service_names, "mfa-service"));
    CHECK(contains(captured_event.service_names, "mfa-service-2"));
}

// The services a check governs are part of what the app was told: they change as the controller lists other services,
// which the context takes in or out of ztx->services before it looks at the MFA checks again.
namespace {
    // as update_services() does when the controller no longer lists the service
    void remove_service(posture_fixture &f, const char *name) {
        free_ziti_service_ptr((ziti_service *) model_map_remove(&f.ztx.services, name));
    }

    void add_service(posture_fixture &f, const char *json) {
        ziti_service *svc = parse_service(json);
        model_map_set(&f.ztx.services, svc->name, svc);
    }
}

TEST_CASE("a service that picks up an MFA check is added to what the app was told", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.service_names.size() == 1);

    add_service(f, SERVICE_JSON_MFA_2);
    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 2);
    REQUIRE(captured_event.service_names.size() == 2);
    CHECK(contains(captured_event.service_names, "mfa-service"));
    CHECK(contains(captured_event.service_names, "mfa-service-2"));
}

TEST_CASE("a service that leaves an MFA check is taken out of what the app was told", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    add_service(f, SERVICE_JSON_MFA_2);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.service_names.size() == 2);

    remove_service(f, "mfa-service-2");
    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 2);
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "mfa-service");
}

TEST_CASE("the same services in another order are not a change", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    add_service(f, SERVICE_JSON_MFA_2);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);

    // the controller lists both again: one of them comes back last
    remove_service(f, "mfa-service");
    add_service(f, SERVICE_JSON_MFA);
    ztx_posture_notify_mfa(&f.ztx);

    CHECK(captured_event.count == 1);
}

// The app learns that a service is gone from its ZitiServiceEvent: a check that no service carries any more is dropped
// without an event of its own, and the app is told of it again when a service brings it back.
TEST_CASE("an MFA check that goes away is dropped, and reported again when it comes back", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    watch(f);
    ztx_posture_notify_mfa(&f.ztx);
    REQUIRE(captured_event.count == 1);

    remove_service(f, "mfa-service");
    ztx_posture_notify_mfa(&f.ztx);
    CHECK(captured_event.count == 1);

    add_service(f, SERVICE_JSON_MFA);
    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 2);
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "mfa-service");
}

// An app that needs a code asks for one, and one code serves every check: the SDK tells of the checks that need a code
// now (no code was given, or the code is past the timeout of the check), all in one event, or else of the checks whose
// code ends first. The other checks have nothing for the app to do yet.
namespace {
    // an MFA check as the controller describes it, on a service of its own
    std::string mfa_service_json(const char *id, const char *name, const char *query_id, int timeout) {
        char buf[600];
        snprintf(buf, sizeof(buf),
                 R"({"id":"%s","name":"%s","posturePolicies":{"p-%s":{"policyId":"p-%s","isPassing":false,)"
                 R"("policyType":"Dial","postureQueries":[{"id":"%s","isPassing":false,"queryType":"MFA",)"
                 R"("timeout":%d,"timeoutRemaining":-1}]}}})",
                 id, name, id, id, query_id, timeout);
        return buf;
    }

    void add_mfa_service(posture_fixture &f, const char *name, const char *query_id, int timeout) {
        add_service(f, mfa_service_json(name, name, query_id, timeout).c_str());
    }
}

TEST_CASE("checks that need a code are reported in one event, with the shortest timeout", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    add_mfa_service(f, "svc-short", "q-short", 60);
    watch(f);

    ztx_posture_notify_mfa(&f.ztx);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_last_code_at == 0);
    CHECK(captured_event.mfa_timeout == 60);
    CHECK(captured_event.mfa_expiring == 0);
    REQUIRE(captured_event.service_names.size() == 2);
    CHECK(contains(captured_event.service_names, "mfa-service"));
    CHECK(contains(captured_event.service_names, "svc-short"));
}

TEST_CASE("with a code, the check whose code ends first is reported, and no other", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    add_mfa_service(f, "svc-long", "q-long", 3600);
    watch(f);

    REQUIRE(give_token(&f.ztx, aged_token(10).c_str()) == ZITI_OK);

    // 300 s ends before 3600 s
    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_timeout == 300);
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "mfa-service");
}

TEST_CASE("the checks that are past their timeout are reported together, the others are not", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    add_mfa_service(f, "svc-short", "q-short", 60);
    add_mfa_service(f, "svc-mid", "q-mid", 90);
    add_mfa_service(f, "svc-long", "q-long", 3600);
    watch(f);

    // 100 s old: the checks of 60 s and 90 s have ended, the ones of 300 s and 3600 s have not
    REQUIRE(give_token(&f.ztx, aged_token(100).c_str()) == ZITI_OK);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_timeout == 60);
    CHECK(captured_event.mfa_expiring == 1);
    REQUIRE(captured_event.service_names.size() == 2);
    CHECK(contains(captured_event.service_names, "svc-short"));
    CHECK(contains(captured_event.service_names, "svc-mid"));
}

TEST_CASE("checks without a timeout are reported together when a code is given", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    f.query()->timeout = -1;
    add_mfa_service(f, "svc-never", "q-never", -1);
    watch(f);

    REQUIRE(give_token(&f.ztx, aged_token(10).c_str()) == ZITI_OK);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_timeout == -1);
    CHECK(captured_event.mfa_expiring == 0);
    REQUIRE(captured_event.service_names.size() == 2);
}

TEST_CASE("a check with a timeout ends before one without", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    add_mfa_service(f, "svc-never", "q-never", -1);
    watch(f);

    REQUIRE(give_token(&f.ztx, aged_token(10).c_str()) == ZITI_OK);

    REQUIRE(captured_event.count == 1);
    CHECK(captured_event.mfa_timeout == 300);
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "mfa-service");
}

TEST_CASE("the check that is reported changes as the code ages", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    add_mfa_service(f, "svc-short", "q-short", 60);
    watch(f);
    REQUIRE(give_token(&f.ztx, aged_token(0).c_str()) == ZITI_OK);
    REQUIRE(captured_event.count == 1);
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "svc-short");
    CHECK(captured_event.mfa_expiring == 0);

    // the 60 s of that check are over, the 300 s of the other are not
    f.ztx.posture_checks->totp.issued_at -= 70;
    ztx_posture_tick(&f.ztx);

    REQUIRE(captured_event.count == 2);
    CHECK(captured_event.mfa_expiring == 1);
    REQUIRE(captured_event.service_names.size() == 1);
    CHECK(captured_event.service_names[0] == "svc-short");

    // and both when the other ends too
    f.ztx.posture_checks->totp.issued_at -= 300;
    ztx_posture_tick(&f.ztx);

    REQUIRE(captured_event.count == 3);
    CHECK(captured_event.service_names.size() == 2);
}

TEST_CASE("an MFA check is not reported when not subscribed, and is once the app subscribes", "[posture][totp]") {
    posture_fixture f(SERVICE_JSON_MFA);
    captured_event = {};
    f.ztx.opts.event_cb = stub_event_cb;

    ztx_posture_notify_mfa(&f.ztx);
    CHECK(captured_event.count == 0);

    f.ztx.opts.events = ZitiPostureStatusEvent;
    ztx_posture_notify_mfa(&f.ztx);
    CHECK(captured_event.count == 1);
}

TEST_CASE("a process check is not reported as an MFA check", "[posture][totp]") {
    posture_fixture f;
    captured_event = {};
    f.ztx.opts.events = ZitiPostureStatusEvent;
    f.ztx.opts.event_cb = stub_event_cb;

    ztx_posture_notify_mfa(&f.ztx);

    CHECK(captured_event.count == 0);
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

TEST_CASE("wildcard detection only fires on glob characters", "[posture]") {
    CHECK_FALSE(glob::ziti_glob_has_wildcard("/opt/app/bin/app"));
    CHECK_FALSE(glob::ziti_glob_has_wildcard("C:\\Program Files\\App\\app.exe"));
    CHECK(glob::ziti_glob_has_wildcard("/opt/app/*/bin/app"));
    CHECK(glob::ziti_glob_has_wildcard("/opt/app/bin/app?"));
}

TEST_CASE("a literal pattern only matches its exact path", "[posture]") {
    CHECK(glob::ziti_glob_match("/opt/app/bin/app", "/opt/app/bin/app", false));
    CHECK_FALSE(glob::ziti_glob_match("/opt/app/bin/app", "/opt/app/bin/app2", false));
    CHECK_FALSE(glob::ziti_glob_match("/opt/app/bin/app", "/opt/app/bin/ap", false));
}

TEST_CASE("case sensitivity of a literal match is controlled by the flag", "[posture]") {
    CHECK_FALSE(glob::ziti_glob_match("/Opt/App", "/opt/app", false));
    CHECK(glob::ziti_glob_match("/Opt/App", "/opt/app", true));
}

TEST_CASE("'*' matches any run of characters, including none and path separators", "[posture]") {
    CHECK(glob::ziti_glob_match("C:\\Program Files\\App\\*\\app.exe",
                                     "C:\\Program Files\\App\\2.1.0\\app.exe", true));
    CHECK(glob::ziti_glob_match("/opt/app/*bin/app", "/opt/app/bin/app", false));
    CHECK(glob::ziti_glob_match("/opt/app/*", "/opt/app/1.2.3/bin/app", false));
    CHECK(glob::ziti_glob_match("*app.exe", "C:\\Program Files\\App\\app.exe", true));
    CHECK_FALSE(glob::ziti_glob_match("/opt/app/*/bin/app", "/opt/other/1.0/bin/app", false));
}

TEST_CASE("'?' matches exactly one character", "[posture]") {
    CHECK(glob::ziti_glob_match("/opt/app-?/bin/app", "/opt/app-1/bin/app", false));
    CHECK_FALSE(glob::ziti_glob_match("/opt/app-?/bin/app", "/opt/app-10/bin/app", false));
    CHECK_FALSE(glob::ziti_glob_match("/opt/app-?/bin/app", "/opt/app-/bin/app", false));
}

TEST_CASE("combined '*' and '?' wildcards match a versioned install path", "[posture]") {
    CHECK(glob::ziti_glob_match("/opt/app/*/v?.exe", "/opt/app/1.2.3/v2.exe", false));
    CHECK_FALSE(glob::ziti_glob_match("/opt/app/*/v?.exe", "/opt/app/1.2.3/v22.exe", false));
}

TEST_CASE("deleted-suffix detection only fires on the exact kernel-appended marker", "[posture]") {
    CHECK(glob::ziti_path_has_deleted_suffix("/opt/app/bin/app (deleted)"));
    CHECK_FALSE(glob::ziti_path_has_deleted_suffix("/opt/app/bin/app"));
    CHECK_FALSE(glob::ziti_path_has_deleted_suffix("/opt/app/bin/app (deleted"));
    CHECK_FALSE(glob::ziti_path_has_deleted_suffix("(deleted)"));
    CHECK(glob::ziti_path_has_deleted_suffix(" (deleted)"));
}

// a /proc/<pid>/exe readlink for a running-but-unlinked binary reads back with this literal
// suffix appended -- a trailing '*' would otherwise happily absorb it and treat the phantom
// path as a match. This is exactly the guard find_running_match()'s Linux branch applies
// (ziti_path_has_deleted_suffix() checked before ziti_glob_match()); the pre-wildcard code's
// exact strcmp() could never produce this false match, since a literal configured path is
// never equal to path + " (deleted)".
TEST_CASE("a wildcard would otherwise match a deleted binary's readlink target", "[posture]") {
    const char *deleted_target = "/opt/app/bin/app (deleted)";
    CHECK(glob::ziti_glob_match("/opt/app/*", deleted_target, false));
    CHECK(glob::ziti_path_has_deleted_suffix(deleted_target));
}

TEST_CASE("an empty pattern only matches an empty candidate", "[posture]") {
    CHECK(glob::ziti_glob_match("", "", false));
    CHECK_FALSE(glob::ziti_glob_match("", "x", false));
    CHECK_FALSE(glob::ziti_glob_has_wildcard(""));
}

TEST_CASE("consecutive stars behave the same as one", "[posture]") {
    CHECK(glob::ziti_glob_match("**", "anything/at/all", false));
    CHECK(glob::ziti_glob_match("**", "", false));
    CHECK(glob::ziti_glob_match("/opt/**/app", "/opt/1/2/3/app", false));
    CHECK(glob::ziti_glob_match("opt**app", "optapp", false));
    CHECK(glob::ziti_glob_match("opt**app", "optXYZapp", false));
}

TEST_CASE("'*' against an empty candidate matches only when nothing else is required", "[posture]") {
    CHECK(glob::ziti_glob_match("*", "", false));
    CHECK_FALSE(glob::ziti_glob_match("a*", "", false));
    CHECK_FALSE(glob::ziti_glob_match("*a", "", false));
}

// the matcher treats '*' as a run of raw characters with no separator awareness (a deliberate
// choice -- see ziti_glob_match's doc comment), so a pattern spelled with one separator style
// still matches a candidate using the other.
TEST_CASE("'*' crosses separator styles because the matcher has no separator awareness", "[posture]") {
    CHECK(glob::ziti_glob_match("/opt/app*", "/opt/app\\1.2.3\\bin\\app", false));
    CHECK(glob::ziti_glob_match("C:\\Program Files*", "C:\\Program Files/App/app.exe", true));
}

namespace {
    // JSON-escapes a filesystem path for embedding in the test service JSON below --
    // matters on Windows, where uv_exepath() returns backslash-separated paths.
    std::string json_escape(const std::string &s) {
        std::string out;
        for (char c: s) {
            if (c == '\\' || c == '"') out += '\\';
            out += c;
        }
        return out;
    }

    std::string current_exe_path() {
        char buf[1024];
        size_t len = sizeof(buf) - 1;
        REQUIRE(uv_exepath(buf, &len) == 0);
        buf[len] = '\0';
        return {buf};
    }

    // builds a one-service, one-PROCESS-query service JSON with the given (already-escaped
    // for JSON, not yet wildcarded) path pattern.
    std::string process_service_json(const std::string &pattern) {
        return R"({"id":"svc-1","name":"test-service","posturePolicies":{"p1":{"policyId":"p1",)"
               R"("isPassing":true,"policyType":"Dial","postureQueries":[{"id":"q1","isPassing":true,"queryType":"PROCESS",)"
               R"("timeout":-1,"process":{"path":")" + json_escape(pattern) + R"("}}]}}})";
    }

    // one loop shared by every production-path case below, run per-case but never closed --
    // same fix as ctrl_endpoint_tests.cpp's test_loop(): creating and closing a uv_loop_t per
    // case hit libuv's `fd > STDERR_FILENO` assertion intermittently once the whole suite ran
    // in the same process, while the cases on their own always passed.
    uv_loop_t *process_check_loop() {
        static uv_loop_t *loop = uv_loop_new();
        return loop;
    }
}

// These two drive the real production path -- ziti_send_posture_data() -> default_pq_process()
// (opts.pq_process_cb left unset, unlike posture_fixture's stub) -> uv_queue_work() ->
// process_check_work() -> find_running_match() -- through a genuinely running uv_loop, rather
// than through the stubbed callback every other test in this file uses. No OS state needs
// faking: appending '*' to this test binary's own executable path is guaranteed to resolve to
// a real, currently-running, readable file, and a nonsense path is guaranteed to match nothing
// on any machine.
TEST_CASE("a wildcard resolving to this process's own executable reports running with a hash", "[posture]") {
    uv_loop_t *loop = process_check_loop();

    ziti_ctx ztx{};
    ziti_api_session session{};
    ztx.loop = loop;
    ztx.auth_state = ZitiAuthStateFullyAuthenticated;
    session.id = "session-1";
    ztx.session = &session;
    // opts.pq_process_cb intentionally left null -- ziti_send_posture_data() falls back to
    // the real default_pq_process()/process_check_work() implementation.

    std::string pattern = current_exe_path() + "*";
    std::string json = process_service_json(pattern);
    ziti_service *service = nullptr;
    REQUIRE(parse_ziti_service_ptr(&service, json.c_str(), json.size()) > 0);
    model_map_set(&ztx.services, service->name, service);

    ziti_posture_init(&ztx, 60);
    ziti_send_posture_data(&ztx);
    REQUIRE(uv_run(loop, UV_RUN_DEFAULT) == 0);

    model_list send_prs = {};
    ztx_collect_posture(&ztx, &send_prs, true);
    pb_holder holder;
    holder.resp = ztx_posture_resp_pb(&ztx, &send_prs);
    model_list_clear(&send_prs, nullptr);

    REQUIRE(holder.resp != nullptr);
    REQUIRE(holder.resp->n_responses == 1);
    const Ziti__EdgeClient__Pb__PostureResponse *r = holder.resp->responses[0];
    REQUIRE(r->type_case == ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_PROCESS_LIST);
    REQUIRE(r->processlist->n_processes == 1);
    const Ziti__EdgeClient__Pb__PostureResponse__Process *proc = r->processlist->processes[0];
    CHECK(std::string(proc->path) == pattern);
    CHECK(proc->isrunning);
    CHECK(proc->hash != nullptr);

    ziti_posture_checks_free(ztx.posture_checks);
    model_map_clear(&ztx.services, (_free_f) free_ziti_service_ptr);
}

TEST_CASE("a wildcard matching no running process reports not-running with no hash or signers", "[posture]") {
    uv_loop_t *loop = process_check_loop();

    ziti_ctx ztx{};
    ziti_api_session session{};
    ztx.loop = loop;
    ztx.auth_state = ZitiAuthStateFullyAuthenticated;
    session.id = "session-1";
    ztx.session = &session;

    const std::string pattern = "/definitely/not/a/real/path/xyz-nonexistent-123/*";
    std::string json = process_service_json(pattern);
    ziti_service *service = nullptr;
    REQUIRE(parse_ziti_service_ptr(&service, json.c_str(), json.size()) > 0);
    model_map_set(&ztx.services, service->name, service);

    ziti_posture_init(&ztx, 60);
    ziti_send_posture_data(&ztx);
    REQUIRE(uv_run(loop, UV_RUN_DEFAULT) == 0);

    model_list send_prs = {};
    ztx_collect_posture(&ztx, &send_prs, true);
    pb_holder holder;
    holder.resp = ztx_posture_resp_pb(&ztx, &send_prs);
    model_list_clear(&send_prs, nullptr);

    REQUIRE(holder.resp != nullptr);
    REQUIRE(holder.resp->n_responses == 1);
    const Ziti__EdgeClient__Pb__PostureResponse *r = holder.resp->responses[0];
    REQUIRE(r->type_case == ZITI__EDGE_CLIENT__PB__POSTURE_RESPONSE__TYPE_PROCESS_LIST);
    REQUIRE(r->processlist->n_processes == 1);
    const Ziti__EdgeClient__Pb__PostureResponse__Process *proc = r->processlist->processes[0];
    CHECK(std::string(proc->path) == pattern);
    CHECK_FALSE(proc->isrunning);
    CHECK(proc->hash == nullptr);
    CHECK(proc->n_signerfingerprints == 0);

    ziti_posture_checks_free(ztx.posture_checks);
    model_map_clear(&ztx.services, (_free_f) free_ziti_service_ptr);
}
