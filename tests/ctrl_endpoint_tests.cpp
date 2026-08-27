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

// ctrl_next_ep() picks the endpoint ziti_ctrl_init() starts on. Its liveness test reads
// uv_now(loop), which on a loop that has not run yet is milliseconds since boot, so the selection
// has to hold for a small clock as well as a large one: a client started by systemd or as a Windows
// service runs within a minute of boot.
//
// Addresses come from the RFC 5737 documentation range so nothing resolves or connects.

#include "catch2_includes.hpp"

#include "ziti_ctrl.h"
#include <ziti/errors.h>
#include <catch2/generators/catch_generators.hpp>
#include <tlsuv/tlsuv.h>
#include <string>
#include <vector>

namespace {
    // One loop for every case here, never run and never closed. Creating and closing a loop per case
    // aborted intermittently on libuv's `fd > STDERR_FILENO` assertion once the whole suite ran in the
    // same process - 2 of 5 runs - while the cases on their own passed 20 of 20. Reusing one loop is
    // stable and costs a single allocation for the life of the process.
    uv_loop_t *test_loop() {
        static uv_loop_t *loop = uv_loop_new();
        return loop;
    }

    // libuv has no setter for the loop's cached time - uv_update_time() only refreshes it from the
    // real clock - so it is assigned directly. Safe in either direction only because these cases never
    // run the loop; uv_run() asserts that the clock never moves backwards.
    void simulate_uptime(uv_loop_t *loop, uint64_t ms) {
        loop->time = ms;
    }

    // 0 means "use the host's own uptime". The loop is shared, so every case sets the time it wants
    // rather than inheriting whatever the previous one left. uv_update_time() is not an option: it
    // asserts the clock never moves backwards, and a previous case may have simulated a larger value.
    void init_and_check_selection(uint64_t uptime_ms, const std::vector<const char *> &endpoints) {
        uv_loop_t *loop = test_loop();
        simulate_uptime(loop, uptime_ms > 0 ? uptime_ms : uv_hrtime() / 1000000);

        tls_context *tls = default_tls_context(nullptr, 0);

        model_list urls = {};
        for (const char *ep: endpoints) {
            model_list_append(&urls, (void *) ep);
        }

        ziti_controller ctrl{};
        REQUIRE(ziti_ctrl_init(loop, &ctrl, &urls, tls) == ZITI_OK);

        const std::string chosen = cstr_str(&ctrl.url);
        bool matched = false;
        for (const char *ep: endpoints) {
            matched = matched || chosen == ep;
        }
        CHECK(matched);

        model_list_clear(&urls, nullptr);
        ziti_ctrl_close(&ctrl);
        tls->free_ctx(tls);
    }
}

TEST_CASE("controller-init-selects-endpoint-within-a-minute-of-boot", "[controller]") {
    // 60s is the last value that fails without the fix and 61s the first that passes: the check is
    // `offline_time + ONE_MINUTE < now`. A week of uptime covers the far side.
    const uint64_t uptime = GENERATE(uint64_t{1}, uint64_t{5 * 1000}, uint64_t{60 * 1000},
                                     uint64_t{61 * 1000}, uint64_t{7 * 24 * 60 * 60 * 1000});

    init_and_check_selection(uptime, {"https://203.0.113.1:1280"});
}

TEST_CASE("controller-init-selects-endpoint-with-the-host-clock", "[controller]") {
    // whatever the machine's real uptime is, rather than a simulated one
    init_and_check_selection(0, {"https://203.0.113.1:1280"});
}

TEST_CASE("controller-init-selects-one-of-several-endpoints", "[controller]") {
    const uint64_t uptime = GENERATE(uint64_t{5 * 1000}, uint64_t{61 * 1000});

    init_and_check_selection(uptime, {"https://203.0.113.1:1280", "https://203.0.113.2:1280",
                                      "https://203.0.113.3:1280"});
}

// The cases above only reach the "never tried" half of the candidate test, since every endpoint is
// freshly allocated when ziti_ctrl_init selects one. These drive the selection directly so the backoff
// arithmetic is under test too.

TEST_CASE("endpoint-backoff-lasts-a-minute-after-a-failure", "[controller]") {
    const uint64_t failed_at = 200 * 1000;

    uv_loop_t *loop = test_loop();
    simulate_uptime(loop, failed_at);

    tls_context *tls = default_tls_context(nullptr, 0);

    model_list urls = {};
    model_list_append(&urls, (void *) "https://203.0.113.1:1280");

    ziti_controller ctrl{};
    REQUIRE(ziti_ctrl_init(loop, &ctrl, &urls, tls) == ZITI_OK);

    // reporting the only endpoint as failed leaves nothing to fall back to
    CHECK(ziti_ctrl_next_ep(&ctrl, "https://203.0.113.1:1280") == nullptr);

    // still cooling down: the test is `offline_time + ONE_MINUTE < now`, so the minute mark is out
    simulate_uptime(loop, failed_at + 60 * 1000);
    CHECK(ziti_ctrl_next_ep(&ctrl, nullptr) == nullptr);

    // a millisecond past the minute it is a candidate again
    simulate_uptime(loop, failed_at + 60 * 1000 + 1);
    const char *revived = ziti_ctrl_next_ep(&ctrl, nullptr);
    REQUIRE(revived != nullptr);
    CHECK(std::string(revived) == "https://203.0.113.1:1280");

    model_list_clear(&urls, nullptr);
    ziti_ctrl_close(&ctrl);
    tls->free_ctx(tls);
}

TEST_CASE("endpoint-selection-skips-the-one-still-cooling-down", "[controller]") {
    // 100001ms is picked so that now % (number of endpoints) lands past the end of the candidate list,
    // which is what the selection used to index by.
    const uint64_t failed_at = 100 * 1000;
    const uint64_t now = 100001;

    uv_loop_t *loop = test_loop();
    simulate_uptime(loop, failed_at);

    tls_context *tls = default_tls_context(nullptr, 0);

    model_list urls = {};
    model_list_append(&urls, (void *) "https://203.0.113.1:1280");
    model_list_append(&urls, (void *) "https://203.0.113.2:1280");
    model_list_append(&urls, (void *) "https://203.0.113.3:1280");

    ziti_controller ctrl{};
    REQUIRE(ziti_ctrl_init(loop, &ctrl, &urls, tls) == ZITI_OK);

    // one endpoint fails, so two of the three remain candidates
    ziti_ctrl_next_ep(&ctrl, "https://203.0.113.1:1280");
    REQUIRE(now % model_map_size(&ctrl.endpoints) == 2);

    simulate_uptime(loop, now);
    const char *chosen = ziti_ctrl_next_ep(&ctrl, nullptr);
    REQUIRE(chosen != nullptr);
    CHECK(std::string(chosen) != "https://203.0.113.1:1280");

    model_list_clear(&urls, nullptr);
    ziti_ctrl_close(&ctrl);
    tls->free_ctx(tls);
}

TEST_CASE("controller-init-rejects-empty-endpoint-list", "[controller]") {
    uv_loop_t *loop = test_loop();
    simulate_uptime(loop, 5 * 1000);

    tls_context *tls = default_tls_context(nullptr, 0);

    model_list urls = {};
    ziti_controller ctrl{};

    // no endpoint to select leaves the url unset, so init has to fail instead of handing that on
    CHECK(ziti_ctrl_init(loop, &ctrl, &urls, tls) != ZITI_OK);

    ziti_ctrl_close(&ctrl);
    tls->free_ctx(tls);
}
