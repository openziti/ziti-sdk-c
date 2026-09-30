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

#include "totp.h"

TEST_CASE("base32_decode", "[totp]") {
    using totp::base32_decode;

    // RFC 4648 test vectors
    CHECK(base32_decode("").empty());
    CHECK(base32_decode("MY======") == std::vector<uint8_t>{'f'});
    CHECK(base32_decode("MZXQ====") == std::vector<uint8_t>{'f', 'o'});
    CHECK(base32_decode("MZXW6===") == std::vector<uint8_t>{'f', 'o', 'o'});
    CHECK(base32_decode("MZXW6YQ=") == std::vector<uint8_t>{'f', 'o', 'o', 'b'});
    CHECK(base32_decode("MZXW6YTB") == std::vector<uint8_t>{'f', 'o', 'o', 'b', 'a'});
    CHECK(base32_decode("MZXW6YTBOI======") == std::vector<uint8_t>{'f', 'o', 'o', 'b', 'a', 'r'});

    SECTION("lowercase and unpadded") {
        CHECK(base32_decode("mzxw6ytboi") == std::vector<uint8_t>{'f', 'o', 'o', 'b', 'a', 'r'});
    }

    SECTION("invalid characters") {
        CHECK_THROWS_AS(base32_decode("MZXW1"), std::invalid_argument);
        CHECK_THROWS_AS(base32_decode("MZ!W"), std::invalid_argument);
    }
}

TEST_CASE("totp RFC 6238 vectors (SHA-1)", "[totp]") {
    const std::string_view ascii = "12345678901234567890";
    std::vector<uint8_t> key(ascii.begin(), ascii.end());

    struct {
        int64_t time;
        uint32_t code8;
    } vectors[] = {
        {59, 94287082},
        {1111111109, 7081804},
        {1111111111, 14050471},
        {1234567890, 89005924},
        {2000000000, 69279037},
        {20000000000, 65353130},
    };

    for (auto &v: vectors) {
        auto t = std::chrono::system_clock::time_point{std::chrono::seconds{v.time}};
        INFO("time = " << v.time);
        CHECK(totp::generate(key, t, 8) == v.code8);
        CHECK(totp::generate(key, t, 6) == v.code8 % 1000000);
    }
}

TEST_CASE("totp from base32 secret", "[totp]") {
    // base32 of "12345678901234567890"
    auto key = totp::base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    auto t = std::chrono::system_clock::time_point{std::chrono::seconds{59}};
    CHECK(totp::generate(key, t) == 287082);
}
