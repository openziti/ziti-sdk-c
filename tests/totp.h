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

// Minimal TOTP (RFC 6238) generator for tests.

#ifndef ZITI_SDK_TEST_TOTP_H
#define ZITI_SDK_TEST_TOTP_H

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace totp {

// RFC 4648 base32 decoding: case-insensitive, '=' padding and whitespace are ignored.
inline std::vector<uint8_t> base32_decode(std::string_view in) {
    std::vector<uint8_t> out;
    uint32_t buf = 0;
    int bits = 0;
    for (char c: in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else if (c == '=' || c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        else throw std::invalid_argument("invalid base32 character");

        buf = (buf << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((buf >> bits) & 0xff);
        }
    }
    return out;
}

// HOTP value (RFC 4226) for the given counter, using HMAC-SHA1.
inline uint32_t hotp(const std::vector<uint8_t> &key, uint64_t counter, int digits = 6) {
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = counter & 0xff;
        counter >>= 8;
    }

    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), msg, sizeof(msg), mac, &mac_len) == nullptr) {
        throw std::runtime_error("HMAC failed");
    }

    // dynamic truncation
    int off = mac[mac_len - 1] & 0x0f;
    uint32_t bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];

    uint32_t mod = 1;
    for (int i = 0; i < digits; i++) mod *= 10;
    return bin % mod;
}

// TOTP value (RFC 6238) at the given time.
inline uint32_t generate(const std::vector<uint8_t> &key,
                         std::chrono::system_clock::time_point t = std::chrono::system_clock::now(),
                         int digits = 6, int period_sec = 30) {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return hotp(key, static_cast<uint64_t>(secs) / period_sec, digits);
}

} // namespace totp

#endif // ZITI_SDK_TEST_TOTP_H
