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

#ifndef ZITI_TESTS_TLS_WIRE_H
#define ZITI_TESTS_TLS_WIRE_H

#include <cstdint>
#include <cstddef>
#include <vector>

namespace tls_wire {

struct server_hello_info {
    uint16_t version = 0;       // negotiated protocol: supported_versions if present, else legacy_version
    uint16_t cipher_suite = 0;
    uint16_t key_share_group = 0;
    bool extended_master_secret = false;
};

// reads the negotiated version, cipher suite and TLS 1.3 key-share group straight off the wire, so the
// result does not depend on what the TLS engine chooses to report
inline bool parse_server_hello(const std::vector<uint8_t> &b, server_hello_info &out) {
    auto u16 = [&](size_t off) { return (uint16_t)((b[off] << 8) | b[off + 1]); };
    // record header (5) + handshake header (4) + legacy_version (2) + random (32) + session id length (1)
    if (b.size() < 44 || b[0] != 0x16 || b[5] != 0x02) return false;
    size_t p = 9;
    out.version = u16(p);
    p += 2 + 32;
    p += 1 + b[p];
    if (p + 5 > b.size()) return false;
    out.cipher_suite = u16(p);
    p += 2 + 1;
    size_t ext_end = p + 2 + u16(p);
    p += 2;
    while (p + 4 <= ext_end && ext_end <= b.size()) {
        uint16_t type = u16(p);
        uint16_t len = u16(p + 2);
        p += 4;
        if (type == 0x002b && len == 2) out.version = u16(p);
        if (type == 0x0033 && len >= 2) out.key_share_group = u16(p);
        if (type == 0x0017) out.extended_master_secret = true;
        p += len;
    }
    return true;
}

// the TLS 1.3 key exchange groups FIPS 140-3 approves: the NIST curves
inline bool is_nist_group(uint16_t g) {
    return g == 0x0017 || g == 0x0018 || g == 0x0019;
}

inline const char *tls_version_name(uint16_t v) {
    switch (v) {
        case 0x0303: return "TLSv1.2";
        case 0x0304: return "TLSv1.3";
        default: return "other";
    }
}

inline const char *cipher_suite_name(uint16_t cs) {
    switch (cs) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xC02F: return "ECDHE-RSA-AES128-GCM-SHA256";
        case 0xC030: return "ECDHE-RSA-AES256-GCM-SHA384";
        case 0xCCA8: return "ECDHE-RSA-CHACHA20-POLY1305";
        default: return "other";
    }
}

inline const char *group_name(uint16_t g) {
    switch (g) {
        case 0x0000: return "(none)";
        case 0x0017: return "secp256r1";
        case 0x0018: return "secp384r1";
        case 0x0019: return "secp521r1";
        case 0x001d: return "x25519";
        case 0x001e: return "x448";
        case 0x0100: return "ffdhe2048";
        default: return "other";
    }
}

} // namespace tls_wire

#endif // ZITI_TESTS_TLS_WIRE_H
