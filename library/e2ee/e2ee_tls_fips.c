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

#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <tlsuv/tls_engine.h>

#define TLS_1_2 0x0303
#define TLS_1_3 0x0304
#define GROUP_SECP256R1 0x0017
#define GROUP_SECP521R1 0x0019

#define REC_HANDSHAKE 0x16
#define HS_SERVER_HELLO 2
#define HS_SERVER_KEY_EXCHANGE 12
#define EXT_EXTENDED_MASTER_SECRET 0x0017
#define EXT_SUPPORTED_VERSIONS 0x002b
#define EXT_KEY_SHARE 0x0033
#define CURVE_TYPE_NAMED 3

// RFC 8446 4.1.3: a ServerHello with this random is a HelloRetryRequest
static const uint8_t HRR_RANDOM[32] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

struct server_flight {
    uint16_t version;
    uint16_t suite;
    uint16_t group;
    bool ems;
    bool hrr;
};

bool tls_is_fips(tls_context *tls) {
    return tls != NULL && tls->fips_status(tls, NULL, 0) == TLS_FIPS_ENABLED;
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t) ((p[0] << 8) | p[1]);
}

// Joins the payloads of the handshake records at the start of a flight, since a handshake message
// can span records. Stops at the first other record: TLS 1.3 encrypts everything after the ServerHello.
static uint8_t *flight_handshake_bytes(const uint8_t *b, size_t len, size_t *hs_len) {
    uint8_t *hs = malloc(len > 0 ? len : 1);
    size_t n = 0;
    size_t p = 0;
    while (hs != NULL && p + 5 <= len && b[p] == REC_HANDSHAKE) {
        size_t rec_len = rd16(b + p + 3);
        if (p + 5 + rec_len > len) {
            break;
        }
        memcpy(hs + n, b + p + 5, rec_len);
        n += rec_len;
        p += 5 + rec_len;
    }
    *hs_len = n;
    return hs;
}

static bool parse_server_hello(const uint8_t *m, size_t len, struct server_flight *f) {
    // legacy_version(2) + random(32) + session id length(1)
    if (len < 35) {
        return false;
    }
    f->version = rd16(m);
    f->hrr = memcmp(m + 2, HRR_RANDOM, sizeof(HRR_RANDOM)) == 0;
    size_t p = 2 + 32;
    p += 1 + m[p];
    // cipher suite(2) + compression(1)
    if (p + 3 > len) {
        return false;
    }
    f->suite = rd16(m + p);
    p += 3;
    if (p + 2 > len) {
        return true;
    }
    size_t ext_end = p + 2 + rd16(m + p);
    if (ext_end > len) {
        return false;
    }
    p += 2;
    while (p + 4 <= ext_end) {
        uint16_t type = rd16(m + p);
        uint16_t ext_len = rd16(m + p + 2);
        p += 4;
        if (p + ext_len > ext_end) {
            return false;
        }
        if (type == EXT_SUPPORTED_VERSIONS && ext_len == 2) f->version = rd16(m + p);
        if (type == EXT_KEY_SHARE && ext_len >= 2) f->group = rd16(m + p);
        if (type == EXT_EXTENDED_MASTER_SECRET) f->ems = true;
        p += ext_len;
    }
    return true;
}

static bool fips_tls12_suite(uint16_t suite) {
    switch (suite) {
        case 0xc02b: // ECDHE-ECDSA-AES128-GCM-SHA256
        case 0xc02c: // ECDHE-ECDSA-AES256-GCM-SHA384
        case 0xc02f: // ECDHE-RSA-AES128-GCM-SHA256
        case 0xc030: // ECDHE-RSA-AES256-GCM-SHA384
            return true;
        default:
            return false;
    }
}

// Reads the negotiated version, cipher suite and key exchange group from a server's first flight: the
// ServerHello, and for TLS 1.2 the curve in the ServerKeyExchange. The engines differ in what they report,
// so the wire is the one source both backends share. Neither backend restricts these on its own in FIPS
// mode: the OpenSSL FIPS provider serves X25519, and Schannel's group order starts with it. So with the
// backend in FIPS mode only the choices SP 800-52r2 approves pass: an AES-GCM suite, a NIST curve, and
// for TLS 1.2 ECDHE with the extended master secret.
int tls_e2ee_check_server_flight(bool fips, const uint8_t *b, size_t len) {
    size_t hs_len = 0;
    uint8_t *hs = flight_handshake_bytes(b, len, &hs_len);
    struct server_flight f = {0};
    bool hello = false;
    size_t p = 0;
    while (hs != NULL && p + 4 <= hs_len) {
        uint8_t type = hs[p];
        size_t msg_len = ((size_t)hs[p + 1] << 16) | ((size_t)hs[p + 2] << 8) | hs[p + 3];
        if (p + 4 + msg_len > hs_len) {
            break;
        }
        const uint8_t *m = hs + p + 4;
        if (p == 0) {
            hello = type == HS_SERVER_HELLO && parse_server_hello(m, msg_len, &f);
            if (!hello) {
                break;
            }
        } else if (type == HS_SERVER_KEY_EXCHANGE && msg_len >= 3 && m[0] == CURVE_TYPE_NAMED) {
            f.group = rd16(m + 1);
        }
        p += 4 + msg_len;
    }
    free(hs);

    if (!hello) {
        ZITI_LOG(fips ? ERROR : DEBUG, "tls e2ee: server flight does not start with a ServerHello");
        return fips ? -1 : 0;
    }

    if (f.hrr) {
        // the key share is only a request: the ServerHello that follows the client's second hello decides
        ZITI_LOG(DEBUG, "tls e2ee: HelloRetryRequest for group[0x%04x]", f.group);
        return 1;
    }

    ZITI_LOG(INFO, "tls e2ee negotiated version[0x%04x] suite[0x%04x] group[0x%04x]%s%s",
             f.version, f.suite, f.group, f.version == TLS_1_2 ? (f.ems ? " ems" : " no-ems") : "",
             fips ? " (FIPS mode)" : "");
    if (!fips) {
        return 0;
    }
    if (f.version == TLS_1_3) {
        if (f.suite != 0x1301 && f.suite != 0x1302) {
            ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires an AES-GCM suite, negotiated[0x%04x]", f.suite);
            return -1;
        }
    } else if (f.version == TLS_1_2) {
        if (!fips_tls12_suite(f.suite)) {
            ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires an ECDHE AES-GCM suite, negotiated[0x%04x]", f.suite);
            return -1;
        }
        if (!f.ems) {
            ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires the extended master secret with TLS 1.2");
            return -1;
        }
    } else {
        ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires TLS 1.2 or 1.3, negotiated[0x%04x]", f.version);
        return -1;
    }
    if (f.group < GROUP_SECP256R1 || f.group > GROUP_SECP521R1) {
        ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires a NIST-curve group, negotiated[0x%04x]", f.group);
        return -1;
    }
    return 0;
}
