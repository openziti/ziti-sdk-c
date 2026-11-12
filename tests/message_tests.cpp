// Copyright (c) 2023.  NetFoundry Inc.
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

#include "catch2_includes.hpp"
#include <catch2/generators/catch_generators.hpp>

#include <cstdlib>
#include <cstring>
#include "message.h"
#include "edge_protocol.h"
#include "ziti/errors.h"

// Regression for SIGBUS on armeabi-v7a inside parse_hdrs (library/message.c).
// Wire format per header: id(4 LE) || length(4 LE) || value(length bytes).
// A header with length=1 advances the cursor by 9, leaving the next header's
// id at a 4-byte-misaligned address. read_int32 used to do `*(uint32_t*)p`
// from a uint8_t*, which is UB and faults on ARMv7 strict-alignment cores.
// With -fsanitize=alignment this trips even on x86_64 / arm64-macOS.
TEST_CASE("parse_hdrs handles misaligned subsequent headers", "[model][alignment]") {
    alignas(uint32_t) uint8_t buf[] = {
        // header[0]: id=1, length=1, value=[0x42]  -> consumes 9 bytes
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x42,
        // header[1]: id=2, length=4, value=[0xDE,0xAD,0xBE,0xEF]
        // starts at offset 9 - deliberately not 4-byte aligned.
        0x02, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF,
    };
    constexpr uint32_t buf_len = sizeof(buf);

    hdr_t *hdrs = nullptr;
    int n = parse_hdrs(buf, buf_len, &hdrs);

    REQUIRE(n == 2);
    REQUIRE(hdrs != nullptr);

    CHECK(hdrs[0].header_id == 1);
    CHECK(hdrs[0].length == 1);
    CHECK(hdrs[0].value[0] == 0x42);

    CHECK(hdrs[1].header_id == 2);
    CHECK(hdrs[1].length == 4);
    CHECK(hdrs[1].value[0] == 0xDE);
    CHECK(hdrs[1].value[1] == 0xAD);
    CHECK(hdrs[1].value[2] == 0xBE);
    CHECK(hdrs[1].value[3] == 0xEF);

    free(hdrs);
}

// A header length larger than what is left of the headers is an error. The parser added it to its read
// position before looking: past the end on 64-bit builds (caught afterwards), and on 32-bit builds a length
// near 2^32 wraps the position back below the end, so parsing carried on out of bounds.
TEST_CASE("parse_hdrs rejects a header longer than the headers", "[model]") {
    alignas(uint32_t) uint8_t buf[] = {
        // header[0]: id=1, length=0xFFFFFFF0, then 4 bytes of value
        0x01, 0x00, 0x00, 0x00,
        0xF0, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00,
    };

    hdr_t *hdrs = nullptr;
    CHECK(parse_hdrs(buf, sizeof(buf), &hdrs) == ZITI_INVALID_STATE);
    CHECK(hdrs == nullptr);
}

TEST_CASE("simple", "[model]") {
    auto p = pool_new(sizeof(message) + 200, 3, (void (*)(void *)) message_free);

    hdr_t headers[] = {
            {
                    .header_id = 1,
                    .length = 3,
                    .value = (uint8_t *) "foo"
            },
            {
                    .header_id = 2,
                    .length = 3,
                    .value = (uint8_t *) "bar"
            },
            {
                .header_id = 3,
                .length = 0,
                .value = nullptr,
            }
    };
    auto content1 = "this is a message";
    uint32_t s1 = 3333;
    auto m1 = message_new(p, ContentTypeData, headers, sizeof(headers)/sizeof(headers[0]), strlen(content1));
    strncpy(reinterpret_cast<char *>(m1->body), content1, strlen(content1));
    message_set_seq(m1, &s1);

    message *m2;
    REQUIRE(message_new_from_header(p, m1->msgbufp, &m2) == ZITI_OK);
    CHECK(m2->header.seq == 3334);
    CHECK(m2->msgbuflen == m1->msgbuflen);
    memcpy(m2->msgbufp, m1->msgbufp, m1->msgbuflen);
    hdr_t *tmp;
    CHECK(parse_hdrs(m2->headers, m2->header.headers_len - 1, &tmp) == ZITI_INVALID_STATE);
    CHECK(parse_hdrs(m2->headers, m2->header.headers_len + 1, &tmp) == ZITI_INVALID_STATE);
    m2->nhdrs = parse_hdrs(m2->headers, m2->header.headers_len, &m2->hdrs);
    CHECK(m2->nhdrs == 3);

    const uint8_t *hdrval;
    size_t hdrlen;
    CHECK(message_get_bytes_header(m2, 1, &hdrval, &hdrlen));
    CHECK(strncmp((const char *) headers[0].value, (const char *) hdrval, hdrlen) == 0);

    CHECK(message_get_bytes_header(m2, 2, &hdrval, &hdrlen));
    CHECK(strncmp((const char *) headers[1].value, (const char *) hdrval, hdrlen) == 0);
    CHECK(strncmp(content1, (const char *) m2->body, m2->header.body_len) == 0);

    CHECK(message_get_bytes_header(m2, 3, &hdrval, &hdrlen));
    CHECK(hdrlen == 0);

    pool_return_obj(m1);
    pool_return_obj(m2);

    pool_destroy(p);
}

TEST_CASE("large", "[model]") {
    auto p = pool_new(sizeof(message) + 20, 3, (void (*)(void *)) message_free);

    hdr_t headers[] = {
            {
                    .header_id = 1,
                    .length = 3,
                    .value = (uint8_t *) "foo"
            },
            {
                    .header_id = 2,
                    .length = 3,
                    .value = (uint8_t *) "bar"
            },
    };
    uint32_t seq = 3333;
    auto content1 = "this is a very long message, it won't fint into the pooled message structure";
    auto m1 = message_new(p, ContentTypeData, headers, 2, strlen(content1));
    strncpy(reinterpret_cast<char *>(m1->body), content1, strlen(content1));
    message_set_seq(m1, &seq);


    message *m2;
    REQUIRE(message_new_from_header(p, m1->msgbufp, &m2) == ZITI_OK);
    CHECK(m2->header.seq == 3334);
    CHECK(seq == 3334);
    CHECK(m2->msgbuflen == m1->msgbuflen);
    memcpy(m2->msgbufp, m1->msgbufp, m1->msgbuflen);
    m2->nhdrs = parse_hdrs(m2->headers, m2->header.headers_len, &m2->hdrs);
    CHECK(m2->nhdrs == 2);

    const uint8_t *hdrval;
    size_t hdrlen;
    CHECK(message_get_bytes_header(m2, 1, &hdrval, &hdrlen));
    CHECK(strncmp((const char *) headers[0].value, (const char *) hdrval, hdrlen) == 0);

    CHECK(message_get_bytes_header(m2, 2, &hdrval, &hdrlen));
    CHECK(strncmp((const char *) headers[1].value, (const char *) hdrval, hdrlen) == 0);

    pool_return_obj(m1);
    pool_return_obj(m2);

    pool_destroy(p);
}

TEST_CASE("large unpooled", "[model]") {
    auto p = pool_new(sizeof(message) + 20, 3, (void (*)(void *)) message_free);

    hdr_t headers[] = {
            {
                    .header_id = 1,
                    .length = 3,
                    .value = (uint8_t *) "foo"
            },
            {
                    .header_id = 2,
                    .length = 3,
                    .value = (uint8_t *) "bar"
            },
    };
    uint32_t seq = 3333;
    auto content1 = "this is a very long message, it won't fint into the pooled message structure";
    auto m1 = message_new(p, ContentTypeData, headers, 2, strlen(content1));
    strncpy(reinterpret_cast<char *>(m1->body), content1, strlen(content1));
    message_set_seq(m1, &seq);

    message *m2;
    REQUIRE(message_new_from_header(nullptr, m1->msgbufp, &m2) == ZITI_OK);
    CHECK(m2->header.seq == 3334);
    CHECK(seq == 3334);
    CHECK(m2->msgbuflen == m1->msgbuflen);
    memcpy(m2->msgbufp, m1->msgbufp, m1->msgbuflen);
    m2->nhdrs = parse_hdrs(m2->headers, m2->header.headers_len, &m2->hdrs);
    CHECK(m2->nhdrs == 2);

    const uint8_t *hdrval;
    size_t hdrlen;
    CHECK(message_get_bytes_header(m2, 1, &hdrval, &hdrlen));
    CHECK(strncmp((const char *) headers[0].value, (const char *) hdrval, hdrlen) == 0);

    CHECK(message_get_bytes_header(m2, 2, &hdrval, &hdrlen));
    CHECK(strncmp((const char *) headers[1].value, (const char *) hdrval, hdrlen) == 0);

    pool_return_obj(m1);
    pool_return_obj(m2);

    pool_destroy(p);
}
// The lengths in an inbound header come from the peer. They were summed in 32 bits, so a header whose
// headers_len + body_len came close to 2^32 got a buffer of a few bytes, and the channel then copied the
// whole declared length into it.
TEST_CASE("inbound header with an oversized data section is rejected", "[model]") {
    auto lens = GENERATE(
            std::pair<uint32_t, uint32_t>{0xFFFFFFECu, 0},           // + HEADER_SIZE wraps to 0
            std::pair<uint32_t, uint32_t>{0xFFFFFFF0u, 0xFu},        // wraps to 19
            std::pair<uint32_t, uint32_t>{0xFFFFFFFFu, 0xFFFFFFFFu}, // the sum of the two wraps too
            std::pair<uint32_t, uint32_t>{0x80000000u, 0});          // over INT32_MAX without a wrap

    auto p = pool_new(sizeof(message) + 200, 3, (void (*)(void *)) message_free);
    header_t h = EMPTY_HEADER;
    h.content = ContentTypeData;
    h.headers_len = lens.first;
    h.body_len = lens.second;
    uint8_t buf[HEADER_SIZE];
    header_to_buffer(&h, buf);

    message *m = nullptr;
    CHECK(message_new_from_header(p, buf, &m) != ZITI_OK);
    CHECK(m == nullptr);

    if (m) pool_return_obj(m);
    pool_destroy(p);
}

// A header with no value is legal on the wire. The bool getter read value[0] regardless, which is the first
// byte after the header: the body, or one byte past the buffer when there is none.
TEST_CASE("a bool header without a value reads as false", "[model]") {
    hdr_t headers[] = {
            {
                    .header_id = 1,
                    .length = 0,
                    .value = nullptr,
            },
    };
    constexpr size_t body_len = 4;
    message *m = message_new(nullptr, ContentTypeData, headers, 1, body_len);
    REQUIRE(m != nullptr);
    memset(m->body, 0x01, body_len); // what the unchecked read lands on
    m->nhdrs = parse_hdrs(m->headers, m->header.headers_len, &m->hdrs);
    REQUIRE(m->nhdrs == 1);

    bool v = true;
    CHECK(message_get_bool_header(m, 1, &v));
    CHECK_FALSE(v);

    pool_return_obj(m);
}
