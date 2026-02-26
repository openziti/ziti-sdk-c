// Copyright (c) 2023-2026.  NetFoundry Inc
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.

#ifndef ZITI_SDK_MESSAGE_H
#define ZITI_SDK_MESSAGE_H

#include "pool.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <tlsuv/queue.h>

#define HEADER_SIZE 20

#define MAGIC_INIT {0x3, 0x6, 0x9, 0xC}

typedef union {
    char magic[4];
    int32_t magint;
} magic_t;

#define HEADER_FIELDS(XX) \
XX(content, uint32_t)\
XX(seq, uint32_t)\
XX(headers_len, uint32_t)\
XX(body_len, uint32_t)

typedef struct {
    magic_t magic;
#define field_decl(n, t) t n;

    HEADER_FIELDS(field_decl)

#undef field_decl

} header_t;

static header_t EMPTY_HEADER = {
        MAGIC_INIT,
};

typedef struct hdr_s {
    uint32_t header_id;
    uint32_t length;
    const uint8_t *value;
} hdr_t;

#define var_header(id, var) header(id, sizeof(var), &(var))
#define header(id, l, v) (hdr_t){ .header_id = (uint32_t)(id), .length = (uint32_t)(l), .value = (uint8_t*)(v)}

typedef struct message_s {
    TAILQ_ENTRY(message_s) _next;

    header_t header;
    uint8_t *headers;
    uint8_t *body;
    hdr_t *hdrs;
    int nhdrs;

    size_t msgbuflen;
    uint8_t *msgbufp;
    uint8_t msgbuf[];
} message;

#ifdef __cplusplus
extern "C" {
#endif


void header_init(header_t *h, uint32_t seq);

void header_to_buffer(header_t *h, uint8_t *buf);

void header_from_buffer(header_t *h, uint8_t *buf);

void message_init(message *m);

void message_free(message *m);

bool message_get_bool_header(message *m, int header_id, bool *v);

bool message_get_int32_header(message *m, int header_id, int32_t *v);

bool message_get_uint64_header(message *m, int header_id, uint64_t *v);

bool message_get_bytes_header(message *m, int header_id, const uint8_t **ptr, size_t *len);

uint8_t *write_hdr(const hdr_t *h, uint8_t *buf);

int parse_hdrs(const uint8_t *buf, uint32_t len, hdr_t **hp);

int message_new_from_header(pool_t *pool, uint8_t buf[HEADER_SIZE], message **msg_p);

message *message_new(pool_t *pool, uint32_t content, const hdr_t *headers, int nheaders, size_t body_len);

void message_set_seq(message *m, uint32_t *seq);

message* new_inspect_result(uint32_t req_seq, uint32_t conn_id, uint8_t type, const char *msg, size_t msglen);

#ifdef __cplusplus
};
#endif

#endif //ZITI_SDK_MESSAGE_H
