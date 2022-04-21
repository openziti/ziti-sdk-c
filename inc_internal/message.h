/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef ZITI_SDK_MESSAGE_H
#define ZITI_SDK_MESSAGE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <uv_mbed/queue.h>

#define HEADER_SIZE 20

#define MAGIC_INIT {0x3, 0x6, 0x9, 0xC}

typedef char magic_t[4];

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

typedef struct {
    uint32_t header_id;
    uint32_t length;
    uint8_t *value;
} hdr_t;

typedef struct message_s {
    TAILQ_ENTRY(message_s) _next;

    header_t header;
    uint8_t *headers;
    uint8_t *body;
    hdr_t *hdrs;
    int nhdrs;
} message;

void header_init(header_t *h, uint32_t seq);
void header_to_buffer(header_t *h, uint8_t *buf);
void header_from_buffer(header_t *h, uint8_t *buf);
void message_init(message *m);
void message_free(message *m);

bool message_get_bool_header(message *m, int header_id, bool *v);

bool message_get_int32_header(message *m, int header_id, int32_t *v);

bool message_get_uint64_header(message *m, int header_id, uint64_t *v);

bool message_get_bytes_header(message *m, int header_id, uint8_t **ptr, size_t *len);

uint8_t *write_hdr(const hdr_t *h, uint8_t *buf);

int parse_hdrs(uint8_t *buf, uint32_t len, hdr_t **hp);

#endif //ZITI_SDK_MESSAGE_H
