//
// Created by eugene on 3/22/19.
//

#ifndef ZITI_SDK_MESSAGE_H
#define ZITI_SDK_MESSAGE_H

#include <stdint.h>
#include <stdbool.h>

#define HEADER_SIZE 20

#define MAGIC_INIT {0x3, 0x6, 0x9, 0xC}

typedef char magic_t[4];

#define HEADER_FIELDS(XX) \
XX(content, uint32_t)\
XX(seq, int32_t)\
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

typedef struct {
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

uint8_t *write_hdr(const hdr_t *h, uint8_t *buf);

int parse_hdrs(uint8_t *buf, uint32_t len, hdr_t **hp);

#endif //ZITI_SDK_MESSAGE_H
