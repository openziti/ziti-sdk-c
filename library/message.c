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

#include "message.h"
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "endian_internal.h"

static const uint8_t *read_int32(const uint8_t *p, uint32_t *val) {
    *val = le32toh(*(uint32_t *) p);
    return p + sizeof(uint32_t);
}

void header_to_buffer(header_t *h, uint8_t *buf) {
    memcpy(buf, h->magic, sizeof(h->magic));
    uint8_t *offset = buf + sizeof(h->magic);

#define write_field(n,t) {\
    t val = htole32(h->n); \
    memcpy(offset, &val, sizeof(t)); \
    offset += sizeof(t);\
}
    HEADER_FIELDS(write_field)
#undef write_field
};

void header_from_buffer(header_t *h, uint8_t *buf) {
    memcpy(h->magic, buf, sizeof(h->magic));
    uint8_t *offset = buf + sizeof(h->magic);

#define read_field(n,t) {\
    t val; \
    memcpy(&val, offset, sizeof(t)); \
    offset += sizeof(t);\
    h->n = le32toh(val);\
}
    HEADER_FIELDS(read_field)
#undef read_field
};


void header_init(header_t *h, uint32_t seq) {
    memcpy(h, &EMPTY_HEADER, sizeof(header_t));
    h->seq = seq;
}

void message_init(message* m) {
    memset(m, 0, sizeof(message));
}

void message_free(message* m) {
    if (m != NULL) {
        if (m->msgbufp != m->msgbuf) {
            free(m->msgbufp);
        }
        FREE(m->hdrs);
    }
}

uint8_t *write_hdr(const hdr_t *h, uint8_t *buf) {
    uint32_t v = htole32(h->header_id);
    memcpy(buf, &v, sizeof(v));
    buf += sizeof(v);

    v = htole32(h->length);
    memcpy(buf, &v, sizeof(v));
    buf += sizeof(v);

    memcpy(buf, h->value, h->length);
    return buf + h->length;
}

int parse_hdrs(uint8_t *buf, uint32_t len, hdr_t **hp) {
    const uint8_t *p = buf;

    hdr_t *headers = NULL;
    int count = 0;
    while (p < buf + len) {
        if (headers == NULL) {
            headers = malloc(sizeof(hdr_t));
        }
        else {
            headers = realloc(headers, (count + 1) * sizeof(hdr_t));
        }

        p = read_int32(p, &headers[count].header_id);
        p = read_int32(p, &headers[count].length);
        headers[count].value = p;
        p += headers[count].length;
        count++;
    }

    *hp = headers;
    return count;
}

static hdr_t *find_header(message *m, int header_id) {
    for (int i = 0; i < m->nhdrs; i++) {
        if (m->hdrs[i].header_id == header_id) {
            return &m->hdrs[i];
        }
    }
    return NULL;
}

bool message_get_bool_header(message *m, int header_id, bool *v) {
    hdr_t *h = find_header(m, header_id);
    if (h != NULL) {
        int8_t val = *h->value;
        *v = (val != 0);
        return true;
    }
    return false;
}

bool message_get_int32_header(message *m, int header_id, int32_t *v) {
    hdr_t *h = find_header(m, header_id);
    uint32_t val = 0;
    if (h != NULL) {
        for (unsigned int i = 0; i < h->length && i < 4; i++) {
            val += (h->value[i] << (i * 8));
        }
        *v = val;
        return true;
    }
    return false;
}

bool message_get_uint64_header(message *m, int header_id, uint64_t *v) {
    hdr_t *h = find_header(m, header_id);
    uint64_t val = 0;
    if (h != NULL) {
        for (unsigned int i = 0; i < h->length && i < 8; i++) {
            val += (h->value[i] << (i * 8));
        }
        *v = val;
        return true;
    }
    return false;
}

bool message_get_bytes_header(message *m, int header_id, uint8_t **v, size_t *len) {
    hdr_t *h = find_header(m, header_id);
    if (h != NULL) {
        *len = h->length;
        *v = h->value;
        return true;
    }
    return false;
}

message *message_new_from_header(pool_t *pool, uint8_t buf[HEADER_SIZE]) {
    header_t h;
    header_from_buffer(&h, buf);

    size_t msgbuflen = HEADER_SIZE + h.headers_len + h.body_len;
    message *m = pool ? pool_alloc_obj(pool) : alloc_unpooled_obj(sizeof(message) + msgbuflen,
                                                                  (void (*)(void *)) message_free);

    m->msgbuflen = msgbuflen;

    size_t msgsize = sizeof(message) + msgbuflen;
    if (msgsize > pool_obj_size(m)) {
        m->msgbufp = malloc(msgbuflen);
    }
    else {
        m->msgbufp = m->msgbuf;
    }

    memcpy(&m->header, &h, sizeof(h));
    m->headers = m->msgbufp + HEADER_SIZE;
    m->body = m->headers + h.headers_len;
    return m;
}

message *message_new(pool_t *pool, uint32_t content, const hdr_t *hdrs, int nhdrs, size_t body_len) {
    uint32_t hdrs_len = 0;
    for (int i = 0; i < nhdrs; i++) {
        // wire format length: header id + val(length) + length
        hdrs_len += sizeof(hdrs[i].header_id) + sizeof(hdrs[i].length) + hdrs[i].length;
    }

    size_t msgbuflen = HEADER_SIZE + hdrs_len + body_len;
    size_t msgsize = sizeof(message) + msgbuflen;
    message *m;
    if (pool == NULL) {
        m = alloc_unpooled_obj(msgsize, (void (*)(void *)) message_free);
    }
    else {
        m = pool_alloc_obj(pool);
    }

    memcpy(&m->header, &EMPTY_HEADER, sizeof(EMPTY_HEADER));
    m->header.content = content;
    m->header.headers_len = hdrs_len;
    m->header.body_len = body_len;
    m->msgbuflen = msgbuflen;

    if (msgsize > pool_obj_size(m)) {
        m->msgbufp = malloc(msgbuflen);
    }
    else {
        m->msgbufp = m->msgbuf;
    }

    // write header
    header_to_buffer(&m->header, m->msgbufp);

    // write/populate headers
    m->hdrs = calloc(nhdrs, sizeof(hdr_t));
    m->nhdrs = nhdrs;
    m->headers = m->msgbufp + HEADER_SIZE;
    m->body = m->headers + m->header.headers_len;
    uint8_t *p = m->headers;
    for (int i = 0; i < nhdrs; i++) {
        m->hdrs[i] = (hdr_t){
            .header_id = hdrs[i].header_id,
            .length = hdrs[i].length,
            .value = p + 2 * sizeof(uint32_t),
        };
        p = write_hdr(&hdrs[i], p);
    }

    return m;
}

void message_set_seq(message *m, uint32_t *seq) {
    if (m->header.seq == 0) {
        *seq += 1;
        m->header.seq = *seq;
    }
    header_to_buffer(&m->header, m->msgbufp);
}


message* new_inspect_result(uint32_t req_seq, uint32_t conn_id, connection_type_t type, const char *msg, size_t msglen) {
    const hdr_t hdrs[] = {
            {
                    .header_id = ConnIdHeader,
                    .length = sizeof(conn_id),
                    .value = (uint8_t *) &conn_id,
            },
            {
                    .header_id = ConnTypeHeader,
                    .length = sizeof(type),
                    .value = &type,
            },
            {
                    .header_id = ReplyForHeader,
                    .length = sizeof(req_seq),
                    .value = (uint8_t *) &(req_seq),
            }
    };
    message *reply = message_new(NULL, ContentTypeConnInspectResponse, hdrs, 3, msglen);
    if (msglen > 0) {
        strncpy((char *) reply->body, msg, msglen);
    }
    return reply;
}
