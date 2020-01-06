/*
Copyright 2019-2020 Netfoundry, Inc.

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

#include "message.h"
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "endian_internal.h"

static uint8_t *read_int32(const uint8_t *p, uint32_t *val) {
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
    FREE(m->headers);
    FREE(m->hdrs);
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
    uint8_t *p = buf;

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
    if (h != NULL) {
        int32_t val = *(int32_t *) h->value;
        *v = le32toh(val);
        return true;
    }
    return false;
}
