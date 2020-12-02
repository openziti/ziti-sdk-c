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

#include <stdint.h>
#include <stdlib.h>
#include "utils.h"

#if _WIN32
#include <crtdefs.h>
#else
#include <sys/param.h>
#endif
#include <uv_mbed/queue.h>

#include "buffer.h"


/** incoming data chunk */
typedef struct chunk_s {
    uint8_t *buf;
    int len;

    STAILQ_ENTRY(chunk_s) next;
} chunk_t;

struct buffer_s {
    STAILQ_HEAD(incoming, chunk_s) chunks;
    int head_offset;
    size_t available;
};


buffer *new_buffer() {
    buffer *b = malloc(sizeof(buffer));
    b->head_offset = 0;
    b->available = 0;
    STAILQ_INIT(&b->chunks);

    return b;
}

void free_buffer(buffer* b) {
    while (!STAILQ_EMPTY(&b->chunks)) {
        chunk_t *chunk = STAILQ_FIRST(&b->chunks);
        STAILQ_REMOVE_HEAD(&b->chunks, next);
        free(chunk->buf);
        free(chunk);
    }
    free(b);
}

void buffer_cleanup(buffer *b) {

    if (STAILQ_EMPTY(&b->chunks)) {
        return;
    }

    chunk_t *chunk = STAILQ_FIRST(&b->chunks);
    if (chunk->len == b->head_offset) {
        STAILQ_REMOVE_HEAD(&b->chunks, next);
        b->head_offset = 0;
        free(chunk->buf);
        free(chunk);
    }
}

void buffer_push_back(buffer* b, size_t count) {
    b->available += count;
    b->head_offset -= count;
}

ssize_t buffer_get_next(buffer* b, size_t want, uint8_t** ptr) {
    if (STAILQ_EMPTY(&b->chunks)) {
        return -1;
    }

    chunk_t *chunk = STAILQ_FIRST(&b->chunks);
    if (chunk->len == b->head_offset) {
        STAILQ_REMOVE_HEAD(&b->chunks, next);
        b->head_offset = 0;
        free(chunk->buf);
        free(chunk);

        if (STAILQ_EMPTY(&b->chunks)) {
            return -1;
        }

        chunk = STAILQ_FIRST(&b->chunks);
    }
    int len = MIN(chunk->len - b->head_offset, want);
    *ptr = chunk->buf + b->head_offset;
    b->head_offset += len;
    b->available -= len;

    return len;
}

void buffer_append(buffer* b, uint8_t *buf, size_t len) {
    chunk_t *e = malloc(sizeof(chunk_t));
    e->buf = buf;
    e->len = len;
    b->available += len;

    STAILQ_INSERT_TAIL(&b->chunks, e, next);
}

size_t buffer_available(buffer* b) {
    return b->available;
}