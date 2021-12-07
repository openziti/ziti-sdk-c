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
#include <stdbool.h>
#include <stdarg.h>

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
    if (b == NULL) return;
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

size_t buffer_available(buffer *b) {
    return b ? b->available : 0;
}

#define WRITE_BUF_CHUNK_SIZE 1024

void string_buf_init(string_buf_t *wb) {
    wb->fixed = false;
    wb->chunk_size = WRITE_BUF_CHUNK_SIZE;
    wb->chunk = malloc(wb->chunk_size);
    wb->buf = new_buffer();
    wb->wp = wb->chunk;
}

void string_buf_init_fixed(string_buf_t *wb, char *outbuf, size_t max) {
    wb->fixed = true;
    wb->chunk = (uint8_t *) outbuf;
    wb->wp = wb->chunk;
    wb->chunk_size = max;
    wb->buf = NULL;
}

size_t string_buf_size(string_buf_t *wb) {
    return buffer_available(wb->buf) + (wb->wp - wb->chunk);
}

int string_buf_append_byte(string_buf_t *wb, char c) {
    if (wb->wp - wb->chunk >= wb->chunk_size) {

        if (wb->fixed) { return -1; }

        buffer_append(wb->buf, wb->chunk, wb->wp - wb->chunk);
        wb->chunk = malloc(wb->chunk_size);
        wb->wp = wb->chunk;
    }
    *wb->wp++ = c;
    return 0;
}

int string_buf_appendn(string_buf_t *wb, const char *str, size_t len) {
    const char *s = str;

    size_t chunk_len;
    size_t copy_len;
    copy:
    chunk_len = wb->chunk + wb->chunk_size - wb->wp;
    copy_len = MIN(chunk_len, len);
    memcpy(wb->wp, s, copy_len);
    len -= copy_len;
    wb->wp += copy_len;
    s += copy_len;

    if (len > 0) {
        if (wb->fixed) { return -1; }

        buffer_append(wb->buf, wb->chunk, wb->wp - wb->chunk);
        wb->chunk = malloc(wb->chunk_size);
        wb->wp = wb->chunk;
        goto copy;
    }

    return 0;
}

int string_buf_append(string_buf_t *wb, const char *str) {
    const char *s = str;

    copy:
    while (*s != '\0' && wb->wp < wb->chunk + wb->chunk_size) { *wb->wp++ = *s++; }

    if (*s != 0) {
        if (wb->fixed) { return -1; }

        buffer_append(wb->buf, wb->chunk, wb->wp - wb->chunk);
        wb->chunk = malloc(wb->chunk_size);
        wb->wp = wb->chunk;
        goto copy;
    }

    return 0;
}

char *string_buf_to_string(string_buf_t *wb, size_t *outlen) {
    size_t bytes_in_buffer = buffer_available(wb->buf);
    char *result = malloc(bytes_in_buffer + (wb->wp - wb->chunk) + 1);

    size_t copied = 0;
    while (copied < bytes_in_buffer) {
        uint8_t *copyp;
        size_t copy_len = buffer_get_next(wb->buf, bytes_in_buffer, &copyp);
        memcpy(result + copied, copyp, copy_len);
        copied += copy_len;
    }

    memcpy(result + copied, wb->chunk, wb->wp - wb->chunk);
    result[copied + (wb->wp - wb->chunk)] = 0;
    if (outlen) {
        *outlen = copied + (wb->wp - wb->chunk);
    }
    // after copy buffer contents is empty -- reset current chunk
    wb->wp = wb->chunk;
    
    return result;
}

void string_buf_free(string_buf_t *wb) {
    wb->wp = NULL;
    if (!wb->fixed) FREE(wb->chunk);
    wb->chunk = NULL;
    free_buffer(wb->buf);
    wb->buf = NULL;
}

string_buf_t *new_string_buf() {
    NEWP(wb, string_buf_t);
    string_buf_init(wb);
    return wb;
}

string_buf_t *new_fixed_string_buf(char *outbuf, size_t max) {
    NEWP(wb, string_buf_t);
    string_buf_init_fixed(wb, outbuf, max);
    return wb;
}

void delete_string_buf(string_buf_t *wb) {
    string_buf_free(wb);
    free(wb);
}

int string_buf_fmt(string_buf_t *wb, FORMAT_STRING(const char *fmt), ...) {
    va_list argp;
    va_start(argp, fmt);

    size_t avail_in_chunk = wb->chunk + wb->chunk_size - wb->wp;
    int len = vsnprintf((char *) wb->wp, avail_in_chunk, fmt, argp);
    va_end(argp);

    // fit into current chunk -- nothing else to do
    if (len < avail_in_chunk) {
        wb->wp += len;
        return len;
    }

    // can't allocate any more memory
    if (wb->fixed) return -1;

    // current chunk is not empty push into buffer
    if (wb->chunk != wb->wp) {
        buffer_append(wb->buf, wb->chunk, wb->wp - wb->chunk);
        wb->chunk = malloc(wb->chunk_size);
        wb->wp = wb->chunk;
    }

    va_start(argp, fmt);

    if (len < wb->chunk_size) {
        len = vsnprintf((char*)wb->wp, wb->chunk_size, fmt, argp);
        wb->wp += len;
    } else {
        // formatted string won't fit into chunk_size -- add directly to the buffer
        char *s = malloc(len + 1);
        len = vsnprintf(s, len + 1, fmt, argp);
        buffer_append(wb->buf, (uint8_t *)s, len);
    }
    va_end(argp);
    return len;
}

