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

#ifndef ZITI_SDK_BUFFER_H
#define ZITI_SDK_BUFFER_H

#include <stdint.h>

#if !defined(__DEFINED_ssize_t) && !defined(__ssize_t_defined)
#if _WIN32
typedef intptr_t ssize_t;
#define __DEFINED_ssize_t
#define __ssize_t_defined
#else
#include <unistd.h>
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct buffer_s buffer;

buffer *new_buffer();
void free_buffer(buffer *);

void buffer_cleanup(buffer *);
ssize_t buffer_get_next(buffer *, size_t want, uint8_t **ptr);
void buffer_push_back(buffer *, size_t);
void buffer_append(buffer *, uint8_t *buf, size_t len);
size_t buffer_available(buffer *);


struct write_buf_s {
    buffer *buf;
    bool fixed;
    size_t chunk_size;
    uint8_t *chunk;
    uint8_t *wp;
};
typedef struct write_buf_s write_buf_t;

void write_buf_init(write_buf_t *wb);
void write_buf_init_fixed(write_buf_t *wb, char *outbuf, size_t max);
int write_buf_append(write_buf_t *wb, const char *str);
int write_buf_append_byte(write_buf_t *wb, char c);
size_t write_buf_size(write_buf_t *wb);
char *write_buf_to_string(write_buf_t *wb, size_t *outlen);
void write_buf_free(write_buf_t *wb);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_BUFFER_H
