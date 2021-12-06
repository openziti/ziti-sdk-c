/*
Copyright (c) 2021 NetFoundry Inc.

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

#ifndef ZITI_SDK_ZITI_BUFFER_H
#define ZITI_SDK_ZITI_BUFFER_H

#include <stdint.h>
#include "externs.h"
#include "ziti_log.h"

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

typedef struct write_buf_s write_buf_t;

ZITI_FUNC write_buf_t* new_write_buf();
ZITI_FUNC write_buf_t* new_fixed_write_buf(char *outbuf, size_t max);
ZITI_FUNC void delete_write_buf(write_buf_t *wb);

ZITI_FUNC int write_buf_append(write_buf_t *wb, const char *str);
ZITI_FUNC int write_buf_append_byte(write_buf_t *wb, char c);
ZITI_FUNC int write_buf_fmt(write_buf_t *wb, FORMAT_STRING(const char *fmt), ...) ziti_printf_args(2,3);
ZITI_FUNC size_t write_buf_size(write_buf_t *wb);
ZITI_FUNC char *write_buf_to_string(write_buf_t *wb, size_t *outlen);


#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_ZITI_BUFFER_H
