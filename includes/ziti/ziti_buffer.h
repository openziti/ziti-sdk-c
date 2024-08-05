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

/**
 * Growing string buffer.
 *
 * string_buf allocates memory internally as needed unless it was created with [new_fixed_string_buf()]
 */
typedef struct string_buf_s string_buf_t;

/**
 * Create new string buffer.
 * @return new buffer instance
 */
ZITI_FUNC string_buf_t *new_string_buf();

/**
 * Create buffer using passed in memory for output. No new memory will be allocated.
 * @param outbuf
 * @param max
 * @return new buffer instance
 */
ZITI_FUNC string_buf_t *new_fixed_string_buf(char *outbuf, size_t max);

/**
 * Deallocate all memory associated with the given string buffer.
 *
 * The passed in pointer is not valid after the function invocation.
 * @param wb
 */
ZITI_FUNC void delete_string_buf(string_buf_t *wb);

/**
 * Append `\0` terminated string to the buffer.
 * @param wb string buffer
 * @param str string
 * @return 0 on success, -1 if `wb` is a fixed buffer and appending would go over its limit.
 */
ZITI_FUNC int string_buf_append(string_buf_t *wb, const char *str);

/**
 * @brief Appends [str] to [wb] converting to urlsafe encoding.
 */
 ZITI_FUNC int string_buf_append_urlsafe(string_buf_t *wb, const char *str);

/**
 * Append `len` bytes from `str` to the string buffer.
 * @param wb string buffer
 * @param str string
 * @param len number of bytes to append
 * @return 0 on success, -1 if `wb` is a fixed buffer and appending would go over its limit.
 */
ZITI_FUNC int string_buf_appendn(string_buf_t *wb, const char *str, size_t len);

/**
 * Append one byte to the string buffer.
 * @param wb string buffer
 * @param c byte to append
 * @return 0 on success, -1 if `wb` is a fixed buffer and appending would go over its limit.
 */
ZITI_FUNC int string_buf_append_byte(string_buf_t *wb, char c);

/**
 * printf style append operation.
 * @param wb string buffer
 * @param fmt printf-style format string
 * @param ... arguments to the `fmt` argument
 * @return 0 on success, -1 if `wb` is a fixed buffer and appending would go over its limit.
 */
ZITI_FUNC int string_buf_fmt(string_buf_t *wb, FORMAT_STRING(const char *fmt), ...) ziti_printf_args(2, 3);

/**
 * number of bytes written to the string buffer so far
 * @param wb string buffer
 * @return number of bytes in the buffer
 */
ZITI_FUNC size_t string_buf_size(string_buf_t *wb);

/**
 * Allocate string big enough to hold the contents of the buffer with '\0` at the end
 * and copy contents into the result.
 * String buffer is cleared after operation is complete.
 * @param wb string buffer
 * @param outlen size of the output not including final `\0' terminator
 * @return allocated string filled with buffer content
 */
ZITI_FUNC char *string_buf_to_string(string_buf_t *wb, size_t *outlen);


#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_ZITI_BUFFER_H
