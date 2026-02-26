// Copyright (c) 2022-2026.  NetFoundry Inc
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

#ifndef ZITI_UTILS_H
#define ZITI_UTILS_H

#include <stdio.h>
#include <string.h>
#include <uv.h>
#include <stdlib.h>
#include <tlsuv/http.h>
#include <ziti/ziti_log.h>

#include "ziti/model_collections.h"
#include "ziti/model_support.h"
#ifdef __cplusplus
extern "C" {
#endif

#if _WIN32

#    if !defined(strncasecmp)
#    define strncasecmp _strnicmp
#    endif

#    if !defined(strcasecmp)
#    define strcasecmp _stricmp
#    endif

#    if !defined(MIN)
#    define MIN(a,b) ((a)<(b) ? (a) : (b))
#    endif

#    if !defined(MAX)
#    define MAX(a,b) ((a) > (b) ? (a) : (b))
#    endif

    typedef unsigned int uint;

#endif

#ifndef z_typeof
#if defined(_MSC_VER)
#define z_typeof(x) __typeof__(x)
#else
#define z_typeof(x) typeof(x)
#endif
#endif
extern const char *ziti_get_build_version(int verbose);

extern const char *ziti_git_branch();

extern const char *ziti_git_commit();

extern void hexDump(char *desc, void *addr, int len);

extern const char *jwt_payload(const char *jwt);

void ziti_fmt_time(char *time_str, size_t time_str_len, uv_timeval64_t *tv);

void hexify(const uint8_t *bin, size_t bin_len, char sep, char **buf);

int lt_zero(int v);

typedef const char *(*fmt_error_t)(int);

typedef int *(*cond_error_t)(int);

#if __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#define THREAD_LOCAL __thread
#elif _MSC_VER
#define THREAD_LOCAL __declspec(thread)
#define UNUSED(x) UNUSED_ ## x
#else
#define THREAD_LOCAL
#define UNUSED(x) UNUSED_ ## x
#endif

#define TO_STRING(m) to_string_(m)
#define to_string_(m) #m

#define NEWP(var, type) type *var = calloc(1, sizeof(type))
#define VAL_OR_ELSE(v, def) ((v) != NULL ? (v) : (def))
#define FREE(v)  do { if ((v) != NULL) { free((void*)(v)); (v) = NULL; } } while(0)
#define FIELD_OR_ELSE(obj, field, def) ((obj) ? ((obj)->field) : (def))
#define FIELD_OR_NULL(obj, field) FIELD_OR_ELSE(obj, field, (z_typeof((obj)->field))0)

#define FMT(ex) _##ex##_fmt
#define COND(ex) _##ex##_cond
#define ERR(ex) (_##ex##_error)
#define ERLINE(ex) (_##ex##_line)
#define ERFILE(ex) (_##ex##_file)
#define ERLBL(ex) _##ex##_label

#define PREPCF(ex, cond, fmt) int ERR(ex) = 0, ERLINE(ex) = 0; const char *_##ex##_op = "<unknown>", *ERFILE(ex) = "<unknown>"; \
fmt_error_t FMT(ex) = (fmt_error_t)(fmt); cond_error_t COND(ex) = (cond_error_t)cond

#define PREPF(ex, fmt) PREPCF(ex, lt_zero, fmt)

#define PREP(ex) PREPF(ex, strerror)

#define TRY(ex, op) ERR(ex) = (op); do {\
if (COND(ex)(ERR(ex))) { ERFILE(ex) = __FILENAME__; ERLINE(ex) = __LINE__; _##ex##_op = #op; goto ERLBL(ex);}\
} while(0)

#define CATCH(ex) { ERLBL(ex):\
    if (COND(ex)(ERR(ex))) {\
        ZITI_LOG(ERROR, "%s:%d - %s => %d (%s)", ERFILE(ex), ERLINE(ex), _##ex##_op, ERR(ex), FMT(ex)(ERR(ex)));\
    }}\
    for (int _##ex##_count = 0;COND(ex)(ERR(ex)) && _##ex##_count == 0; _##ex##_count++)

#define line_idx(i, l) i ## l

#define FOR_line(el, arr, LINE) int line_idx(idx,LINE); for ( \
line_idx(idx,LINE) = 0, (el) = (arr) ? (arr)[line_idx(idx,LINE)] : NULL;   \
el != NULL; \
line_idx(idx,LINE)++, (el) = (arr)[line_idx(idx,LINE)]  )

#define FOR(el, arr) FOR_line(el, arr, __LINE__)


#define container_of(ptr, type, member) ((type *) ((char*)(ptr) - offsetof(type, member)))

#define CLOSE_AND_NULL(h) do{ if (h) { \
if (!uv_is_closing((uv_handle_t*)(h))) uv_close((uv_handle_t*)(h), (uv_close_cb)free); \
(h) = NULL;                            \
}}while(0)

#define CALL_CB(cb, ...) if ((cb) != NULL) (cb)(__VA_ARGS__)

/**
 * Split string based on delimiters.
 * strings are appended to the provided list. Caller is responsible to freeing resulting strings -
 * possibly via `model_list_clear(result, free)`
 * @param str
 * @param delim
 * @param result
 * @return number of tokens
 */
extern size_t str_split(const char *str, const char *delim, model_list *result);

int load_key_internal(tls_context *tls, tlsuv_private_key_t *key, const char *keystr);

int gen_p11_key_internal(tls_context *tls, tlsuv_private_key_t *key, const char *keyuri);

int load_file(const char *path, size_t pathlen, char **content, size_t *size);

uint64_t next_backoff(int *count, int max, uint64_t base);

tlsuv_http_req_t* ziti_json_request(
    tlsuv_http_t *clt, const char *method, const char *path,
    void (*cb)(tlsuv_http_resp_t *resp, const char *err, json_object *content, void *ctx),
    void *ctx);

#ifdef __cplusplus
}
#endif

#endif //ZITI_UTILS_H
