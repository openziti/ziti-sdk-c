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

#ifndef ZITI_TLS_UTILS_H
#define ZITI_TLS_UTILS_H

#include <stdio.h>
#include <string.h>
#include <uv.h>
#include <http_parser.h>
#include <stdlib.h>
#include <uv_mbed/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const char *ziti_get_version(int verbose);
extern const char *ziti_git_branch();
extern const char *ziti_git_commit();
extern void hexDump(char *desc, void *addr, int len);


int lt_zero(int v);
int non_zero(int v);

typedef const char *(*fmt_error_t)(int);
typedef int *(*cond_error_t)(int);

#define NEWP(var, type) type *var = calloc(1, sizeof(type))
#define VAL_OR_ELSE(v, def) ((v) != NULL ? (v) : (def))
#define FREE(v) if ((v) != NULL) { free(v); (v) = NULL; }

#define __FILENAME__ (&__FILE__[SOURCE_PATH_SIZE])


char *fmt_mbederr(int err);

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
        ZITI_LOG(ERROR, "%s:%d - %s => %d(%s)", ERFILE(ex), ERLINE(ex), _##ex##_op, ERR(ex), FMT(ex)(ERR(ex)));\
    }}\
    for (int _##ex##_count = 0;COND(ex)(ERR(ex)) && _##ex##_count == 0; _##ex##_count++)


#define FOR(idx, arr) for (int (idx) = 0; (idx) < SIZEOF(arr) && (arr)[(idx)] != NULL; (idx)++)

extern void init_debug();

extern int ziti_debug_level;
extern FILE *ziti_debug_out;


// for windows compilation NOGDI needs to be set:
// right click ziti -> properties -> C/C++ -> Preprocessor - ensure NOGDI is in the list of preprocessor definitions
// if it's not present check the CMakeLists.txt file
#define DEBUG_LEVELS(XX) \
    XX(NONE) \
    XX(ERROR) /*WINDOWS - see comment above wrt NOGDI*/ \
    XX(WARN) \
    XX(INFO) \
    XX(DEBUG) \
    XX(VERBOSE) \
    XX(TRACE)


enum DebugLevel {
#define _level(n) n,
    DEBUG_LEVELS(_level)
#undef _level
};

#define container_of(ptr, type, member) ((type *) ((ptr) - offsetof(type, member)))


#define ZITI_LOG(level, fmt, ...) do { \
if (level <= ziti_debug_level) {\
    long elapsed = get_elapsed();\
    fprintf(ziti_debug_out, "[%9ld.%03ld] " #level "\t%s:%d %s(): " fmt "\n",\
        elapsed/1000, elapsed%1000, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__);\
        }\
} while(0)

long get_elapsed();

void ziti_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

int get_url_data(const char *url, struct http_parser_url *parser, int uf, char *out, size_t maxout);

#ifdef __cplusplus
}
#endif

#endif //ZITI_TLS_UTILS_H
