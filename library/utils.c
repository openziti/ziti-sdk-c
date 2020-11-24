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

#include <uv.h>
#include <uv_mbed/uv_mbed.h>
#include <ziti/ziti_model.h>
#include <ziti/ziti_log.h>
#include <stdarg.h>

#include "utils.h"

#if _WIN32
#include <time.h>
#endif


#if !defined(ZITI_VERSION)
#define ZITI_VERSION unknown
#endif

#if !defined(ZITI_BUILDNUM)
#define ZITI_BUILDNUM <local>
#endif

#if !defined(ZITI_BRANCH)
#define ZITI_BRANCH "<no-branch>"
#define ZITI_COMMIT "<sha>"
#endif

/*
 * https://sourceforge.net/p/predef/wiki/OperatingSystems/
 */
#if defined(WIN32)
#define ZITI_OS Windows
#elif defined(__ANDROID__)
#define ZITI_OS Android
#elif defined(__linux__)
#define ZITI_OS Linux
#elif defined(__APPLE__)
#define ZITI_OS MacOS
#else
#define ZITI_OS UKNOWN
#endif

/*
 * from https://sourceforge.net/p/predef/wiki/Architectures/
 */
#if defined(__aarch64__)
#define ZITI_ARCH arm64
#elif defined(__arm__)
#define ZITI_ARCH arm
#elif defined(__amd64__)
#define ZITI_ARCH amd64
#elif defined(__i386__)
#define ZITI_ARCH x86
#else
#define ZITI_ARCH UKNOWN
#endif

#define MAX_LOG_LINE (1024 * 2)

const char *ziti_get_build_version(int verbose) {
    if (verbose) {
        return "\n\tVersion:\t" to_str(ZITI_VERSION)
               "\n\tBuild Date:\t" to_str(BUILD_DATE)
               "\n\tGit Branch:\t" to_str(ZITI_BRANCH)
               "\n\tGit SHA:\t" to_str(ZITI_COMMIT)
               "\n\tOS:\t" to_str(ZITI_OS)
               "\n\tArch:\t" to_str(ZITI_ARCH)
               "\n";

    }
    return to_str(ZITI_VERSION) "-" to_str(ZITI_BUILDNUM);
}

const char* ziti_git_branch() {
    return to_str(ZITI_BRANCH);
}

const char* ziti_git_commit() {
    return to_str(ZITI_COMMIT);
}

int ziti_debug_level = INFO;
static FILE *ziti_debug_out;
static bool log_initialized = false;

#if _WIN32
#define strcasecmp _stricmp
#endif

const char *(*get_elapsed)();

static const char *get_elapsed_time();

static const char *get_utc_time();

static void flush_log(uv_prepare_t *p);

static void uv_mbed_logger(const char *level, const char *file, unsigned int line, const char *msg);

static void default_log_writer(const char *level, const char *loc, const char *msg, size_t msglen);

static uv_loop_t *ts_loop;
static uint64_t starttime;
static uint64_t last_update;
static char elapsed_buffer[32];
static uint64_t clock_offset;

static uv_prepare_t log_flusher;
static log_writer logger = default_log_writer;

void ziti_set_log(log_writer log_func, uv_loop_t *loop) {
    init_debug(loop);
    uv_mbed_set_debug(ziti_debug_level, uv_mbed_logger);
    logger = log_func;
}

void init_debug(uv_loop_t *loop) {
    if (log_initialized) {
        return;
    }
    get_elapsed = get_elapsed_time;
    char *ts_format = getenv("ZITI_TIME_FORMAT");
    if (ts_format && strcasecmp("utc", ts_format) == 0) {
        get_elapsed = get_utc_time;
    }
    ts_loop = loop;
    log_initialized = true;
    char *level = getenv("ZITI_LOG");
    if (level != NULL) {
        ziti_debug_level = (int) strtol(level, NULL, 10);
    }
    ziti_debug_out = stderr;
    uv_mbed_set_debug(ziti_debug_level, uv_mbed_logger);

    starttime = uv_now(loop);
    uv_timeval64_t clock;
    uv_gettimeofday(&clock);
    clock_offset = (clock.tv_sec * 1000 + clock.tv_usec / 1000) - starttime; // in millis

    uv_prepare_init(loop, &log_flusher);
    uv_unref((uv_handle_t *) &log_flusher);
    uv_prepare_start(&log_flusher, flush_log);
}

void ziti_logger(const char *level, const char *file, unsigned int line, const char *func, const char *fmt, ...) {
    static size_t loglinelen = 1024;
    static char *logbuf;

    if (!logbuf) { logbuf = malloc(loglinelen); }

    va_list argp;
    va_start(argp, fmt);
    char location[128];
    if (func && func[0]) {
        snprintf(location, sizeof(location), "%s:%d %s()", file, line, func);
    }
    else {
        snprintf(location, sizeof(location), "%s:%d", file, line);
    }

    int len = vsnprintf(logbuf, loglinelen, fmt, argp);
    if (len > loglinelen) {
        loglinelen = len + 1;
        logbuf = realloc(logbuf, loglinelen);
        vsnprintf(logbuf, loglinelen, fmt, argp);
    }

    if (logger) { logger(level, location, logbuf, len); }
}

static void default_log_writer(const char *level, const char *loc, const char *msg, size_t msglen) {
    const char *elapsed = get_elapsed();
    fprintf(ziti_debug_out, "[%s] %7s %s ", elapsed, level, loc);
    fwrite(msg, 1, msglen, ziti_debug_out);
    fputc('\n', ziti_debug_out);
}

static void uv_mbed_logger(const char *level, const char *file, unsigned int line, const char *msg) {
    ziti_logger(level, file, line, NULL, msg);
}

static void flush_log(uv_prepare_t *p) {
    fflush(ziti_debug_out);
}

static const char *get_elapsed_time() {
    uint64_t now = uv_now(ts_loop);
    if (now > last_update) {
        last_update = now;
        uint64_t elapsed = now - starttime;
        snprintf(elapsed_buffer, sizeof(elapsed_buffer), "%9ld.%03ld", elapsed / 1000, elapsed % 1000);
    }
    return elapsed_buffer;
}

static const char *get_utc_time() {
    uint64_t now = uv_now(ts_loop);
    if (now > last_update) {
        last_update = now;
        uint64_t realtime = clock_offset + now;
        time_t time = realtime / 1000; // seconds
        time_t millis = realtime % 1000;
        struct tm *tm = gmtime(&time);

        snprintf(elapsed_buffer, sizeof(elapsed_buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                 1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
                 tm->tm_hour, tm->tm_min, tm->tm_sec, millis
                 );
    }
    return elapsed_buffer;
}

static char errbuf[1024];

void ziti_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *) malloc(suggested_size);
    if (buf->base == NULL) {
        ZITI_LOG(ERROR, "failed to allocate %zd bytes. Prepare for crash", suggested_size);
        buf->len = 0;
    }
    else {
        buf->len = suggested_size;
    }
}

int get_url_data(const char *url, struct http_parser_url *parser, int uf, char *out, size_t maxout) {
    if ((parser->field_set & (1 << uf)) != 0) {
        snprintf(out, maxout, "%*.*s", parser->field_data[uf].len, parser->field_data[uf].len,
                 url + parser->field_data[uf].off);
        return 1;
    }
    out[0] = 0;
    return 0;
}

int lt_zero(int v) { return v < 0; }

int non_zero(int v) { return v != 0; }

void hexDump (char *desc, void *addr, int len) {
    if (DEBUG > ziti_debug_level) return;
    ZITI_LOG(DEBUG, " ");
    int i;
    unsigned char buffLine[17];
    unsigned char *pc = (unsigned char*)addr;
    if (desc != NULL){
       printf ("%s:\n", desc);
    }
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) {
                printf ("  %s\n", buffLine);
            }
            printf ("  %07x ", i);
        }
        printf ("%02x", pc[i]);
        if ((i % 2) == 1) {
            printf (" "); 
        }
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buffLine[i % 16] = '.';
        }
        else{
           buffLine[i % 16] = pc[i];
        }    

        buffLine[(i % 16) + 1] = '\0'; //Clears the next array buffLine
    }
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    printf ("  %s\n", buffLine);
    fflush(stdout); 
    ZITI_LOG(DEBUG, " ");
}

void ziti_fmt_time(char* time_str, size_t time_str_sz, uv_timeval64_t* tv) {
    if (tv == NULL) {
        strncpy(time_str, "null tv", time_str_sz);
    } else {
        struct tm* start_tm = gmtime(&tv->tv_sec);
        strftime(time_str, time_str_sz, "%FT%T", start_tm);
    }
}