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

#define LEVEL_LBL(lvl) #lvl,
static const char *const level_labels[] = {
        DEBUG_LEVELS(LEVEL_LBL)
};

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
#ifdef ZITI_BUILDNUM
    return to_str(ZITI_VERSION) "-" to_str(ZITI_BUILDNUM);
#else
    return to_str(ZITI_VERSION);
#endif
}

const char* ziti_git_branch() {
    return to_str(ZITI_BRANCH);
}

const char* ziti_git_commit() {
    return to_str(ZITI_COMMIT);
}

static int ziti_log_lvl = ZITI_LOG_DEFAULT_LEVEL;
static FILE *ziti_debug_out;
static bool log_initialized = false;

const char *(*get_elapsed)();

static const char *get_elapsed_time();

static const char *get_utc_time();

static void flush_log(uv_prepare_t *p);

static void default_log_writer(int level, const char *loc, const char *msg, size_t msglen);

static uv_loop_t *ts_loop;
static uint64_t starttime;
static uint64_t last_update;
static char elapsed_buffer[32];

static uv_prepare_t log_flusher;
static log_writer logger = NULL;
static void init_debug(uv_loop_t *loop);

static void init_uv_mbed_log();

void ziti_log_init(uv_loop_t *loop, int level, log_writer log_func) {
    init_debug(loop);

    init_uv_mbed_log();

    if (level == ZITI_LOG_DEFAULT_LEVEL) {
        level = ziti_log_lvl;
    } // in case it was set before

    ziti_log_set_level(level);

    if (log_func == NULL) {
        // keep the logger if it was already set
        ziti_log_set_logger(logger ? logger : default_log_writer);
    } else {
        ziti_log_set_logger(log_func);
    }
}

void ziti_log_set_level(int level) {
    if (level == ZITI_LOG_DEFAULT_LEVEL) {
        char *lvl = getenv("ZITI_LOG");
        if (lvl != NULL) {
            ziti_log_lvl = (int) strtol(lvl, NULL, 10);
        } else {
            ziti_log_lvl = INFO;
        }
    } else {
        ziti_log_lvl = level;
    }

    if (logger) {
        char msg[128];
        int len = snprintf(msg, sizeof(msg), "set log level: ziti_log_lvl=%d &ziti_log_lvl = %p", ziti_log_lvl, &ziti_log_lvl);
        logger(INFO, "ziti_log_set_level", msg, len);
    }
}

int ziti_log_level() {
    return ziti_log_lvl;
}

void ziti_log_set_logger(log_writer log) {
    logger = log;
}

static void init_uv_mbed_log() {
    char *lvl;
    if ((lvl = getenv("UV_MBED_DEBUG")) != NULL) {
        int l = (int) strtol(lvl, NULL, 10);
        uv_mbed_set_debug(l, uv_mbed_logger);
    }
}

static void init_debug(uv_loop_t *loop) {
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
    ziti_log_set_level(ziti_log_lvl);
    ziti_debug_out = stderr;

    starttime = uv_now(loop);

    uv_prepare_init(loop, &log_flusher);
    uv_unref((uv_handle_t *) &log_flusher);
    uv_prepare_start(&log_flusher, flush_log);
}

void ziti_logger(int level, const char *module, const char *file, unsigned int line, const char *func, FORMAT_STRING(const char *fmt), ...) {
    static size_t loglinelen = 1024;
    static char *logbuf;

    if (!logbuf) { logbuf = malloc(loglinelen); }

    va_list argp;
    va_start(argp, fmt);
    char location[128];
    char *last_slash = strrchr(file, '/');

    int modlen = 16;
    if (module == NULL) {
        if (last_slash == NULL) {
            modlen = 0;
        } else {
            char *p = last_slash;
            while (p > file) {
                p--;
                if (*p == '/') {
                    p++;
                    break;
                }
            }
            module = p;
            modlen = (int) (last_slash - p);
        }
    }

    if (last_slash) {
        file = last_slash + 1;
    }
    if (func && func[0]) {
        snprintf(location, sizeof(location), "%.*s:%s:%u %s()", modlen, module, file, line, func);
    } else {
        snprintf(location, sizeof(location), "%.*s:%s:%u", modlen, module, file, line);
    }

    int len = vsnprintf(logbuf, loglinelen, fmt, argp);
    va_end(argp);
    if (len > loglinelen) {
        loglinelen = len + 1;
        logbuf = realloc(logbuf, loglinelen);
        va_start(argp, fmt);
        vsnprintf(logbuf, loglinelen, fmt, argp);
        va_end(argp);
    }

    if (logger) { logger(level, location, logbuf, len); }
}

static void default_log_writer(int level, const char *loc, const char *msg, size_t msglen) {
    const char *elapsed = get_elapsed();
    fprintf(ziti_debug_out, "[%s] %7s %s ", elapsed, level_labels[level], loc);
    fwrite(msg, 1, msglen, ziti_debug_out);
    fputc('\n', ziti_debug_out);
}

void uv_mbed_logger(int level, const char *file, unsigned int line, const char *msg) {
    ziti_logger(level, "uv-mbed", file, line, NULL, msg);
}

void ziti_enable_uv_mbed_logger(int enabled) {
    if(enabled) {
        uv_mbed_set_debug(9, uv_mbed_logger);
    } else {
        uv_mbed_set_debug(1, NULL);
    }
}

static void flush_log(uv_prepare_t *p) {
    fflush(ziti_debug_out);
}

static const char *get_elapsed_time() {
    uint64_t now = uv_now(ts_loop);
    if (now > last_update) {
        last_update = now;
        unsigned long long elapsed = now - starttime;
        snprintf(elapsed_buffer, sizeof(elapsed_buffer), "%9llu.%03llu", (elapsed / 1000), (elapsed % 1000));
    }
    return elapsed_buffer;
}

static const char *get_utc_time() {
    uint64_t now = uv_now(ts_loop);
    if (now > last_update) {
        last_update = now;

        uv_timeval64_t ts;
        uv_gettimeofday(&ts);
        struct tm *tm = gmtime(&ts.tv_sec);

        snprintf(elapsed_buffer, sizeof(elapsed_buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                 1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
                 tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_usec / 1000
                 );
    }
    return elapsed_buffer;
}

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
    if (DEBUG > ziti_log_level()) return;
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

void hexify(const uint8_t *bin, size_t bin_len, char sep, char **buf) {
    static char hex[] = "0123456789abcdef";
    size_t out_size = sep ? bin_len * 3 : bin_len * 2 + 1;
    char *out = malloc(out_size);
    char *p = out;
    for (int i = 0; i < bin_len; i++) {
        unsigned char b = bin[i];
        if (sep && i > 0) *p++ = sep;
        *p++ = hex[b >> 4];
        *p++ = hex[b & 0xf];
    }
    *p = 0;
    *buf = out;
}