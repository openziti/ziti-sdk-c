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

#include <mbedtls/error.h>
#include <uv.h>
#include <uv_mbed/uv_mbed.h>
#include <ziti/ziti_model.h>
#include "utils.h"


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
FILE *ziti_debug_out;
static bool log_initialized = false;

#if _WIN32
LARGE_INTEGER frequency;
LARGE_INTEGER start;
LARGE_INTEGER end;
#else
struct timespec starttime;
#endif

void ziti_set_log(FILE *log) {
    init_debug();
    ziti_debug_out = log;
    uv_mbed_set_debug(ziti_debug_level, log);
}

void init_debug() {
    if (log_initialized) {
        return;
    }
    log_initialized = true;
    char *level = getenv("ZITI_LOG");
    if (level != NULL) {
        ziti_debug_level = (int) strtol(level, NULL, 10);
    }
    ziti_debug_out = stderr;

    uv_mbed_set_debug(ziti_debug_level, ziti_debug_out);
#if _WIN32
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);
#else
    clock_gettime(CLOCK_MONOTONIC, &starttime);
#endif
}

long get_elapsed() {
#if _WIN32
	QueryPerformanceCounter(&end);
	LARGE_INTEGER elapsed; // microseconds
	elapsed.QuadPart = ( end.QuadPart - start.QuadPart ) * 1000;
	return ( elapsed.QuadPart /= frequency.QuadPart ) ;
#else
	struct timespec cur;
	clock_gettime(CLOCK_MONOTONIC, &cur);
	return (cur.tv_sec - starttime.tv_sec) * 1000 + ((cur.tv_nsec - starttime.tv_nsec) / ((long)1e6));
#endif
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
