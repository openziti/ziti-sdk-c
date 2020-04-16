//
// Created by eugene on 4/15/2020.
//

#ifndef ZITI_SDK_ZITI_LOG_H
#define ZITI_SDK_ZITI_LOG_H

#include "externs.h"

#ifdef SOURCE_PATH_SIZE
#define __FILENAME__ (&__FILE__[SOURCE_PATH_SIZE])
#else
#define __FILENAME__ __FILE__
#endif


#define ZITI_LOG(level, fmt, ...) do { \
if (level <= ziti_debug_level) {\
    long elapsed = get_elapsed();\
    fprintf(ziti_debug_out, "[%9ld.%03ld] " #level "\tziti-sdk-c:%s:%d %s(): " fmt "\n",\
        elapsed/1000, elapsed%1000, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__);\
        }\
} while(0)

#ifdef __cplusplus
extern "C" {
#endif

ZITI_FUNC long get_elapsed();
ZITI_FUNC extern void init_debug();
ZITI_FUNC extern int ziti_debug_level;
ZITI_FUNC extern FILE *ziti_debug_out;

#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_ZITI_LOG_H
