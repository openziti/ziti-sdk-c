//
// Created by eugene on 4/15/2020.
//

#ifndef ZITI_SDK_ZITI_LOG_H
#define ZITI_SDK_ZITI_LOG_H

#include <uv.h>

#include "externs.h"

#ifdef SOURCE_PATH_SIZE
#define __FILENAME__ (&__FILE__[SOURCE_PATH_SIZE])
#else
#define __FILENAME__ __FILE__
#endif

#ifndef ZITI_LOG_PREFIX
#define ZITI_LOG_PREFIX
#endif

#define _to_str(x) #x
#define to_str(x) _to_str(x)
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

#define ZITI_LOG(level, fmt, ...) do { \
if (level <= ziti_log_level()) { ziti_logger(level, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__); }\
} while(0)

#define ZTX_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "ztx[%d] " fmt, ztx->id, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

#define ZITI_LOG_DEFAULT_LEVEL (-1)

typedef void (*log_writer)(int level, const char *loc, const char *msg, size_t msglen);

ZITI_FUNC extern void
ziti_logger(int level, const char *file, unsigned int line, const char *func, const char *fmt, ...);

// call once
// use ZITI_LOG_DEFAULT_LEVEL to use default(INFO)/ZITI_LOG env var
// pass logger = NULL to use default output
ZITI_FUNC extern void ziti_log_init(uv_loop_t *loop, int level, log_writer logger);

ZITI_FUNC extern void ziti_log_set_logger(log_writer logger);

// use ZITI_LOG_DEFAULT_LEVEL to reset to default(INFO) or ZITI_LOG env var
ZITI_FUNC extern void ziti_log_set_level(int level);

// don't use directly
ZITI_FUNC extern int ziti_log_level();

#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_ZITI_LOG_H
