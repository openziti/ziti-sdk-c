//
// Created by eugene on 4/30/2020.
//

#ifndef ZITI_SDK_METRICS_H
#define ZITI_SDK_METRICS_H

#include <stdint.h>
#include <stdbool.h>
#include <uv_mbed/queue.h>
#include <uv.h>

struct rate_s {
    int64_t delta;
    int64_t rate;
    int64_t param;

    void (*tick_fn)(struct rate_s *);
    long init;
    LIST_ENTRY(rate_s) _next;

};

typedef struct rate_s rate_t;

enum rate_type {
    EWMA_1m,
    EWMA_5m,
    EWMA_15m,
    MMA_1m,
    CMA_1m,
};

#ifdef __cplusplus
extern "C" {
#endif

extern void metrics_init(uv_loop_t *loop, long interval_secs);

extern void metrics_rate_init(rate_t *r, enum rate_type type);
extern void metrics_rate_close(rate_t* r);

extern void metrics_rate_update(rate_t *r, long delta);
extern double metrics_rate_get(rate_t *r);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_METRICS_H
