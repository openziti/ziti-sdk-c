/*
Copyright (c) 2019-2020 NetFoundry, Inc.

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
