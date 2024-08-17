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

#include "metrics.h"

#define _USE_MATH_DEFINES

#include <math.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
# if __STDC_NO_ATOMICS__
#   include <atomic.h>

#   define InterlockedAdd64(p, v) (*p) += (v)
#   define InterlockedExchange64(p, v) (*p) = (v)
#   define InterlockedExchange(p, v) (*p) = (v)
# else
#include <stdatomic.h>
# endif
#endif

#if defined(_MSC_VER)
#include <stdatomic.h>
#endif

#define NANOS(s) ((s) * 1e9)
#define MILLIS(s) ((s) * 1000)

static const double SECOND = NANOS(1); // one second in nanos

static time_fn clock_fn;
static void *clock_ctx;

static double interval = 5; // 5 seconds is default
static double intervalNanos = NANOS(5);

static void tick_ewma(rate_t *ewma);
static void tick_cma(rate_t *cma);
static void tick_instant(rate_t *inst);

extern void metrics_init(long interval_secs, time_fn f, void *time_ctx) {

    if (clock_fn == NULL) {
        clock_fn = f;
        clock_ctx = time_ctx;
        
        interval = (double)interval_secs;
        intervalNanos = NANOS(interval);
    }

}

extern void metrics_rate_close(rate_t* r) {
    if (r->active) {
        r->active = false;
        r->tick_fn = NULL;
        atomic_exchange(&r->delta, 0);
        r->rate = 0;
    }
}

extern int metrics_rate_init(rate_t *r, rate_type type) {
    if (r->active) {
        metrics_rate_close(r);
    }
    memset(r, 0, sizeof(rate_t));
    switch (type) {
        case EWMA_5s:
            r->tick_fn = tick_ewma;
            *(double*)(&r->param) = 1.0 - pow(M_E, -(interval / 12));
            break;
        case EWMA_1m:
            r->tick_fn = tick_ewma;
            *(double*)(&r->param) = 1.0 - pow(M_E, -(interval / 60.0));
            break;

        case EWMA_5m:
            r->tick_fn = tick_ewma;
            *(double*)(&r->param) = 1.0 - pow(M_E, -(interval / 60.0 / 5.0));
            break;

        case EWMA_15m:
            r->tick_fn = tick_ewma;
            *(double*)(&r->param) = 1.0 - pow(M_E, -(interval / 60.0 / 15.0));
            break;

        case MMA_1m:
            r->tick_fn = tick_ewma;
            *(double*)(&r->param) = interval/60.0;
            break;

        case CMA_1m:
            r->tick_fn = tick_cma;
            break;
            
        case INSTANT:
            r->tick_fn = tick_instant;
            r->param = 1;
            break;
        default:
            return -1;
    }
    if (clock_fn) {
        r->last_tick = clock_fn(clock_ctx);
    }

    r->active = true;
    return 0;
}

static void rate_catchup(rate_t *r) {
    if (clock_fn) {
        uint64_t now = clock_fn(clock_ctx);
        while (now > r->last_tick + (uint64_t) MILLIS(interval)) {
            r->tick_fn(r);
            r->last_tick = r->last_tick + (uint64_t) MILLIS(interval);
        }
    }
}

extern void metrics_rate_update(rate_t *r, long delta) {
    if (r == NULL || !r->active) return;

    rate_catchup(r);
    atomic_fetch_add(&r->delta, delta);
}

extern double metrics_rate_get(rate_t *r) {
    if (r == NULL) return 0;
    rate_catchup(r);
    double rate = (*(double*)&r->rate) * (SECOND);
    return rate;
}

static double instant_rate(rate_t *r) {
    int64_t c = r->delta;
    atomic_fetch_add(&r->delta, -c);
    return ((double) c) / (intervalNanos);
}

static void tick_cma(rate_t *cma) {
    double r = instant_rate(cma);
    double current_rate = *(double*)&cma->rate;
    current_rate = (r + current_rate * cma->param) / ((double) cma->param + 1);

    atomic_exchange(&cma->rate, *(int64_t *) (&current_rate));
    atomic_exchange(&cma->param, cma->param + 1);
}

static void tick_ewma(rate_t *ewma) {
    double r = instant_rate(ewma);

    if (ewma->init == 1) {
        double currRate = *(double*)&ewma->rate;
        currRate += *(double*)(&ewma->param) * (r - currRate);
        atomic_exchange(&ewma->rate, *(int64_t *) (&currRate));
    } else {
        atomic_exchange(&ewma->rate, *(int64_t *) (&r));
        atomic_exchange(&ewma->init, 1);
    }
}

static void tick_instant(rate_t *inst) {
    double r = instant_rate(inst);
    atomic_exchange(&inst->delta, 0); //reset the delta
    atomic_exchange(&inst->rate, *(int64_t*)(&r));
}
