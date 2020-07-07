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
#include <uv.h>

#if defined(__unix__) || defined(__APPLE__)
#include <stdatomic.h>
#define InterlockedAdd64(p, v) atomic_fetch_add(p,v)
#define InterlockedExchange64(p, v) atomic_store(p,v)
#define InterlockedExchange(p, v) atomic_store(p,v)
#endif

#define NANOS(s) ((s) * 1e9)
#define MILLIS(s) ((s) * 1000)

static const double SECOND = NANOS(1); // one second in nanos

static uv_timer_t ticker;
static double interval = 5; // 5 seconds is default
static double intervalNanos = NANOS(5);

static LIST_HEAD(meters, rate_s) all_rates = LIST_HEAD_INITIALIZER(all_rates);

static void ticker_cb(uv_timer_t *t);
static void tick_ewma(rate_t *ewma);
static void tick_cma(rate_t *cma);
static void tick_instant(rate_t *inst);

static double default_rate_get(rate_t* r);
static double metrics_get_instant(rate_t *r);

extern void metrics_init(uv_loop_t *loop, long interval_secs) {

    if (!uv_is_active((uv_handle_t*)&ticker)) {

        interval = (double)interval_secs;
        intervalNanos = NANOS(interval);

        uv_timer_init(loop, &ticker);
        uv_timer_start(&ticker, ticker_cb, MILLIS(interval_secs), MILLIS(interval_secs));
        uv_unref((uv_handle_t*)&ticker);
    }

}

extern void metrics_rate_close(rate_t* r) {
    if (r->active) {
        r->active = false;
        LIST_REMOVE(r, _next);
    }
}

extern void metrics_rate_init(rate_t *r, rate_type type) {
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
    }

    r->active = true;
    LIST_INSERT_HEAD(&all_rates, r, _next);
}

extern void metrics_rate_update(rate_t *r, long delta) {
    InterlockedAdd64(&r->delta, delta);
}

extern double metrics_rate_get(rate_t *r) {
    double rate = (*(double*)&r->rate) * (SECOND);
    return rate;
}

void tick_all() {
    rate_t *r;
    LIST_FOREACH(r, &all_rates, _next) {
        if (r->tick_fn) {
            r->tick_fn(r);
        }
    }

}

static void ticker_cb(uv_timer_t *t) {
    tick_all();
}

static double instant_rate(rate_t *r) {
    int64_t c = r->delta;
    InterlockedAdd64(&r->delta, -c);
    return ((double) c) / (intervalNanos);
}

static void tick_cma(rate_t *cma) {
    double r = instant_rate(cma);
    double current_rate = *(double*)&cma->rate;
    current_rate = (r + current_rate * cma->param) / ((double) cma->param + 1);

    InterlockedExchange64(&cma->rate, *(int64_t *) (&current_rate));
    InterlockedExchange64(&cma->param, cma->param + 1);
}

static void tick_ewma(rate_t *ewma) {
    double r = instant_rate(ewma);

    if (ewma->init == 1) {
        double currRate = *(double*)&ewma->rate;
        currRate += *(double*)(&ewma->param) * (r - currRate);
        InterlockedExchange64(&ewma->rate, *(int64_t *) (&currRate));
    } else {
        InterlockedExchange64(&ewma->rate, *(int64_t *) (&r));
        InterlockedExchange(&ewma->init, 1);
    }
}

// a function that will return the last measured value expressed as 
double metrics_get_instant(rate_t* r) {
    double d = (double)r->rate;
    return (double)r->rate;
}

static void tick_instant(rate_t *inst) {
    double r = instant_rate(inst);
    InterlockedExchange64(&inst->delta, 0); //reset the delta
    InterlockedExchange64(&inst->rate, *(int64_t*)(&r));
}
