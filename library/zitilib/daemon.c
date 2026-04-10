// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//
//
#include <ziti/zitilib.h>
#include <ziti/ziti_log.h>

#include "zl.h"

#include <tlsuv/queue.h>
#include <uv.h>

#define INVALID_THREAD ((uv_thread_t) -1)

uv_key_t err_key;

static uv_once_t init;
static uv_mutex_t q_mut;
static uv_async_t q_async;
static LIST_HEAD(loop_queue, queue_elem_s) loop_q;


// invocation state
static uv_mutex_t loop_lock;
static uv_cond_t loop_cond;
static uv_thread_t daemon_thread = INVALID_THREAD;

typedef struct queue_elem_s {
    loop_work_cb cb;
    void *arg;
    future_t *f;
    LIST_ENTRY(queue_elem_s) _next;
} queue_elem_t;

static void process_on_loop(uv_async_t *async);
static void looper(void *arg);


static void internal_init() {
#if defined(PTHREAD_ONCE_INIT)
//    pthread_atfork(NULL, NULL, child_init);
#endif
    uv_key_create(&err_key);
    uv_mutex_init(&q_mut);
    uv_mutex_init(&loop_lock);
    uv_cond_init(&loop_cond);
}

void Ziti_lib_init(void) {
    uv_once(&init, internal_init);

    c_with(uv_mutex_lock(&loop_lock), uv_mutex_unlock(&loop_lock)) {
        if (daemon_thread == INVALID_THREAD) {
            uv_thread_create(&daemon_thread, looper, NULL);
            uv_cond_wait(&loop_cond, &loop_lock);
        }
    }
}

future_t *schedule_on_loop(loop_work_cb cb, void *arg, bool wait) {
    future_t *f = NULL;
    if (wait) {
        f = new_future();
    }

    queue_elem_t *el = calloc(1, sizeof(queue_elem_t));
    el->cb = cb;
    el->arg = arg;
    el->f = f;

    uv_mutex_lock(&q_mut);
    LIST_INSERT_HEAD(&loop_q, el, _next);
    uv_mutex_unlock(&q_mut);
    uv_async_send(&q_async);

    return f;
}

void process_on_loop(uv_async_t *async) {
    LIST_HEAD(loop_queue, queue_elem_s) q = {0};

    // drain q
    uv_mutex_lock(&q_mut);
    while (!LIST_EMPTY(&loop_q)) {
        queue_elem_t *el = LIST_FIRST(&loop_q);
        LIST_REMOVE(el, _next);
        LIST_INSERT_HEAD(&q, el, _next);
    }
    uv_mutex_unlock(&q_mut);

    while (!LIST_EMPTY(&q)) {
        queue_elem_t *el = LIST_FIRST(&q);
        LIST_REMOVE(el, _next);
        el->cb(el->arg, el->f, async->loop);
        free(el);
    }
}

static void looper(void *arg) {
    (void)arg;
    uv_thread_setname("zitilib-daemon");
    uv_loop_t *loop = uv_loop_new();
    c_with(uv_mutex_lock(&loop_lock), uv_mutex_unlock(&loop_lock)) {
        ziti_log_init(loop, -1, NULL);
        uv_async_init(loop, &q_async, process_on_loop);
        uv_cond_broadcast(&loop_cond);
    }

    ZITI_LOG(DEBUG, "loop is starting");
    uv_run(loop, UV_RUN_DEFAULT);
    if (!LIST_EMPTY(&loop_q)) {
        ZITI_LOG(WARN, "queue is not empty at shutdown");
    }
    ZITI_LOG(DEBUG, "loop is done");

    // there should not be any active loop handles at this point,
    // but run the loop a few times to allow any pending close callbacks to run and free their handles
    for (int i = 0; i < 10; i++) {
        int n = uv_run(loop, UV_RUN_ONCE);
        if (n == 0) {
            break;
        }
    }

    if (uv_loop_close(loop) == UV_EBUSY) {
        ZITI_LOG(WARN, "some handles still active at shutdown");
        uv_print_all_handles(loop, stderr);
    }
    free(loop);

    c_with(uv_mutex_lock(&loop_lock), uv_mutex_unlock(&loop_lock)) {
        daemon_thread = INVALID_THREAD;
        memset(&q_async, 0, sizeof(q_async));
        uv_cond_broadcast(&loop_cond);
    }
}

void do_shutdown(void *args, future_t *f, uv_loop_t *l) {
    (void)args;
    model_map_iter *it = model_map_iterator(&ziti_contexts);
    while (it) {
        ztx_wrap_t *w = model_map_it_value(it);
        it = model_map_it_remove(it);
        if (w->ztx) {
            ziti_shutdown(w->ztx);
        }
        model_map_clear(&w->intercepts, (void (*)(void *)) free_ziti_intercept_cfg_v1_ptr);
    }
    complete_future(f, NULL, 0);
    uv_close((uv_handle_t *) &q_async, NULL);

    uv_stop(l);
}

void Ziti_lib_shutdown(void) {
    uv_thread_t t;
    c_with(uv_mutex_lock(&loop_lock), uv_mutex_unlock(&loop_lock)) {
        t = daemon_thread;
        if (t != INVALID_THREAD) {
            schedule_on_loop(do_shutdown, NULL, false);
            uv_cond_wait(&loop_cond, &loop_lock);
        }
    }

    if (t != INVALID_THREAD) {
        uv_thread_join(&t);
    }
}

int Ziti_last_error() {
    intptr_t p = (intptr_t) uv_key_get(&err_key);
    return (int)p;
}

void zl_set_error(int err) {
    uv_key_set(&err_key, (void *) (intptr_t) err);
}

bool zl_check_daemon() {
    uv_thread_t t;
    c_with(uv_mutex_lock(&loop_lock), uv_mutex_unlock(&loop_lock)) {
            t = daemon_thread;
    }
    return t != INVALID_THREAD;
}

