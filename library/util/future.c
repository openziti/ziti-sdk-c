//
// 	Copyright NetFoundry Inc.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

#include <stdbool.h>
#include <stdlib.h>
#include <uv.h>

#include "future.h"

typedef struct future_s {
    uv_mutex_t lock;
    uv_cond_t cond;
    void *result;
    int err;
    bool completed;
    bool deleted;
} future_t;


future_t *new_future() {
    future_t *f = calloc(1, sizeof(future_t));
    int rc = uv_mutex_init(&f->lock);
    if (rc != 0) {
        fprintf(stderr, "failed to init lock %d/%s\n", rc, uv_strerror(rc));
    }
    rc = uv_cond_init(&f->cond);
    if (rc != 0) {
        fprintf(stderr, "failed to init cond %d/%s\n", rc, uv_strerror(rc));
    }
    return f;
}

void destroy_future(future_t *f) {
    if (f == NULL) return;

    uv_mutex_lock(&f->lock);

    // some code may try to complete it
    if (!f->completed) {
        f->deleted = true;
        uv_mutex_unlock(&f->lock);
        return;
    }

    uv_mutex_unlock(&f->lock);
    uv_mutex_destroy(&f->lock);
    uv_cond_destroy(&f->cond);
    free(f);
}

int await_future_timed(future_t *f, void **result, uint64_t timeout) {
    if (f == NULL) {
        if (result) *result = NULL;
        return 0;
    }

    // uv_cond_timedwait timeout is in nanoseconds, so we convert milliseconds to nanoseconds
    timeout *= 1000000;

    uv_mutex_lock(&f->lock);
    while (!f->completed) {
        if (timeout == 0) {
            uv_cond_wait(&f->cond, &f->lock);
            continue;
        }

        if (uv_cond_timedwait(&f->cond, &f->lock, timeout) == UV_ETIMEDOUT) {
            uv_mutex_unlock(&f->lock);
            return UV_ETIMEDOUT;
        }
    }
    int err = f->err;
    void *res = f->result;
    uv_mutex_unlock(&f->lock);

    if (result) *result = res;
    return err;
}

int await_future(future_t *f, void **result) {
    return await_future_timed(f, result, 0);
}

int complete_future(future_t *f, void *result, int code) {
    if (f == NULL) return 0;

    int rc = UV_EINVAL;
    uv_mutex_lock(&f->lock);
    bool deleted = f->deleted;
    if (!f->completed) {
        f->completed = true;
        f->result = result;
        f->err = code;
        uv_cond_broadcast(&f->cond);
        rc = 0;
    }
    uv_mutex_unlock(&f->lock);

    // caller discarded the future
    if (deleted) {
        destroy_future(f);
    }
    return rc;
}

int fail_future(future_t *f, int err) {
    if (f == NULL) return 0;

    int rc = UV_EINVAL;
    uv_mutex_lock(&f->lock);
    bool deleted = f->deleted;
    if (!f->completed) {
        f->completed = true;
        f->err = err;
        uv_cond_broadcast(&f->cond);
        rc = 0;
    }
    uv_mutex_unlock(&f->lock);

    // caller discarded the future
    if (deleted) {
        destroy_future(f);
    }
    return rc;
}
