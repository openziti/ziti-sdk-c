// Copyright (c) 2022-2023.  NetFoundry Inc.
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

#include "pool.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <tlsuv/queue.h>
#include <assert.h>

struct pool_obj_s {
    pool_t *pool;
    size_t size;

    LIST_ENTRY(pool_obj_s) _next;
    void (*clear_func)(void *);
    char obj[];
};

struct pool_s {
    LIST_HEAD(objs, pool_obj_s) pool;
    size_t memsize;
    size_t capacity;
    size_t out;
    bool is_closed;

    void (*clear_func)(void *);
};

pool_t *pool_new(size_t objsize, size_t count, void (*clear_func)(void *)) {
    pool_t *p = calloc(1, sizeof(pool_t));
    p->memsize = objsize;
    p->capacity = count;
    p->clear_func = clear_func;
    return p;
}

void pool_destroy(pool_t *pool) {
    pool->is_closed = true;

    while (!LIST_EMPTY(&pool->pool)) {
        struct pool_obj_s *m = LIST_FIRST(&pool->pool);
        LIST_REMOVE(m, _next);
        free(m);
    }

    if (pool->out == 0) {
        free(pool);
    }
}

bool pool_has_available(pool_t *pool) {
    assert(pool);
    assert(!pool->is_closed);
    return !LIST_EMPTY(&pool->pool) || pool->capacity > pool->out;
}

void *alloc_unpooled_obj(size_t size, void (*clear_func)(void *)) {
    struct pool_obj_s *obj = calloc(1, sizeof(struct pool_obj_s) + size);
    if (obj) {
        obj->size = size;
        obj->pool = NULL;
        obj->clear_func = clear_func;
        return obj->obj;
    }
    return NULL;
}

void *pool_alloc_obj(pool_t *pool) {
    if (pool == NULL) {
        return NULL;
    }
    assert(!pool->is_closed);

    struct pool_obj_s *member = NULL;
    if (!LIST_EMPTY(&pool->pool)) {
        member = LIST_FIRST(&pool->pool);
        LIST_REMOVE(member, _next);
    }
    else if (pool->capacity > pool->out) {
        member = calloc(1, sizeof(struct pool_obj_s) + pool->memsize);
        member->size = pool->memsize;
        member->pool = pool;
        member->clear_func = pool->clear_func;
    }

    if (member) {
        pool->out++;
        return &member->obj;
    }

    return NULL;
}

size_t pool_mem_size(pool_t *pool) {
    return pool ? pool->memsize : 0;
}

size_t pool_obj_size(void *o) {
    if (o == NULL) { return 0; }

    struct pool_obj_s *m = container_of((char *) o, struct pool_obj_s, obj);
    return m->size;
}

void pool_return_obj(void *o) {
    if (o == NULL) { return; }

    struct pool_obj_s *m = container_of((char *) o, struct pool_obj_s, obj);
    if (m->clear_func) {
        m->clear_func(o);
    }
    pool_t *pool = m->pool;
    if (pool == NULL) {
        free(m);
        return;
    }

    memset(o, 0, m->size);
    pool->out--;

    if (pool->is_closed) {
        free(m);
        if (pool->out == 0) {
            free(pool);
        }
    } else {
        LIST_INSERT_HEAD(&pool->pool, m, _next);
    }
}