/*
Copyright (c) 2022 NetFoundry, Inc.

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

#include "pool.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <uv_mbed/queue.h>

struct pool_obj_s {
    pool_t *pool;
    size_t size;

    LIST_ENTRY(pool_obj_s) _next;

    char obj[];
};

struct pool_s {
    LIST_HEAD(objs, pool_obj_s) pool;
    size_t memsize;
    size_t count;
    size_t out;

    void (*clear_func)(void *);
};

pool_t *pool_new(size_t objsize, size_t count, void (*clear_func)(void *)) {
    pool_t *p = calloc(1, sizeof(pool_t));
    p->memsize = objsize;
    p->count = count;
    p->clear_func = clear_func;
    return p;
}

void pool_destroy(pool_t *p) {
    while (!LIST_EMPTY(&p->pool)) {
        struct pool_obj_s *m = LIST_FIRST(&p->pool);
        LIST_REMOVE(m, _next);
        free(m);
    }

    free(p);
}

bool pool_has_available(pool_t *pool) {
    return !LIST_EMPTY(&pool->pool) || pool->count > 0;
}

void *pool_alloc_obj(pool_t *pool) {
    struct pool_obj_s *member = NULL;
    if (!LIST_EMPTY(&pool->pool)) {
        member = LIST_FIRST(&pool->pool);
        LIST_REMOVE(member, _next);
    } else if (pool->count > 0) {
        pool->count--;
        member = calloc(1, sizeof(struct pool_obj_s) + pool->memsize);
        member->size = pool->memsize;
        member->pool = pool;
    }

    if (member) {
        pool->out++;
        return &member->obj;
    }

    return NULL;
}

size_t pool_obj_size(void *o) {
    struct pool_obj_s *m = container_of((char *) o, struct pool_obj_s, obj);
    return m->size;
}

void pool_return_obj(void *o) {
    struct pool_obj_s *m = container_of((char *) o, struct pool_obj_s, obj);
    pool_t *pool = m->pool;
    if (pool->clear_func) { pool->clear_func(o); }
    memset(o, 0, pool->memsize);
    LIST_INSERT_HEAD(&pool->pool, m, _next);
    pool->out--;
}