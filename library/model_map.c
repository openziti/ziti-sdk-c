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

#include <ziti/model_map.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <uv_mbed/queue.h>
#include "utils.h"

struct model_map_entry {
    void *key;
    size_t key_len;
    uint32_t key_hash;
    void *value;
    LIST_ENTRY(model_map_entry) _next;
    LIST_ENTRY(model_map_entry) _tnext;
    model_map *_map;
};

#define ENTRY_KEY(e) ((e)->key_len > sizeof((e)->key) ? (e)->key : &(e)->key)

typedef LIST_HEAD(entries_s, model_map_entry) entries_t;

struct model_impl_s {
    entries_t entries;
    entries_t *table;
    int buckets;
    size_t size;
};

static uint32_t key_hash0(const uint8_t *key, size_t key_len) {
    uint32_t h = 0;
    for (size_t idx = 0; idx < key_len; idx++) {
        h = ((h << 5U) + h) + key[idx];
    }
    return h;
}

static const int DEFAULT_MAP_BUCKETS = 16;

static uint32_t (*key_hash)(const uint8_t *key, size_t key_len) = key_hash0;

static void map_resize_table(model_map *m) {
    if (m->impl == NULL) { return; }

    int orig_buckets = m->impl->buckets;
    m->impl->buckets *= 2;
    m->impl->table = realloc(m->impl->table, m->impl->buckets * sizeof(entries_t));
    memset(m->impl->table, 0, sizeof(entries_t) * m->impl->buckets);

    struct model_map_entry *el;
    LIST_FOREACH(el, &m->impl->entries, _next) {
        uint32_t idx = el->key_hash % m->impl->buckets;
        entries_t *bucket = m->impl->table + idx;
        LIST_INSERT_HEAD(bucket, el, _tnext);
    }
}

static struct model_map_entry *find_map_entry(const model_map *m, const uint8_t *key, size_t key_len, uint32_t *hash_out) {
    uint32_t kh = key_hash(key, key_len);
    if (hash_out) {
        *hash_out = kh;
    }
    uint32_t idx = kh % m->impl->buckets;
    entries_t *bucket = m->impl->table + idx;
    struct model_map_entry *entry;
    LIST_FOREACH(entry, bucket, _tnext) {
        if (key_len == entry->key_len && kh == entry->key_hash) {
            void *ekey = ENTRY_KEY(entry);
            if (memcmp(key, ekey, key_len) == 0) {
                return entry;
            }
        }
    }
    return NULL;
}

size_t model_map_size(const model_map *m) {
    return m->impl ? m->impl->size : 0;
}

void *model_map_setl(model_map *m, long key, void *val) {
    return model_map_set_key(m, &key, sizeof(key), val);
}

void *model_map_set(model_map *m, const char *key, void *val) {
    return model_map_set_key(m, key, strlen(key) + 1, val);
}

void *model_map_set_key(model_map *m, const void *key, size_t key_len, void *val) {

    if (m->impl == NULL) {
        m->impl = calloc(1, sizeof(struct model_impl_s));
        m->impl->buckets = DEFAULT_MAP_BUCKETS;
        m->impl->table = calloc(m->impl->buckets, sizeof(entries_t));
    }

    uint32_t kh;
    struct model_map_entry *el = find_map_entry(m, key, key_len, &kh);
    if (el != NULL) {
        void *old_val = el->value;
        el->value = val;
        return old_val;
    }

    el = malloc(sizeof(struct model_map_entry));
    el->value = val;
    el->key_len = key_len;
    if (key_len > sizeof(el->key)) {
        el->key = malloc(key_len);
        memcpy(el->key, key, key_len);
    } else {
        memcpy(&el->key, key, key_len);
    }
    el->key_hash = kh;
    el->_map = m;
    uint32_t idx = el->key_hash % m->impl->buckets;

    entries_t *bucket = m->impl->table + idx;
    LIST_INSERT_HEAD(&m->impl->entries, el, _next);
    LIST_INSERT_HEAD(bucket, el, _tnext);
    m->impl->size++;

    if (m->impl->size > m->impl->buckets * 2) {
        map_resize_table(m);
    }

    return NULL;
}

void *model_map_getl(const model_map *m, long key) {
    return model_map_get_key(m, &key, sizeof(key));
}

void *model_map_get(const model_map *m, const char *key) {
    return model_map_get_key(m, key, strlen(key) + 1);
}

void *model_map_get_key(const model_map *m, const void *key, size_t key_len) {
    if (m == NULL || m->impl == NULL) {
        return NULL;
    }

    struct model_map_entry *el = find_map_entry(m, key, key_len, NULL);
    return el ? el->value : NULL;
}

void *model_map_removel(model_map *m, long key) {
    return model_map_remove_key(m, &key, sizeof(key));
}

void *model_map_remove(model_map *m, const char *key) {
    return model_map_remove_key(m, key, strlen(key) + 1);
}

void *model_map_remove_key(model_map *m, const void *key, size_t key_len) {
    if (m->impl == NULL) {
        return NULL;
    }

    void *val = NULL;
    struct model_map_entry *el = find_map_entry(m, key, key_len, NULL);
    if (el != NULL) {
        val = el->value;
        LIST_REMOVE(el, _next);
        LIST_REMOVE(el, _tnext);
        if (el->key_len > sizeof(el->key)) {
            free(el->key);
        }
        free(el);
        m->impl->size--;
    }

    if (m->impl->size == 0) {
        FREE(m->impl->table);
        FREE(m->impl);
    }
    return val;
}

void model_map_clear(model_map *map, void (*val_free_func)(void *)) {
    if (map->impl == NULL) { return; }

    while (!LIST_EMPTY(&map->impl->entries)) {
        struct model_map_entry *el = LIST_FIRST(&map->impl->entries);
        LIST_REMOVE(el, _next);
        if (el->key_len > sizeof(el->key)) {
            FREE(el->key);
        }
        if (val_free_func) {
            val_free_func(el->value);
        }
        FREE(el->value);
        FREE(el);
    }
    FREE(map->impl->table);
    FREE(map->impl);
}

model_map_iter model_map_iterator(const model_map *m) {
    if (m->impl == NULL) { return NULL; }
    return LIST_FIRST(&m->impl->entries);
}

const char *model_map_it_key(model_map_iter it) {
    return (const char *) model_map_it_key_s(it, NULL);
}

const void *model_map_it_key_s(model_map_iter it, size_t *key_len) {
    if (it == NULL) { return NULL; }

    struct model_map_entry *entry = (struct model_map_entry *) it;
    if (key_len != NULL) {
        *key_len = entry->key_len;
    }

    return ENTRY_KEY(entry);
}

long model_map_it_lkey(model_map_iter it) {
    const long *keyp = model_map_it_key_s(it, NULL);
    return *keyp;
}

void *model_map_it_value(model_map_iter it) {
    return it != NULL ? ((struct model_map_entry *) it)->value : NULL;
}

model_map_iter model_map_it_next(model_map_iter it) {
    return it != NULL ? LIST_NEXT((struct model_map_entry *) it, _next) : NULL;
}

model_map_iter model_map_it_remove(model_map_iter it) {
    model_map_iter next = model_map_it_next(it);
    if (it != NULL) {
        struct model_map_entry *e = (struct model_map_entry *) it;
        model_map *m = e->_map;
        m->impl->size--;
        LIST_REMOVE(e, _next);
        LIST_REMOVE(e, _tnext);
        if (e->key_len > sizeof(e->key)) {
            free(e->key);
        }
        free(e);

        // last element removed
        if (m->impl->size == 0) {
            FREE(m->impl->table);
            FREE(m->impl);
        }
    }
    return next;
}
