// Copyright (c) 2022.  NetFoundry Inc.
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


#ifndef ZITI_SDK_MODEL_COLLECTIONS_H
#define ZITI_SDK_MODEL_COLLECTIONS_H

#include "externs.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *model_map_iter;

typedef struct model_map {
    struct model_impl_s *impl;
} model_map;

ZITI_FUNC size_t model_map_size(const model_map *map);

ZITI_FUNC void *model_map_set_key(model_map *m, const void *key, size_t key_len, const void *val);

ZITI_FUNC void *model_map_set(model_map *map, const char *key, const void *val);

ZITI_FUNC void *model_map_setl(model_map *map, long key, const void *val);

ZITI_FUNC void *model_map_get_key(const model_map *map, const void *key, size_t key_len);

ZITI_FUNC void *model_map_get(const model_map *map, const char *key);

ZITI_FUNC void *model_map_getl(const model_map *map, long key);

ZITI_FUNC void *model_map_remove_key(model_map *map, const void *key, size_t key_len);

ZITI_FUNC void *model_map_remove(model_map *map, const char *key);

ZITI_FUNC void *model_map_removel(model_map *map, long key);

ZITI_FUNC void model_map_clear(model_map *map, void (*val_free_func)(void *));

ZITI_FUNC model_map_iter model_map_iterator(const model_map *map);

ZITI_FUNC const char *model_map_it_key(model_map_iter it);

ZITI_FUNC const void *model_map_it_key_s(model_map_iter it, size_t *key_len);

ZITI_FUNC long model_map_it_lkey(model_map_iter it);

ZITI_FUNC void *model_map_it_value(model_map_iter it);

ZITI_FUNC model_map_iter model_map_it_next(model_map_iter it);

ZITI_FUNC model_map_iter model_map_it_remove(model_map_iter it);

#define line_var(v) var(v,__LINE__)
#define var(x, y) _var(x,y)
#define _var(x,y) x ## y

#ifdef __cplusplus
#define z_typeof(v) decltype(v)
#else
#define z_typeof(v) __typeof__(v)
#endif

#define MODEL_MAP_FOREACH(k, v, map) \
model_map_iter line_var(e);\
for (line_var(e) = model_map_iterator(map), \
     (k) = (z_typeof(k))(uintptr_t)model_map_it_key(line_var(e)), \
     (v) = (z_typeof(v))model_map_it_value(line_var(e)),          \
     line_var(e) = model_map_it_next(line_var(e)); \
     (k) != NULL; \
     (k) = (z_typeof(k))(uintptr_t)model_map_it_key(line_var(e)), \
     (v) = (z_typeof(v))model_map_it_value(line_var(e)),          \
     line_var(e) = model_map_it_next(line_var(e))\
     )

#define MODEL_MAP_FOR(it, m)\
model_map_iter line_var(itn) = model_map_it_next(model_map_iterator(&(m)));\
for(model_map_iter it = model_map_iterator(&(m));                          \
    (it) != NULL;           \
    (it) = line_var(itn), line_var(itn) = model_map_it_next(line_var(itn)))

typedef struct model_list_s {
    struct model_list_impl_s *impl;
} model_list;

typedef void *model_list_iter;

ZITI_FUNC size_t model_list_size(const model_list *l);

// insert at the head
ZITI_FUNC void model_list_push(model_list *l, const void *el);

// append to the end
ZITI_FUNC void model_list_append(model_list *l, const void *el);

// remove from the head
ZITI_FUNC void *model_list_pop(model_list *l);

ZITI_FUNC const void *model_list_head(const model_list *l);

ZITI_FUNC void model_list_clear(model_list *l, void (*clear_f)(void *));

ZITI_FUNC model_list_iter model_list_iterator(model_list *l);

ZITI_FUNC model_list_iter model_list_it_next(model_list_iter it);

ZITI_FUNC model_list_iter model_list_it_remove(model_list_iter it);

ZITI_FUNC const void *model_list_it_element(model_list_iter it);

#define MODEL_LIST_FOR(it, m)\
model_list_iter line_var(itn) = model_list_it_next(model_list_iterator(&(m))); \
for(model_list_iter it = model_list_iterator(&(m)); (it) != NULL;              \
(it) = line_var(itn), line_var(itn) = model_list_it_next(line_var(itn)))


#define MODEL_LIST_FOREACH(el, list) \
model_list_iter line_var(it);    \
for(line_var(it) = model_list_iterator((model_list*)&(list)); \
line_var(it) != NULL && ((el) = (z_typeof(el))model_list_it_element(line_var(it)), true);                                 \
line_var(it) = model_list_it_next(line_var(it)))

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_MODEL_COLLECTIONS_H
