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


#ifndef ZITI_SDK_MODEL_MAP_H
#define ZITI_SDK_MODEL_MAP_H

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

ZITI_FUNC void *model_map_set_key(model_map *m, const void *key, size_t key_len, void *val);

ZITI_FUNC void *model_map_set(model_map *map, const char *key, void *val);

ZITI_FUNC void *model_map_setl(model_map *map, long key, void *val);

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

#define var(x, y) x##y

#define MODEL_MAP_FOREACH_l(k, v, map, line) \
model_map_iter var(e, line);\
for (var(e,line) = model_map_iterator(map), k = model_map_it_key(var(e,line)), v = model_map_it_value(var(e,line)); \
     var(e,line) != NULL; \
     var(e,line) = model_map_it_next(var(e,line)), k = model_map_it_key(var(e,line)), v = model_map_it_value(var(e,line)))

#define MODEL_MAP_FOREACH(k, v, map) MODEL_MAP_FOREACH_l(k, v, map, __LINE__)

#define MODEL_MAP_FOR(it, m) for(model_map_iter it = model_map_iterator(&(m)); (it) != NULL; (it) = model_map_it_next(it))

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_MODEL_MAP_H
