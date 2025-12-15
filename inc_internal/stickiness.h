// Copyright (c) 2022-2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ZITI_SDK_STICKINESS_H
#define ZITI_SDK_STICKINESS_H

#include <stc/cstr.h>
#define nsafe(s) ((s) ? (s) : "")

typedef struct sticky_key {
    cstr service;
    cstr id;
    cstr target;
} sticky_key;

static inline sticky_key sticky_key_make(cstr_raw service, cstr_raw id, cstr_raw target)  {
    return (sticky_key){
        .service = cstr_from(service),
        .id = cstr_from(id),
        .target = cstr_from(target)
    };
}

static inline void sticky_key_drop(sticky_key *key)  {
    cstr_drop(&key->service);
    cstr_drop(&key->id);
    cstr_drop(&key->target);
}

static inline sticky_key sticky_key_clone(sticky_key key)  {
    return (sticky_key){
        .service = cstr_clone(key.service),
        .id = cstr_clone(key.id),
        .target = cstr_clone(key.target),
    };
}

typedef struct {
    const char *service;
    const char *id;
    const char *target;
} sticky_key_raw;

static inline sticky_key sticky_key_from(sticky_key_raw raw) {
    return sticky_key_make(nsafe(raw.service), nsafe(raw.id), nsafe(raw.target));
}

static inline sticky_key_raw sticky_key_toraw(const sticky_key *key) {
    return (sticky_key_raw){
        .service = cstr_str(&key->service),
        .id = cstr_str(&key->id),
        .target = cstr_str(&key->target),
    };
}

static inline int sticky_key_raw_eq(const sticky_key_raw *a, const sticky_key_raw *b) {
    return strcmp(nsafe(a->service), nsafe(b->service)) == 0 &&
        strcmp(nsafe(a->id), nsafe(b->id)) == 0 &&
            strcmp(nsafe(a->target), nsafe(b->target)) == 0;
}

static inline size_t sticky_key_raw_hash(const sticky_key_raw *r) {
    return c_hash_mix(
        c_hash_str(nsafe(r->service)),
        c_hash_str(nsafe(r->id)),
        c_hash_str(nsafe(r->target)));
}

// type: sticky_tokens_map = hashmap<sticky_key, cstr>
#define i_type sticky_tokens_map
#define i_keypro sticky_key
#define i_valpro cstr
#include <stc/hmap.h>

#endif // ZITI_SDK_STICKINESS_H
