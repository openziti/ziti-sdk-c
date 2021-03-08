/*
Copyright (c) 2020 NetFoundry, Inc.

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


#ifndef ZITI_SDK_MODEL_SUPPORT_H
#define ZITI_SDK_MODEL_SUPPORT_H

#ifndef __cplusplus
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#endif

#include <string.h>

#include "externs.h"

/**
 * set of macros to help generate struct and function for our model;
 *
 * - DECLARE_MODEL(type, model_def) :
 *    `type` name of the struct,
 *    `model_def` - marco defining fields for the model
 *
 *    NOTE: matching IMPL_MODEL macro in model.c is used to generate function implementations
 *
 * Fields are defined with name, type, type modifier, and path (for JSON mapping)
 *   type could be primitives (bool, int, string, timestamp - string in ISO8601 format) or other model types
 *   type modifier: none, ptr, array
 *
 * The following functions are generated:
 * - int parse_TYPE(TYPE*, json, len) -- parses json into an allocated struct, returns 0 if successful, -1 otherwise
 *
 * - void free_TYPE(TYPE *obj)   -- frees struct
 *
 * - int dump_TYPE(TYPE *obj, int indent) -- prints the struct to `stdout`,
 *              `indent` is used for printing nested model objects
 */

#define MODEL_API

#define none(t) t
#define ptr(t)  t*
#define array(t) t##_array
#define map(t)  model_map

#define FIELD_DECL(name, type, mod, path, _) mod(type) name;

#define DECLARE_MODEL(type, model) \
typedef struct type##_s {\
model(FIELD_DECL, type) \
} type;\
typedef type ** type##_array; \
MODEL_API type_meta* get_##type##_meta();\
MODEL_API ptr(type) alloc_##type();\
MODEL_API void free_##type(type *v); \
MODEL_API int cmp_##type(const type *lh, const type *rh); \
MODEL_API void free_##type##_array(array(type) *ap);\
MODEL_API int parse_##type(ptr(type) v, const char* json, size_t len);\
MODEL_API int parse_##type##_ptr(ptr(type) *p, const char* json, size_t len);\
MODEL_API int parse_##type##_array(array(type) *a, const char* json, size_t len);\
MODEL_API int json_from_##type(const ptr(type) v, char *buf, size_t maxlen, size_t *len);

#define gen_field_meta(n, memtype, modifier, p, partype) {\
.name = #n, \
.path = #p, \
.offset = offsetof(partype,n), \
.mod = modifier##_mod, \
.meta = get_##memtype##_meta, \
},

#define IMPL_MODEL(type, model) \
static field_meta type##_FIELDS[] =  {\
    model(gen_field_meta, type) \
    }; \
static type_meta type##_META = { \
.name = #type, \
.size = sizeof(type),\
.field_count = sizeof(type##_FIELDS) / sizeof(field_meta),\
.fields = type##_FIELDS,\
};\
type_meta* get_##type##_meta() { return &type##_META; }\
int parse_##type(ptr(type) v, const char* json, size_t len) { return model_parse(v, json, len, &type##_META); } \
int parse_##type##_ptr(ptr(type) *p, const char* json, size_t len) {\
*p = (type *)calloc(1, type##_META.size); \
int rc = parse_##type(*p, json, len); \
if (rc < 0) { free_##type(*p); free(*p); *p = NULL; } \
return rc;\
}\
int parse_##type##_array(array(type) *a, const char *json, size_t len) { return model_parse_array((void***)a, json, len, &type##_META); }\
ptr(type) alloc_##type() { return (ptr(type))calloc(1, sizeof(type)); } \
int cmp_##type(const type *lh, const type *rh) { return model_cmp(lh, rh, &type##_META); }\
void free_##type(type *v) { model_free(v, &type##_META); } \
void free_##type##_array(array(type) *ap) { model_free_array((void***)ap, &type##_META); }\
MODEL_API int json_from_##type(const ptr(type) v, char *json, size_t maxlen, size_t *len)\
{ return model_to_json(v, &type##_META, 0, json, maxlen, len); }


#ifdef __cplusplus
extern "C" {
#endif
typedef char *string;
typedef char **string_array;
typedef int **int_array;
typedef bool **bool_array;
typedef char *json;

enum _field_mod {
    none_mod,
    ptr_mod,
    array_mod,
    map_mod
};

typedef struct field_meta {
    const char *name;
    const char *path;
    size_t offset;
    enum _field_mod mod;

    struct type_meta *(*meta)();
} field_meta;

typedef int (*_parse_f)(void *obj, const char *json, void *tok);

typedef int (*_to_json_f)(const void *obj, int indent, char *json, size_t max, size_t *len);

typedef void (*_free_f)(void *obj);
typedef int (*_cmp_f)(const void *lh, const void *rh);

typedef struct type_meta {
    const char *name;
    size_t size;
    const int field_count;
    field_meta *fields;
    _cmp_f comparer;
    _parse_f parser;
    _to_json_f jsonifier;
    _free_f destroyer;
} type_meta;

ZITI_FUNC void model_free(void *obj, type_meta *meta);

ZITI_FUNC void model_free_array(void ***ap, type_meta *meta);

ZITI_FUNC int model_cmp(const void *lh, const void *rh, type_meta *meta);

ZITI_FUNC int model_parse(void *obj, const char *json, size_t len, type_meta *meta);

ZITI_FUNC int model_parse_array(void ***arp, const char *json, size_t len, type_meta *meta);

ZITI_FUNC int model_to_json(const void *obj, type_meta *meta, int indent, char *buf, size_t maxlen, size_t *len);

ZITI_FUNC extern type_meta *get_bool_meta();

ZITI_FUNC extern type_meta *get_int_meta();

ZITI_FUNC extern type_meta *get_string_meta();

ZITI_FUNC extern type_meta *get_timestamp_meta();

ZITI_FUNC extern type_meta *get_json_meta();

ZITI_FUNC extern type_meta *get_model_map_meta();

typedef struct timeval timestamp;


typedef void *model_map_iter;

typedef struct model_map {
    struct model_impl_s *impl;
} model_map;

ZITI_FUNC size_t model_map_size(model_map *map);

ZITI_FUNC void *model_map_set(model_map *map, const char *key, void *val);

ZITI_FUNC void *model_map_get(model_map *map, const char *key);

ZITI_FUNC void *model_map_remove(model_map *map, const char *key);

ZITI_FUNC void model_map_clear(model_map *map, _free_f val_free_func);

ZITI_FUNC model_map_iter model_map_iterator(model_map *map);

ZITI_FUNC const char *model_map_it_key(model_map_iter *it);

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


typedef enum {
    tag_null,
    tag_bool,
    tag_number,
    tag_string
} tag_type;

typedef struct {
    tag_type type;
    union {
        bool bool_value;
        int num_value;
        string string_value;
    };
} tag;

ZITI_FUNC type_meta *get_tag_meta();

ZITI_FUNC int parse_enum(void *ptr, const char *json, void *tok, const void *enum_type);
ZITI_FUNC int json_enum(const void *ptr, char *json, size_t max, size_t *len, const void *enum_type);

#define mk_enum(v,t) t##_##v,
#define enum_field(v,t) const t v;

#define DECLARE_ENUM(Enum, Values) \
enum Enum {                             \
Values(mk_enum, Enum)                   \
Enum##_Unknown = -1,                    \
};                                 \
typedef enum Enum Enum;\
struct Enum##_s { \
const char* (*name)(int v);                       \
Enum (*value_of)(const char* n);                  \
Enum (*value_ofn)(const char* s, size_t n);       \
Values(enum_field, Enum)                          \
};                                 \
MODEL_API type_meta* get_##Enum##_meta();\
extern const struct Enum##_s Enum##s;

#define enum_value_of(v,t,s,n) if (strncmp(s,#v,n) == 0) return (t)t##s.v;
#define enum_case(v,t)  case t##_##v: return #v;
#define enum_field_val(v,t) .v = t##_##v,
#define IMPL_ENUM(Enum, Values) \
static const char* Enum##_name(int v) { \
switch (v) { \
Values(enum_case,Enum)\
default: return "unknown " #Enum; \
}                                \
}\
Enum Enum##_value_ofn(const char* s, size_t n) {\
Values(enum_value_of, Enum, s, n)  \
return Enum##_Unknown;          \
}                               \
Enum Enum##_value_of(const char* s) {\
return Enum##_value_ofn(s, strlen(s));     \
}                               \
                                \
const struct Enum##_s Enum##s = {  \
.name = Enum##_name,            \
.value_of = Enum##_value_of,    \
.value_ofn = Enum##_value_ofn,    \
Values(enum_field_val,Enum)\
};                              \
static int cmp_##Enum(const ptr(Enum) lh, const ptr(Enum) rh) { \
return get_int_meta()->comparer(lh, rh);               \
};\
static int parse_##Enum(ptr(Enum) e, const char* json, void *tok) {     \
return parse_enum(e, json, tok, &Enum##s);                              \
}\
static int Enum##_json(const ptr(Enum) e, int indent, char *json, size_t max, size_t *len) {     \
return json_enum(e, json, max, len, &Enum##s);                              \
}\
static type_meta Enum##_meta = {\
        .size = sizeof(int), \
        .comparer = (_cmp_f) cmp_##Enum, \
        .parser = (_parse_f) parse_##Enum, \
        .jsonifier = (_to_json_f) Enum##_json, \
        };           \
type_meta* get_##Enum##_meta() { return &Enum##_meta; }\


#if __cplusplus
}
#endif

#endif //ZITI_SDK_MODEL_SUPPORT_H
