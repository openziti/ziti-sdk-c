// Copyright (c) 2020-2022.  NetFoundry Inc.
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


#ifndef ZITI_SDK_MODEL_SUPPORT_H
#define ZITI_SDK_MODEL_SUPPORT_H

#ifndef __cplusplus
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#ifndef _MSC_VER
#include <sys/time.h>
#endif
#endif

#include <string.h>

#ifdef _MSC_VER
#define hide_MSC_VER _MSC_VER
#undef _MSC_VER
#endif
#include <json-c/json.h>
#ifdef hide_MSC_VER
#define _MSC_VER hide_MSC_VER
#undef hide_MSC_VER
#endif

#include "externs.h"
#include "model_collections.h"
#include "types.h"

#if !defined(__DEFINED_ssize_t) && !defined(__ssize_t_defined)
#if _WIN32
typedef intptr_t ssize_t;
#define __DEFINED_ssize_t
#define __ssize_t_defined
#else
#include <unistd.h>
#endif
#endif

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

#define MODEL_VISIBILITY

#define MODEL_JSON_COMPACT 0x1

#define none(t) t
#define ptr(t)  t*
#define array(t) t##_array
#define map(t)  model_map
#define list(t) model_list

#define FIELD_DECL(name, type, mod, path, _) mod(type) name;

#define DECLARE_MODEL(type, model) \
typedef struct type##_s {\
model(FIELD_DECL, type) \
} type;\
DECLARE_MODEL_FUNCS(type)

#define DECLARE_MODEL_FUNCS(T) \
typedef T ** T##_array; \
MODEL_VISIBILITY const type_meta* get_##T##_meta();\
static inline ptr(T) alloc_##T(){ return (ptr(T))model_alloc(get_##T##_meta()); }\
static inline void free_##T(ptr(T) v) { model_free(v, get_##T##_meta()); }     \
static inline void free_##T##_ptr(ptr(T) v) { model_free(v, get_##T##_meta()); free(v); }; \
static inline int cmp_##T(const ptr(T) lh, const ptr(T) rh) { return model_cmp(lh, rh, get_##T##_meta()); } \
MODEL_VISIBILITY void free_##T##_array(array(T) *ap);\
MODEL_VISIBILITY int parse_##T(ptr(T) v, const char* json, size_t len);\
MODEL_VISIBILITY int parse_##T##_ptr(ptr(T) *p, const char* json, size_t len);\
MODEL_VISIBILITY int parse_##T##_array(array(T) *a, const char* json, size_t len); \
MODEL_VISIBILITY int parse_##T##_list(list(T) *l, const char* json, size_t len); \
static inline ssize_t T##_to_json_r(const ptr(T) v, int flags, char *outbuf, size_t max) { return model_to_json_r(v, get_##T##_meta(), flags, outbuf, max); } \
static inline char* T##_to_json(const ptr(T) v, int flags, size_t *len) { return model_to_json(v, get_##T##_meta(), flags, len); }   \
static inline int T##_from_json(ptr(T) v, struct json_object *j) { return model_from_json(v, j, get_##T##_meta()); } \
static inline int T##_ptr_from_json(ptr(T) *v, struct json_object *j) {      \
    if (j == NULL || json_object_get_type(j) == json_type_null) { *v = NULL; return 0; }  \
    *v = alloc_##T();          \
    int rc = model_from_json(*v, j, get_##T##_meta());                              \
    if (rc != 0) { free_##T##_ptr(*v); *v = NULL;}          \
    return rc;\
} \
static inline int T##_list_from_json(list(T) *l, struct json_object *j) { return model_list_from_json(l, j, get_##T##_meta()); } \
static inline int T##_array_from_json(array(T) *a, struct json_object *j) { return model_array_from_json((void***)a, j, get_##T##_meta()); }

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
    };                          \
static type_meta type##_META = { \
.name = #type, \
.size = sizeof(type),\
.field_count = sizeof(type##_FIELDS) / sizeof(field_meta),\
.fields = type##_FIELDS,\
};                              \
IMPL_MODEL_FUNCS(type)

#define IMPL_MODEL_FUNCS(T)  \
const type_meta* get_##T##_meta() { return &T##_META; }\
int parse_##T(ptr(T) v, const char* json, size_t len) { return model_parse(v, json, len, get_##T##_meta()); } \
int parse_##T##_ptr(ptr(T) *p, const char* json, size_t len) {\
*p = (ptr(T))calloc(1, sizeof(T)); \
int rc = parse_##T(*p, json, len); \
if (rc < 0) { free_##T(*p); free(*p); *p = NULL; } \
return rc;\
}\
int parse_##T##_array(array(T) *a, const char *json, size_t len) { return model_parse_array((void***)a, json, len, get_##T##_meta()); }\
int parse_##T##_list(list(T) *l, const char *json, size_t len) { return model_parse_list(l, json, len, get_##T##_meta()); }\
void free_##T##_array(array(T) *ap) { model_free_array((void***)ap, get_##T##_meta()); }

#ifdef __cplusplus
extern "C" {
#endif
typedef const char *model_string;

typedef model_string *model_string_array;
typedef int64_t model_number;
typedef model_number **model_number_array;
typedef bool model_bool;
typedef model_bool **model_bool_array;
typedef char *json;

enum _field_mod {
    none_mod,
    ptr_mod,
    array_mod,
    map_mod,
    list_mod,
};

typedef struct field_meta {
    const char *name;
    const char *path;
    size_t offset;
    enum _field_mod mod;

    const struct type_meta *(*meta)();
} field_meta;

typedef int (*_parse_f)(void *obj, const char *json, void *tok);
typedef int (*_to_json_f)(const void *obj, void *buf, int indent, int flags);
typedef void (*_free_f)(void *obj);
typedef int (*_cmp_f)(const void *lh, const void *rh);

typedef int (*from_json_func)(void *obj, struct json_object *json, const struct type_meta *meta);
typedef struct json_object* (*to_json_func)(const void *obj);

typedef struct type_meta {
    const char *name;
    size_t size;
    const int field_count;
    field_meta *fields;
    _cmp_f comparer;
    _to_json_f jsonifier;
    _free_f destroyer;
    from_json_func from_json;
    to_json_func to_json;
} type_meta;

#define MODEL_PARSE_INVALID (-2)
#define MODEL_PARSE_PARTIAL (-3)

ZITI_FUNC void* model_alloc(const type_meta *meta);
ZITI_FUNC void model_free(void *obj, const type_meta *meta);

ZITI_FUNC void model_free_array(void ***ap, const type_meta *meta);

ZITI_FUNC int model_cmp(const void *lh, const void *rh, const type_meta *meta);

ZITI_FUNC int model_parse(void *obj, const char *json, size_t len, const type_meta *meta);

ZITI_FUNC int model_from_json(void *obj, struct json_object *json, const type_meta *meta);
ZITI_FUNC int model_list_from_json(model_list *l, struct json_object *json, const type_meta *meta);
ZITI_FUNC int model_array_from_json(void ***obj, struct json_object *json, const type_meta *meta);

ZITI_FUNC int model_parse_array(void ***arp, const char *json, size_t len, const type_meta *meta);

ZITI_FUNC int model_parse_list(model_list *list, const char *json, size_t len, const type_meta *meta);

ZITI_FUNC char *model_to_json(const void *obj, const type_meta *meta, int flags, size_t *len);

ZITI_FUNC ssize_t model_to_json_r(const void *obj, const type_meta *meta, int flags, char *outbuf, size_t max);

ZITI_FUNC extern const type_meta *get_model_bool_meta();

ZITI_FUNC extern const type_meta *get_model_number_meta();

ZITI_FUNC extern const type_meta *get_model_string_meta();

ZITI_FUNC extern const type_meta *get_timestamp_meta();

ZITI_FUNC extern const type_meta *get_json_meta();

ZITI_FUNC extern const type_meta *get_duration_meta();

typedef struct timeval timestamp;

int model_map_compare(const model_map *lh, const model_map *rh, const type_meta *m);

typedef enum {
    tag_null,
    tag_bool,
    tag_number,
    tag_string
} tag_type;

typedef struct {
    tag_type type;
    union {
        model_bool bool_value;
        model_number num_value;
        model_string string_value;
    };
} tag;

ZITI_FUNC const type_meta *get_tag_meta();

ZITI_FUNC int enum_from_json(void *ptr, struct json_object *j, const void *enum_type);
ZITI_FUNC int json_enum(const void *ptr, void *buf, int indent, int flags, const void *enum_type);
ZITI_FUNC struct json_object* enum_to_json(const void* ptr, const void *enum_type);


#define mk_enum2(v,t) t##_##v
#define mk_enum3(v,n,t) t##_##v
#define enum_f2(v, t) const t v
#define enum_f3(v, n, t) const t v

#define get_ovrd(_1, _2, _3, NAME, ...) NAME

#define mk_enum(...) get_ovrd(__VA_ARGS__, mk_enum3, mk_enum2)(__VA_ARGS__),
#define enum_field(...) get_ovrd(__VA_ARGS__, enum_f3, enum_f2)(__VA_ARGS__);

#define DECLARE_ENUM(Enum, Values) \
enum Enum {                        \
Enum##_Unknown = 0,                \
Values(mk_enum, Enum)              \
};                                 \
typedef enum Enum Enum;            \
typedef Enum **Enum##_array;       \
struct Enum##_s {                  \
const char* (*name)(int v);                       \
Enum (*value_of)(const char* n);                  \
Enum (*value_ofn)(const char* s, size_t n);       \
Values(enum_field, Enum)                          \
};                                 \
MODEL_VISIBILITY const type_meta* get_##Enum##_meta();\
extern const struct Enum##_s Enum##s;

#define get_value_of_ovrd(_1, _2, _3, _4, _5, NAME, ...) NAME
#define enum_value_of4(v, t, str, len) if(strncmp(str,#v,len) == 0){return (t)t##s.v;}
#define enum_value_of5(n, v, t, str, len) if(strncmp(str,v,len) == 0){return (t)t##s.n;}
#define enum_value_of(...) get_value_of_ovrd(__VA_ARGS__, enum_value_of5, enum_value_of4)(__VA_ARGS__)

#define enum_c2(v,t)  case t##_##v: return #v
#define enum_c3(n,v,t) case t##_##n: return v
#define enum_case(...)  get_ovrd(__VA_ARGS__, enum_c3, enum_c2)(__VA_ARGS__);

#define enum_field_v2(v,t) .v = t##_##v
#define enum_field_v3(n,v,t) .n = t##_##n

#define enum_field_val(...) get_ovrd(__VA_ARGS__, enum_field_v3, enum_field_v2)(__VA_ARGS__),
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
return ((lh) ? (*lh) : Enum##_Unknown) - ((rh) ? (*rh) : Enum##_Unknown); \
};\
static int Enum##_json(const ptr(Enum) e, void *buf, int indent, int flags) {     \
return json_enum(e, buf, indent, flags, &Enum##s);                              \
}                               \
static int Enum##_from_json(ptr(Enum) e, struct json_object *j, type_meta *m) {    \
                                return enum_from_json(e, j, &Enum##s); \
}                               \
static struct json_object* Enum##_to_json(const ptr(Enum) e) {         \
                                return enum_to_json(e, &Enum##s); \
}\
static type_meta Enum##_meta = {\
        .name = #Enum,        \
        .size = sizeof(Enum), \
        .field_count = 0,     \
        .fields = NULL,       \
        .comparer = (_cmp_f) cmp_##Enum, \
        .jsonifier = (_to_json_f) Enum##_json,  \
        .destroyer = NULL, \
        .from_json = (from_json_func) Enum##_from_json,         \
        .to_json = (to_json_func) Enum##_to_json, \
        };           \
const type_meta* get_##Enum##_meta() { return &Enum##_meta; }\

#if __cplusplus
}
#endif

#endif //ZITI_SDK_MODEL_SUPPORT_H
