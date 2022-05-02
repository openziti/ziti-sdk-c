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
#include "model_map.h"

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

#define MODEL_API

#define MODEL_JSON_COMPACT 0x1

#define none(t) t
#define ptr(t)  t*
#define array(t) t##_array
#define map(t)  model_map

#define FIELD_DECL(name, type, mod, path, _) mod(type) name;

#define DECLARE_MODEL(type, model) \
typedef struct type##_s {\
model(FIELD_DECL, type) \
} type;\
DECLARE_MODEL_FUNCS(type)

#define DECLARE_MODEL_FUNCS(type) \
typedef type ** type##_array; \
MODEL_API type_meta* get_##type##_meta();\
MODEL_API ptr(type) alloc_##type();\
MODEL_API void free_##type(type *v); \
MODEL_API int cmp_##type(const type *lh, const type *rh); \
MODEL_API void free_##type##_array(array(type) *ap);\
MODEL_API int parse_##type(ptr(type) v, const char* json, size_t len);\
MODEL_API int parse_##type##_ptr(ptr(type) *p, const char* json, size_t len);\
MODEL_API int parse_##type##_array(array(type) *a, const char* json, size_t len); \
/** write to fixed buffer */                                 \
MODEL_API ssize_t type##_to_json_r(const ptr(type) v, int flags, char *outbuf, size_t max); \
MODEL_API char* type##_to_json(const ptr(type) v, int flags, size_t *len);

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

#define IMPL_MODEL_FUNCS(type)  \
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
void free_##type(ptr(type) v) { model_free(v, &type##_META); } \
void free_##type##_array(array(type) *ap) { model_free_array((void***)ap, &type##_META); }                      \
MODEL_API ssize_t type##_to_json_r(const ptr(type) v, int flags, char *outbuf, size_t max) {                    \
return model_to_json_r(v, &type##_META, flags, outbuf, max); } \
char* type##_to_json(const ptr(type) v, int flags, size_t *len) { return model_to_json(v, &type##_META, flags, len); }


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

typedef int (*_to_json_f)(const void *obj, void *buf, int indent, int flags);

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

#define MODEL_PARSE_INVALID (-2)
#define MODEL_PARSE_PARTIAL (-3)

ZITI_FUNC void model_free(void *obj, type_meta *meta);

ZITI_FUNC void model_free_array(void ***ap, type_meta *meta);

ZITI_FUNC int model_cmp(const void *lh, const void *rh, type_meta *meta);

ZITI_FUNC int model_parse(void *obj, const char *json, size_t len, type_meta *meta);

ZITI_FUNC int model_parse_array(void ***arp, const char *json, size_t len, type_meta *meta);

ZITI_FUNC char *model_to_json(const void *obj, const type_meta *meta, int flags, size_t *len);

ZITI_FUNC ssize_t model_to_json_r(const void *obj, const type_meta *meta, int flags, char *outbuf, size_t max);

ZITI_FUNC extern type_meta *get_bool_meta();

ZITI_FUNC extern type_meta *get_int_meta();

ZITI_FUNC extern type_meta *get_string_meta();

ZITI_FUNC extern type_meta *get_timestamp_meta();

ZITI_FUNC extern type_meta *get_json_meta();

ZITI_FUNC extern type_meta *get_model_map_meta();

typedef struct timeval timestamp;

int model_map_compare(const model_map *lh, const model_map *rh, type_meta *m);

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
ZITI_FUNC int json_enum(const void *ptr, void *buf, int indent, int flags, const void *enum_type);

#define mk_enum(v,t) t##_##v,
#define enum_field(v,t) const t v;

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
MODEL_API type_meta* get_##Enum##_meta();\
extern const struct Enum##_s Enum##s;

#define call_f(f,args) f args
#define enum_value_of1(v, t, s, n) if(strncmp(s,#v,n) == 0){return (t)t##s.v;}
#define enum_value_of(v,...) call_f(enum_value_of1, (v, __VA_ARGS__))

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
static int Enum##_json(const ptr(Enum) e, void *buf, int indent, int flags) {     \
return json_enum(e, buf, indent, flags, &Enum##s);                              \
}\
static type_meta Enum##_meta = {\
        .name = #Enum,        \
        .size = sizeof(Enum), \
        .field_count = 0,     \
        .fields = NULL,       \
        .comparer = (_cmp_f) cmp_##Enum, \
        .parser = (_parse_f) parse_##Enum, \
        .jsonifier = (_to_json_f) Enum##_json, \
        };           \
type_meta* get_##Enum##_meta() { return &Enum##_meta; }\

#if __cplusplus
}
#endif

#endif //ZITI_SDK_MODEL_SUPPORT_H
