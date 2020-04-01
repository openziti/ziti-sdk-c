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

#include <uv_mbed/queue.h>


#define none(t) t
#define ptr(t)  t*
#define array(t) t##_array

#define FIELD_DECL(name, type, mod, path, _) mod(type) name;

#define DECLARE_MODEL(type, model) \
typedef struct type##_s {\
model(FIELD_DECL, type) \
LIST_ENTRY(type##_s) _next; \
} type;\
typedef type ** type##_array; \
typedef LIST_HEAD(type##_l, type##_s) type##_list;\
ptr(type) alloc_##type();\
void free_##type(type *v); \
void free_##type##_array(array(type) *ap);\
int parse_##type(ptr(type) v, const char* json, int len);\
int parse_##type##_ptr(ptr(type) *p, const char* json, int len);\
int parse_##type##_array(array(type) *a, const char* json, int len);\
void dump_##type(type *v, int);

#define gen_field_meta(n, memtype, modifier, p, partype) {\
.name = #n, \
.path = #p, \
.offset = offsetof(partype,n), \
.mod = modifier##_mod, \
.meta = &memtype##_META, \
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
int parse_##type(ptr(type) v, const char* json, int len) { return model_parse(v, json, len, &type##_META); } \
int parse_##type##_ptr(ptr(type) *p, const char* json, int len) {\
*p = (type *)calloc(1, type##_META.size); \
return parse_##type(*p, json, len); \
}\
int parse_##type##_array(array(type) *a, const char *json, int len) { return model_parse_array((void***)a, json, len, &type##_META); }\
ptr(type) alloc_##type() { return (ptr(type))calloc(1, sizeof(type)); } \
void free_##type(type *v) { model_free(v, &type##_META); } \
void free_##type##_array(array(type) *ap) { model_free_array((void***)ap, &type##_META); }\
void dump_##type(type *v, int off) { model_dump(v, off, &type##_META);}

#ifdef __cplusplus
extern "C" {
#endif
typedef char *string;
typedef char **string_array;
typedef int **int_array;
typedef bool **bool_array;

enum _field_mod {
    none_mod,
    ptr_mod,
    array_mod
};

typedef struct field_meta {
    const char *name;
    const char *path;
    size_t offset;
    enum _field_mod mod;
    struct type_meta *meta;
} field_meta;

typedef int (*_parse_f)(void *obj, const char *json, void *tok);

typedef void (*_free_f)(void *obj);

typedef struct type_meta {
    const char *name;
    size_t size;
    const int field_count;
    field_meta *fields;
    _parse_f parser;
    _free_f destroyer;
} type_meta;

void model_free(void *obj, type_meta *meta);
void model_free_array(void ***ap, type_meta *meta);
void model_dump(void *obj, int off, type_meta *meta);

int model_parse(void *obj, const char *json, size_t len, type_meta *meta);
int model_parse_array(void ***arp, const char *json, size_t len, type_meta *meta);

extern type_meta bool_META;
extern type_meta int_META;
extern type_meta string_META;
extern type_meta timestamp_META;

typedef struct timeval timestamp;
#if __cplusplus
}
#endif

#endif //ZITI_SDK_MODEL_SUPPORT_H
