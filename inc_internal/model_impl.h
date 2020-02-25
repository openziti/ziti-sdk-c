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


#ifndef ZITI_SDK_MODEL_IMPL_H
#define ZITI_SDK_MODEL_IMPL_H

#include <stdlib.h>
#include <stdio.h>

#define cast_array(t) void**
#define cast_ptr(t) t*
#define cast_none(t) t

#define parse_field(n, type, mod, path) obj->n = ( mod(type) ) parse_##mod(json, json_len, "$." #path, (parse_func)parse_##type);
#define free_field(f, type, mod, _) free_##mod((cast_##mod(type))obj->f, free_##type);
#define dump_field(f, type, mod, _) dump_##mod((void*)obj->f, #f, (dump_func)dump_##type, ind + 2);

#define FROM_JSON(type, model) type* parse_##type(const char* json, int json_len){\
type *obj = calloc(1, sizeof(type));\
model(parse_field)\
return obj;\
}

#define FROM_JSON_ARR(type) type** parse_##type##_array(const char* json, int json_len){\
return (type**)parse_array(json, json_len, "$", (parse_func)parse_##type); \
}

#define FREE_MODEL(type, model) void free_##type(type *obj) {\
if (obj != NULL) {\
model(free_field)\
free(obj);\
}\
}

#define FREE_MODEL_ARR(type) void free_##type##_array(type **arr) {\
    type **pptr; \
    for (pptr = arr; *pptr != NULL; pptr++) {\
        free_##type(*pptr);\
    }\
}

#define FREE_MODEL_LIST(type) void free_##type##_list(type##_list *l) {\
    type *it; \
    while(!LIST_EMPTY(l)){\
        it = LIST_FIRST(l);\
        LIST_REMOVE(it, _next);\
        free_##type(it); \
    }\
}

#define DUMP_MODEL(type, model) int dump_##type(type *obj, int ind) {\
printf("%*.*s" #type "\n", ind, ind, " ");\
model(dump_field)\
return 0;\
}

#define MODEL_IMPL(type, model) \
FROM_JSON(type, model) \
FROM_JSON_ARR(type) \
FREE_MODEL(type, model) \
FREE_MODEL_ARR(type) \
FREE_MODEL_LIST(type) \
DUMP_MODEL(type, model)



typedef int (*dump_func)(void *, int);
typedef void *(*parse_func)(const char *, int);
typedef void (*free_func)(void *);

#define free_none(f, func) func(f)

#ifdef __cplusplus
extern "C" {
#endif

int parse_bool(const char *json, int json_len);

int parse_int(const char *json, int json_len);

string parse_string(const char *json, int json_len);

timeval_t *parse_timeval_t(const char *json, int json_len);

void *parse_none(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int));

void *parse_ptr(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int));

void **parse_array(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int));

int dump_timeval_t(struct timeval *t);

int dump_string(const char *s, int len);

int dump_int(int i, int len);

int dump_bool(bool v, int len);

int dump_none(void *obj, char *name, dump_func func, int indent);

int dump_ptr(void *obj, char *name, int (*dump_func)(void *o, int ind), int ind);

int dump_array(void **arr, char *name, int (*dump_func)(void *o, int ind), int ind);

void free_int(int i);

void free_bool(bool i);

void free_string(string s);

void free_timeval_t(struct timeval *t);

void free_ptr(void *obj, free_func f);

void free_array(void **arr, free_func f);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_MODEL_IMPL_H
