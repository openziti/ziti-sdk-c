/*
Copyright 2019-2020 NetFoundry, Inc.

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

#ifndef ZT_SDK_MODEL_H
#define ZT_SDK_MODEL_H

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <uv_mbed/queue.h>

#if _WIN32
#include <time.h>
#else
#include <sys/time.h>
#endif

/**
 * set of macros to help generate struct and function for our model;
 *
 * - DECLARE_MODEL(type, model_def) :
 *    `type` name of the struct,
 *    `model_def` - marco defining fields for the model
 *
 *    NOTE: matching MODEL_IMPL macro in model.c is used to generate function implementations
 *
 * Fields are defined with name, type, type modifier, and path (for JSON mapping)
 *   type could be primitives (bool, int, string) or other model types
 *   type modifier: none, ptr, arr (nested model types has to be used with ptr or arr)
 *   fields could be mapped from nested JSON structure with `.`(dot) notation.
 *
 * The following functions are generated:
 * - TYPE* parse_TYPE(json, len) -- parses json into an allocated struct
 *
 * - void free_TYPE(TYPE *obj)   -- frees struct
 *
 * - int dump_TYPE(TYPE *obj, int indent) -- prints the struct to `stdout`,
 *              `indent` is used for printing nested model objects
 */

#define FIELD_DECL(name, type, mod, path) mod(type) name;

/*
 * field type macros
 *
 * Nested model objects are supported as pointers and NULL-terminated arrays of pointers
 */
#define none(type) type
#define array(type) type##_array
#define ptr(type) type*


/*
 * Model declaration: struct type, and functions
 */
#define DECLARE_MODEL(type, model) \
typedef struct type##_s {\
model(FIELD_DECL) \
LIST_ENTRY(type##_s) _next; \
} type;\
typedef LIST_HEAD(type##_l, type##_s) type##_list;\
typedef type** type##_array; \
type* parse_##type(const char* json, int json_len);\
type** parse_##type##_array(const char* json, int json_len);\
void free_##type(type* type);\
void free_##type##_array(type** arr); \
void free_##type##_list(type##_list* l); \
int dump_##type(type* type, int len);

typedef char* string;
typedef string* string_array;
typedef struct timeval timeval_t;

#endif //ZT_SDK_MODEL_H
