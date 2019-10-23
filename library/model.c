/*
Copyright 2019 Netfoundry, Inc.

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
#define MJSON_API_ONLY
#include <mjson.h>


#include <stdbool.h>
#include "model.h"
#include <math.h>


//#define free_int(_)
//#define free_bool(_)

typedef int (*dump_func)(void *, int);
typedef void *(*parse_func)(const char *, int);
typedef void (*free_func)(void *);


void free_int(int i) {}
void free_bool(bool i) {}

void free_string(string s) {
    if (s != NULL) {
        free((void *) s);
    }
}

static string parse_string(const char *json, int json_len, const char *path) {
    const char *f;
    int n;
    string result = NULL;
    if (path != NULL && mjson_find(json, json_len, path, &f, &n) == MJSON_TOK_STRING) {
        result = calloc(1, n + 1);
        mjson_get_string(f, n, "$", result, n);
    }
    return result;
}

static int parse_bool(const char *json, int json_len, const char *path) {
    int result;
    int rc =  mjson_get_bool(json, json_len, path, &result);
    if (rc == 0) return false;
    return result;
}

static int parse_int(const char *json, int json_len, const char *path) {
    double result;
    if (mjson_get_number(json, json_len, path, &result)) {
        return (int)round(result);
    }
    return -1;
}

static void *parse_ptr(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int)) {
    const char *f;
    int n;
    if (mjson_find(json, json_len, path, &f, &n) == MJSON_TOK_OBJECT) {
        return parse_func(f, n);
    }
    return NULL;
}

static void **parse_array(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int)) {
    const char *arrjson;
    int arrjson_len;
    int array_len = 1;
    void **result = NULL;

    if (mjson_find(json, json_len, path, &arrjson, &arrjson_len) == MJSON_TOK_ARRAY) {
        result = calloc(array_len, sizeof(void *));
        int idx = 0;
        do {
            if (array_len <= idx) {
                array_len += 2;
                result = realloc(result, array_len * sizeof(void *));
            }
            char elem_path[24];
            sprintf(elem_path, "$[%d]", idx);
            const char *el_json;
            int el_len;
            enum mjson_tok tok = mjson_find(arrjson, arrjson_len, elem_path, &el_json, &el_len);
            if (tok != MJSON_TOK_INVALID) {
                result[idx] = parse_func(el_json, el_len);
                if (result[idx] == NULL) {
                    break;
                }
                idx++;
            }
            else {
                result[idx] = NULL;
                break;
            }
        } while (1);
    }
    return result;
}

#define free_none(f, func) func(f)

int dump_string(const char *s, int len) {
    printf("%s\n", s ? s : "<null>");
    return 0;
}

int dump_int(int i, int len) {
    printf("%d\n", i);
    return 0;
}

int dump_bool(bool v, int len) {
    printf("%s\n", v ? "true" : "false");
    return 0;
}

#define parse_none(json, len, path, func) func(json, len, path)



int dump_none(void *obj, char *name, dump_func func, int indent) {
    printf("%*.*s%s: ", indent, indent, "", name);
    func(obj, indent);
    return 0;
}

int dump_ptr(void *obj, char *name, int (*dump_func)(void *o, int ind), int ind) {
    printf("%*.*s%s = ", ind, ind, "", name);
    if (obj != NULL) {
        dump_func(obj, ind + 2);
    }
    else {
        printf("null\n");
    }
    return 0;
}

int dump_array(void **arr, char *name, int (*dump_func)(void *o, int ind), int ind) {
    printf("%*.*s%s > [\n", ind, ind, "", name);
    for (int i = 0; arr[i] != NULL; i++) {
        dump_func(arr[i], ind + 2);
    }
    printf("%*.*s]\n", ind, ind, "");
    return 0;
}

void free_ptr(void *obj, free_func f) {
    f(obj);
}

void free_array(void **arr, free_func f) {
    for (int i = 0; arr[i] != NULL; i++) {
        f(arr[i]);
    }
    free(arr);
}

#define cast_array(t) void**
#define cast_ptr(t) t*
#define cast_none(t) t

#define parse_field(n, type, mod, path) obj->n = ( mod(type) ) parse_##mod(json, json_len, path, (parse_func)parse_##type);
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
model(free_field)\
free(obj);\
}

#define FREE_MODEL_ARR(type) void free_##type##_array(type **arr) {\
free_array((void**)arr, (free_func)free_##type); \
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
DUMP_MODEL(type, model)

MODEL_IMPL(ziti_service, ZITI_SERVICE_MODEL)
MODEL_IMPL(nf_config, ZITI_CONFIG_MODEL)

MODEL_IMPL(ziti_gateway, ZITI_GATEWAY_MODEL)
MODEL_IMPL(ziti_net_session, ZITI_NET_SESSION_MODEL)

MODEL_IMPL(ctrl_version, ZITI_CTRL_VERSION)