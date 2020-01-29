/*
Copyright 2019-2020 Netfoundry, Inc.

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

#if _WIN32
#include <time.h>
#define timegm(v) _mkgmtime(v)
#else
#define _GNU_SOURCE //add time.h include after defining _GNU_SOURCE
#include <time.h>
#endif

#define MJSON_API_ONLY
#include <mjson.h>


#include <stdbool.h>
#include <utils.h>

#include "model.h"
#include <math.h>

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


string parse_string(const char *json, int json_len) {
    const char *f;
    int n;
    string result = NULL;
    const char path[] = "$";
    if (path != NULL && mjson_find(json, json_len, path, &f, &n) == MJSON_TOK_STRING) {
        result = calloc(1, n + 1);
        mjson_get_string(f, n, "$", result, n);
    }
    return result;
}

struct timeval *parse_timeval_t(const char *json, int json_len) {
    char *date_str = parse_string(json, json_len);
    NEWP(t, struct timeval);
    struct tm t2 = {0};
    // "2019-08-05T14:02:52.337619Z"
    int rc = sscanf(date_str, "%d-%d-%dT%d:%d:%d.%ldZ",
            &t2.tm_year, &t2.tm_mon, &t2.tm_mday,
            &t2.tm_hour, &t2.tm_min, &t2.tm_sec, &t->tv_usec);
    t2.tm_year -= 1900;
    t2.tm_mon -= 1;

    t->tv_sec = timegm(&t2);

    free(date_str);
    return t;
}

void free_timeval_t(struct timeval *t) {
    free(t);
}

int dump_timeval_t(struct timeval *t, int off) {
    printf("%*.*s%s\n", off, off, "", ctime(&t->tv_sec));
    return 0;
}

int parse_bool(const char *json, int json_len) {
    int result;
    int rc =  mjson_get_bool(json, json_len, "$", &result);
    if (rc == 0) return false;
    return result;
}

int parse_int(const char *json, int json_len) {
    double result;
    if (mjson_get_number(json, json_len, "$", &result)) {
        return (int)lrint(result);
    }
    return -1;
}

void *parse_ptr(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int)) {
    const char *f;
    int n;
    enum mjson_tok tok = mjson_find(json, json_len, path, &f, &n);
    switch (tok) {
        case MJSON_TOK_OBJECT:
        case MJSON_TOK_STRING:
            return parse_func(f, n);
    }
    return NULL;
}

void **parse_array(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int)) {
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
    printf("%*.*s%s\n", len, len, "", s ? s : "<null>");
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

void* parse_none(const char *json, int json_len, char *path, void *(*parse_func)(const char *, int)) {
    const char *obj;
    int obj_len;
    void *result = NULL;

    enum mjson_tok tok = mjson_find(json, json_len, path, &obj, &obj_len);

    if (tok != MJSON_TOK_INVALID) {
        result = parse_func(obj, obj_len);
    }
    return result;
}


int dump_none(void *obj, char *name, dump_func func, int indent) {
    printf("%*s%s: ", indent, "", name);
    func(obj, 0);
    return 0;
}

int dump_ptr(void *obj, char *name, int (*dump_func)(void *o, int ind), int ind) {
    printf("%*s%s = ", ind, "", name);
    if (obj != NULL) {
        dump_func(obj, ind + 2);
    }
    else {
        printf("null\n");
    }
    return 0;
}

int dump_array(void **arr, char *name, int (*dump_func)(void *o, int ind), int ind) {
    printf("%*.*s%s > [", ind, ind, "", name);
    for (int i = 0; arr && arr[i] != NULL; i++) {
        printf("\n");
        dump_func(arr[i], ind + 2);
    }
    printf("%*s]\n", ind, "");
    return 0;
}

void free_ptr(void *obj, free_func f) {
    f(obj);
}

void free_array(void **arr, free_func f) {
    for (int i = 0; arr && arr[i] != NULL; i++) {
        f(arr[i]);
    }
    free(arr);
}
