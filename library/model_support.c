/*
Copyright (c) 2020 Netfoundry, Inc.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSMN_PARENT_LINKS 1
#define JSMN_STATIC

#include <jsmn.h>

#include <nf/model_support.h>
#include <utils.h>


static int parse_obj(void *obj, const char *json, jsmntok_t *tok, type_meta *meta);

void model_dump(void *obj, int off, type_meta *meta) {
    // TODO
}

int model_parse_array(void ***arrp, const char *json, size_t len, type_meta *meta) {
    jsmn_parser parser;
    jsmn_init(&parser);
    jsmntok_t toks[1024];
    memset(toks, 0, sizeof(toks));
    jsmntok_t *tok = toks;
    jsmn_parse(&parser, json, len, toks, 1024);
    if (tok->type != JSMN_ARRAY) {
        return -1;
    }

    int children = tok->size;
    void **arr = calloc(toks[0].size + 1, sizeof(void *));
    tok++;
    for (int i = 0; i < children; i++) {
        void *el = calloc(1, meta->size);
        int rc = parse_obj(el, json, tok, meta);
        if (rc < 0) {
            model_free(el, meta);
            FREE(el);
            return rc;
        }
        arr[i] = el;
        tok += rc;
    }
    *arrp = arr;
    return 0;
}

int model_parse(void *obj, const char *json, size_t len, type_meta *meta) {
    jsmn_parser parser;
    jsmn_init(&parser);
    jsmntok_t toks[1024];
    memset(toks, 0, sizeof(toks));
    jsmn_parse(&parser, json, len, toks, 1024);
    int res = parse_obj(obj, json, toks, meta);
    return res > 0 ? 0 : res;
}

void model_free_array(void ***ap, type_meta *meta) {
    if (ap == NULL || *ap == NULL) { return; }

    void **el = *ap;
    while (*el != NULL) {
        model_free(*el, meta);
        free(*el);
        el++;
    }
    FREE(*ap);
}

void model_free(void *obj, type_meta *meta) {
    if (obj == NULL) { return; }

    if (meta->destroyer != NULL) {
        return meta->destroyer(obj);
    }

    for (int i = 0; i < meta->field_count; i++) {
        field_meta *fm = &meta->fields[i];
        void **f_addr = (void **) ((char *) obj + fm->offset);
        void *f_ptr = NULL;
        if (fm->mod == none_mod) {
            f_ptr = f_addr;
            model_free(f_ptr, fm->meta);
        }
        else if (fm->mod == ptr_mod) {
            f_ptr = (void *) (*f_addr);
            if (f_ptr != NULL) {
                model_free(f_ptr, fm->meta);
                free(f_ptr);
            }
        }
        else if (fm->mod == array_mod) {
            void **arr = (void **) (*f_addr);
            if (arr != NULL) {
                for (int idx = 0; arr[idx] != NULL; idx++) {
                    f_ptr = arr + idx;
                    if (fm->meta == &string_META) {
                        model_free(f_ptr, fm->meta);
                    }
                    else {
                        void *mem_ptr = (void *) (*(void **) f_ptr);
                        model_free(mem_ptr, fm->meta);
                        free(mem_ptr);
                    }
                }
                free(arr);
            }
        }
    }
}

static int parse_array(void **arr, const char *json, jsmntok_t *tok, type_meta *el_meta) {
    if (tok->type != JSMN_ARRAY) {
        fprintf(stderr, "unexpected token, array as expected\n");
        return -1;
    }
    int children = tok->size;
    void **elems = calloc(children + 1, sizeof(void *));
    *arr = elems;
    int idx;
    int rc = 0;
    int processed = 1;
    tok++;
    for (idx = 0; idx < children; idx++) {
        void *el;
        if (el_meta != &string_META) {
            el = calloc(1, el_meta->size);
            elems[idx] = el;
        }
        else {
            el = &elems[idx];
        }
        if (el_meta->parser != NULL) {
            rc = el_meta->parser(el, json, tok);
        }
        else {
            rc = parse_obj(el, json, tok, el_meta);
        }
        if (rc < 0) {
            return rc;
        }
        tok += rc;
        processed += rc;
    }
    return processed;
}

static int parse_obj(void *obj, const char *json, jsmntok_t *tok, type_meta *meta) {
    memset(obj, 0, meta->size);
    if (tok->type != JSMN_OBJECT) {
        return -1;
    }
    int tokens_processed = 1;
    int children = tok->size;
    tok++;
    while (children != 0) {
        if (tok->type != JSMN_STRING) {
            fprintf(stderr, "unexpected token\n");
            return -1;
        }
        field_meta *fm = NULL;
        for (int i = 0; i < meta->field_count; i++) {
            if (strncmp(meta->fields[i].path, json + tok->start, tok->end - tok->start) == 0) {
                fm = &meta->fields[i];
                break;
            }
        }
        tokens_processed++;

        int rc;
        if (fm != NULL) {
            tok++;
            void *field = (char *) obj + fm->offset;
            if (fm->mod == array_mod) {
                rc = parse_array(field, json, tok, fm->meta);
            }
            else {
                char *memobj = NULL;
                if (fm->mod == none_mod) {
                    memobj = (char *) (field);
                }
                else if (fm->mod == ptr_mod) {
                    memobj = (char *) calloc(1, fm->meta->size);
                    *(char **) field = memobj;
                }
                if (memobj == NULL) {
                    fprintf(stderr, "member[%s] not found\n", fm->name);
                    return -1;
                }

                if (fm->meta->parser != NULL) {
                    rc = fm->meta->parser(memobj, json, tok);
                }
                else {
                    rc = parse_obj(memobj, json, tok, fm->meta);
                }
            }
            if (rc < 0) {
                return rc;
            }
            tok += rc;
            tokens_processed += rc;
        }
        else {
            // skip
            fprintf(stderr, "skipping unmapped field %.*s\n", tok->end - tok->start, json + tok->start);
            tok++;
            int end = tok->end;
            while (tok->type != JSMN_UNDEFINED && tok->start <= end) {
                tok++;
                tokens_processed++;
            }
        }
        children--;
    }
    return tokens_processed;
}


static int _parse_int(int *val, const char *json, jsmntok_t *tok) {
    if (tok->type == JSMN_PRIMITIVE) {
        char *end;
        int v = (int) strtol(&json[tok->start], &end, 10);
        if (end != &json[tok->end]) {
            fprintf(stderr, "did not consume all parsing int\n");
        }
        *val = v;
        return 1;
    }
    return -1;
}

static int _parse_bool(bool *val, const char *json, jsmntok_t *tok) {
    if (tok->type == JSMN_PRIMITIVE) {
        if (json[tok->start] == 't') {
            *val = true;
        }
        else if (json[tok->start] == 'f') {
            *val = false;
        }
        else {
            return -1;
        }
        return 1;
    }
    return -1;
}

static int _parse_string(char **val, const char *json, jsmntok_t *tok) {
    if (tok->type == JSMN_STRING) {
        *val = (char *) calloc(1, tok->end - tok->start + 1);

        const char *endp = json + tok->end;
        char *out = *val;
        const char *in = json + tok->start;
        while (in < endp) {
            if (*in == '\\') {
                switch (*++in) {
                    case 'b':
                        *out++ = '\b';
                        break;
                    case 'r':
                        *out++ = '\r';
                        break;
                    case 't':
                        *out++ = '\t';
                        break;
                    case 'n':
                        *out++ = '\n';
                        break;
                    case '\\':
                        *out++ = '\\';
                        break;
                    case '"':
                        *out++ = '"';
                        break;
                    default:
                        *out++ = *in;
                        fprintf(stderr, "unhandled escape seq '\\%c'", *in);
                }
                in++;
            }
            else {
                *out++ = *in++;
            }
        }
        return 1;
    }
    return -1;
}

static int _parse_timeval(timestamp *t, const char *json, jsmntok_t *tok) {

    char *date_str = NULL;
    int rc = _parse_string(&date_str, json, tok);

    if (rc < 0) { return rc; }

    struct tm t2 = {0};
    // "2019-08-05T14:02:52.337619Z"
    rc = sscanf(date_str, "%d-%d-%dT%d:%d:%d.%ldZ",
                &t2.tm_year, &t2.tm_mon, &t2.tm_mday,
                &t2.tm_hour, &t2.tm_min, &t2.tm_sec, &t->tv_usec);
    t2.tm_year -= 1900;
    t2.tm_mon -= 1;

    t->tv_sec = timegm(&t2);

    free(date_str);
    return 1;
}

static void _free_noop(void *v) {}

static void _free_string(char **s) {
    if (*s != NULL) {
        free(*s);
        *s = NULL;
    }
}

type_meta bool_META = {
        .size = sizeof(bool),
        .parser = (_parse_f) (_parse_bool),
        .destroyer = _free_noop,
};

type_meta int_META = {
        .size = sizeof(int),
        .parser = (_parse_f) _parse_int,
        .destroyer = _free_noop,
};

type_meta string_META = {
        .size = sizeof(char *),
        .parser = (_parse_f) _parse_string,
        .destroyer = (_free_f) _free_string,
};

type_meta timestamp_META = {
        .size = sizeof(struct timeval),
        .parser = (_parse_f) _parse_timeval,
        .destroyer = (_free_f) _free_noop,
};