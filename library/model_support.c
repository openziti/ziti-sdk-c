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

#include <ziti/model_support.h>
#include <utils.h>

#if _WIN32
#include <time.h>
#define timegm(v) _mkgmtime(v)
#else
#define _GNU_SOURCE //add time.h include after defining _GNU_SOURCE
#include <time.h>
#endif

#define null_checks(lh, rh) \
    if (lh == rh) { return 0; } \
    if (lh == NULL) { return -1; } \
    if (rh == NULL) { return 1; }

static int parse_obj(void *obj, const char *json, jsmntok_t *tok, type_meta *meta);

static int model_map_compare(model_map *lh, model_map *rh, type_meta *m);

void model_dump(void *obj, int off, type_meta *meta) {
    // TODO
}

jsmntok_t* parse_tokens(jsmn_parser *parser, const char *json, size_t len, size_t *ntok) {
    size_t tok_cap = 256;
    jsmn_init(parser);

    jsmntok_t *toks = calloc(tok_cap, sizeof(jsmntok_t));

    int rc = jsmn_parse(parser, json, len, toks, tok_cap);
    while (rc == JSMN_ERROR_NOMEM) {
        toks = realloc(toks,(tok_cap *= 2) * sizeof(jsmntok_t));
        ZITI_LOG(VERBOSE, "reallocating token array, new size = %zd", tok_cap);
        rc = jsmn_parse(parser, json, len, toks, tok_cap);
    }

    if (rc < 0) {
        ZITI_LOG(ERROR, "jsmn_parse() failed: %d", rc);
        free(toks);
        toks = NULL;
        *ntok = 0;
    } else {
        *ntok = rc;
    }
    if (*ntok == tok_cap) {
        toks = realloc(toks, (tok_cap + 1) * sizeof(jsmntok_t));
    }
    toks[*ntok].type = JSMN_UNDEFINED;

    return toks;
}

int model_cmp(void *lh, void *rh, type_meta *meta) {
    null_checks(lh, rh)

    int rc = 0;
    for (int i = 0; rc == 0 && i < meta->field_count; i++) {
        field_meta *fm = meta->fields + i;
        type_meta *ftm = fm->meta();

        void **lf_addr = (void **) ((char *) lh + fm->offset);
        void **rf_addr = (void **) ((char *) rh + fm->offset);
        void *lf_ptr, *rf_ptr;

        if (fm->mod == none_mod) {
            lf_ptr = lf_addr;
            rf_ptr = rf_addr;
            rc = ftm->comparer ? ftm->comparer(lf_ptr, rf_ptr) : model_cmp(lf_ptr, rf_ptr, ftm);
        }
        else if (fm->mod == ptr_mod) {
            lf_ptr = (void *) (*lf_addr);
            rf_ptr = (void *) (*rf_addr);
            rc = ftm->comparer ? ftm->comparer(lf_ptr, rf_ptr) : model_cmp(lf_ptr, rf_ptr, ftm);
        }
        else if (fm->mod == map_mod) {
            lf_ptr = lf_addr;
            rf_ptr = rf_addr;

            rc = model_map_compare(lf_ptr, rf_ptr, ftm);
        }
        else if (fm->mod == array_mod) {
            void **larr = (void **) (*lf_addr);
            void **rarr = (void **) (*rf_addr);

            if (larr == rarr) {}
            else if (larr == NULL) { rc = -1; }
            else if (rarr == NULL) { rc = 1; }
            else {
                for (int idx = 0; rc == 0; idx++) {
                    lf_ptr = larr[idx];
                    rf_ptr = rarr[idx];
                    if (rf_ptr == NULL && lf_ptr == NULL) { break; }

                    if (ftm->comparer) {
                        if (fm->meta == get_string_meta) {
                            rc = ftm->comparer(&lf_ptr, &rf_ptr);
                        }
                        else {
                            rc = ftm->comparer(lf_ptr, rf_ptr);
                        }
                    }
                    else {
                        rc = model_cmp(lf_ptr, rf_ptr, ftm);
                    }
                }
            }
        }
    }

    return rc;
}

int model_parse_array(void ***arrp, const char *json, size_t len, type_meta *meta) {
    jsmn_parser parser;
    size_t ntoks;
    jsmntok_t *tokens = parse_tokens(&parser, json, len, &ntoks);
    if (tokens == NULL) {
        return -1;
    }

    jsmntok_t *tok = tokens;
    if (tok->type != JSMN_ARRAY) {
        FREE(tokens);
        return -1;
    }

    int children = tok->size;
    void **arr = calloc(tokens[0].size + 1, sizeof(void *));
    tok++;
    for (int i = 0; i < children; i++) {
        void *el = calloc(1, meta->size);
        int rc = parse_obj(el, json, tok, meta);
        if (rc < 0) {
            model_free(el, meta);
            FREE(el);
            FREE(tokens);
            return rc;
        }
        arr[i] = el;
        tok += rc;
    }
    *arrp = arr;
    FREE(tokens);
    return 0;
}

int model_parse(void *obj, const char *json, size_t len, type_meta *meta) {
    jsmn_parser parser;
    size_t ntoks;
    jsmntok_t *tokens = parse_tokens(&parser, json, len, &ntoks);
    int res = tokens != NULL ? parse_obj(obj, json, tokens, meta) : -1;
    FREE(tokens);
    return res > 0 ? 0 : res;
}

int model_to_json(void *obj, type_meta *meta, int indent, char *buf, size_t maxlen, size_t *len) {
    char *p = buf;
    *p++ = '{';
    *p++ = '\n';
    int rc = 0;
    char *last_coma = NULL;
    for (int i = 0; rc == 0 && i < meta->field_count; i++) {
        field_meta *fm = meta->fields + i;
        type_meta *ftm = fm->meta();

        void **f_addr = (void **) ((char *) obj + fm->offset);
        void *f_ptr = fm->mod == none_mod ? f_addr : (void *) (*f_addr);

        if (fm->meta == get_string_meta) {
            f_ptr = (void *) (*f_addr);
        }

        if (f_ptr == NULL) {
            continue;
        }


        if (f_ptr != NULL) {
            for (int j = 0; j <= indent; j++, *p++ = '\t') {}
            *p++ = '"';
            strcpy(p, fm->path);
            p += strlen(fm->path);
            *p++ = '"';
            *p++ = ':';
        }

        if (fm->mod == none_mod || fm->mod == ptr_mod) {
            size_t flen;
            if (ftm->jsonifier) {
                ftm->jsonifier(f_ptr, indent + 1, p, buf + maxlen - p, &flen);
            }
            else {
                model_to_json(f_ptr, ftm, indent + 1, p, buf + maxlen - p, &flen);
            }
            p += flen;
        }
        else if (fm->mod == map_mod) {
            indent++;
            model_map *map = (model_map *) f_addr;
            const char *k;
            void *v;
            *p++ = '{';
            char *comma = p;
            *p++ = '\n';
            size_t ellen;
            MODEL_MAP_FOREACH(k, v, map) {
                for (int j = 0; j <= indent; j++, *p++ = '\t') {}
                *p++ = '"';
                strcpy(p, k);
                p += strlen(k);
                *p++ = '"';
                *p++ = ':';
                if (ftm->jsonifier) {
                    ftm->jsonifier(v, indent + 1, p, buf + maxlen - p, &ellen);
                }
                else {
                    model_to_json(v, ftm, indent + 1, p, buf + maxlen - p, &ellen);
                }
                p += ellen;
                comma = p;
                *p++ = ',';
                *p++ = '\n';
            }
            if (comma != NULL) {
                p = comma;
            }
            *p++ = '}';
            indent--;
        }
        else if (fm->mod == array_mod) {
            void **arr = (void **) (*f_addr);

            int idx = 0;
            *p++ = '[';
            for (idx = 0; rc == 0; idx++) {
                f_ptr = arr[idx];
                if (f_ptr == NULL) { break; }
                if (idx > 0) {
                    *p++ = ',';
                }

                size_t ellen;
                if (ftm->jsonifier) {
                    rc = ftm->jsonifier(f_ptr, indent + 1, p, buf + maxlen - p, &ellen);
                }
                else {
                    rc = model_to_json(f_ptr, ftm, indent + 1, p, buf + maxlen - p, &ellen);
                }
                p += ellen;
            }

            *p++ = ']';
        }
        else {
            ZITI_LOG(ERROR, "unsupported mod[%d] for field[%s]", fm->mod, fm->name);
            return -1;
        }
        *p++ = ',';
        last_coma = p - 1;
        *p++ = '\n';
    }
    if (last_coma != NULL) {
        p = last_coma;
        *p++ = '\n';
    }

    for (int j = 0; j < indent; j++, *p++ = '\t') {}
    *p++ = '}';
    *p = '\0';
    *len = p - buf;
    return 0;
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
            model_free(f_ptr, fm->meta());
        }
        else if (fm->mod == ptr_mod) {
            f_ptr = (void *) (*f_addr);
            if (f_ptr != NULL) {
                model_free(f_ptr, fm->meta());
                free(f_ptr);
            }
        }
        else if (fm->mod == array_mod) {
            void **arr = (void **) (*f_addr);
            if (arr != NULL) {
                for (int idx = 0; arr[idx] != NULL; idx++) {
                    f_ptr = arr + idx;
                    if (fm->meta == get_string_meta) {
                        model_free(f_ptr, fm->meta());
                    }
                    else {
                        void *mem_ptr = (void *) (*(void **) f_ptr);
                        model_free(mem_ptr, fm->meta());
                        free(mem_ptr);
                    }
                }
                free(arr);
            }
        }
        else if (fm->mod == map_mod) {
            model_map *map = (model_map *) f_addr;
            _free_f ff = NULL;
            model_map_iter it = model_map_iterator(map);
            while (it != NULL) {
                const char *k = model_map_it_key(it);
                void *v = model_map_it_value(it);
                if (fm->meta == get_string_meta || fm->meta == get_json_meta) {
                    fm->meta()->destroyer(&v);
                }
                else if (fm->meta()->destroyer) {
                    fm->meta()->destroyer(v);
                }
                else {
                    model_free(v, fm->meta());
                }
                free(v);

                it = model_map_it_remove(it);
            }

            if (fm->meta == get_string_meta) {
                ff = free;
            }
            else {
                ff = fm->meta()->destroyer;
            }
            model_map_clear(map, ff);
        }
    }
}

static int parse_array(void **arr, const char *json, jsmntok_t *tok, type_meta *el_meta) {
    if(tok-> type == JSMN_PRIMITIVE && json[tok->start] == 'n'){ //null check
        *arr = NULL;
        return 1;
    }

    if (tok->type != JSMN_ARRAY) {
        ZITI_LOG(ERROR, "unexpected token, array as expected");
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
        if (el_meta != get_string_meta()) {
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

static int parse_map(void *mapp, const char *json, jsmntok_t *tok, type_meta *el_meta) {
    if (tok->type != JSMN_OBJECT) {
        ZITI_LOG(ERROR, "unexspected JSON token near '%.*s', expecting object", 20, json + tok->start);
        return -1;
    }
    model_map *map = mapp;
    int tokens_processed = 1;
    int children = tok->size;
    tok++;
    for (int i = 0; i < children; i++) {
        if (tok->type != JSMN_STRING) {
            ZITI_LOG(ERROR, "parsing[map] error: unexpected token starting at `%.*s'", 20, json + tok->start);
            return -1;
        }
        const char *key = json + tok->start;
        size_t keylen = tok->end - tok->start;

        tok++;
        tokens_processed++;
        void *value = NULL;
        int rc;
        if (el_meta == get_string_meta()) {
            rc = get_string_meta()->parser(&value, json, tok);
        }
        else if (el_meta == get_json_meta()) {
            rc = get_json_meta()->parser(&value, json, tok);
        }
        else {
            value = calloc(1, el_meta->size);
            rc = el_meta->parser ?
                 el_meta->parser(value, json, tok) :
                 parse_obj(value, json, tok, el_meta);
        }
        if (rc < 0) {
            FREE(value);
            return rc;
        }
        tok += rc;
        tokens_processed += rc;
        char *k = calloc(1, keylen + 1);
        strncpy(k, key, keylen);
        model_map_set(map, k, value);
        free(k);
    }
    return tokens_processed;
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
            ZITI_LOG(ERROR, "parsing[%s] error: unexpected token starting at `%.*s'\n", meta->name, 20, json + tok->start);
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
                rc = parse_array(field, json, tok, fm->meta());
            }
            else if (fm->mod == map_mod) {
                rc = parse_map(field, json, tok, fm->meta());
            }
            else {
                char *memobj = NULL;
                if (fm->mod == none_mod) {
                    memobj = (char *) (field);
                }
                else if (fm->mod == ptr_mod) {
                    memobj = (char *) calloc(1, fm->meta()->size);
                    *(char **) field = memobj;
                }
                if (memobj == NULL) {
                    ZITI_LOG(ERROR, "member[%s] not found", fm->name);
                    return -1;
                }

                if (fm->meta()->parser != NULL) {
                    rc = fm->meta()->parser(memobj, json, tok);
                }
                else {
                    rc = parse_obj(memobj, json, tok, fm->meta());
                }
            }
            if (rc < 0) {
                return rc;
            }
            tok += rc;
            tokens_processed += rc;
        }
        else {
            ZITI_LOG(TRACE, "skipping unmapped field[%.*s] while parsing %s", tok->end - tok->start, json + tok->start, meta->name);
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
            ZITI_LOG(WARN, "did not consume all parsing int");
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
static int _parse_json(char **val, const char *json, jsmntok_t *tok) {
    int start = tok->type == JSMN_STRING ? tok->start - 1 : tok->start;
    int end = tok->type == JSMN_STRING ? tok->end + 1 : tok->end;

    int json_len = end - start;
    *val = calloc(1, json_len + 1);
    strncpy(*val, json + start, json_len);

    int processed = 0;
    jsmntok_t *t = tok;
    while (t->type != JSMN_UNDEFINED && t->end <= tok->end) {
        processed++;
        t++;
    }

    return processed;
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
                        ZITI_LOG(ERROR, "unhandled escape seq '\\%c'", *in);
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

static int _parse_tag(tag *t, const char *json, jsmntok_t *tok) {
    int rc = -1;
    switch (tok->type) {
        case JSMN_PRIMITIVE:
            rc = _parse_bool(&t->bool_value, json, tok);
            if (rc == -1) {
                rc = _parse_int(&t->num_value, json, tok);
                t->type = tag_number;
            }
            else {
                t->type = tag_bool;
            }
            break;
        case JSMN_STRING:
            rc = _parse_string(&t->string_value, json, tok);
            t->type = tag_string;
            break;
        default:
            rc = -1;
    }
    return rc;
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


static int _cmp_bool(bool *lh, bool *rh) {
    null_checks(lh, rh)
    if (*lh == *rh) { return 0; }
    if (!*lh) { return -1; }
    return 1;
}

static int _cmp_int(int *lh, int *rh) {
    null_checks(lh, rh)
    return (*lh - *rh);
}

static int _cmp_timeval(timestamp *lh, timestamp *rh) {
    null_checks(lh, rh)
    return (int) (lh->tv_sec == rh->tv_sec ? (lh->tv_usec - rh->tv_usec) : (lh->tv_sec - rh->tv_sec));
}

static int _cmp_string(char **lh, char **rh) {
    null_checks(lh, rh)
    if (*lh == *rh) { return 0; } // same ptr or both NULL

    return strcmp(*lh, *rh);
}

static int _cmp_tag(tag *lh, tag *rh) {
    null_checks(lh, rh)
    if (lh == rh) { return 0; } // same ptr or both NULL
    if (lh->type != rh->type) {
        return (int) lh->type - (int) rh->type;
    }

    switch (lh->type) {
        case tag_bool:
            return _cmp_bool(&lh->bool_value, &rh->bool_value);
        case tag_number:
            return _cmp_int(&lh->num_value, &rh->num_value);
        case tag_string:
            return _cmp_string(&lh->string_value, &rh->string_value);
        case tag_null:
            return 0;
    }
}

static int _cmp_map(model_map *lh, model_map *rh) {
    null_checks(lh, rh)

    int rc = 0;
    for (model_map_iter lit = model_map_iterator(lh), rit = model_map_iterator(rh);
         lit != NULL && rit != NULL;
         lit = model_map_it_next(lit), rit = model_map_it_next(rit)) {

        if (lit == NULL) { rc -= 1; }
        if (rit == NULL) { rc += 1; }
    }

    //
    if (rc == 0) {
        model_map_iter it = model_map_iterator(lh);
        while (it != NULL && rc == 0) {
            char *lhv = model_map_it_value(it);
            char *rhv = model_map_get(rh, model_map_it_key(it));
            if (rhv == NULL) {
                rc = 1;
            }
            else {
                rc = strcmp(lhv, rhv);
            }

            it = model_map_it_next(it);
        }
    }

    return rc;
}

static int _bool_json(bool *v, int indent, char *json, size_t max, size_t *len) {
    if (*v) {
        strcpy(json, "true");
        *len = 4;
    }
    else {
        strcpy(json, "false");
        *len = 5;
    }
    return 0;
}

static int _int_json(int *v, int indent, char *json, size_t max, size_t *len) {
    int rc = snprintf(json, max, "%d", *v);
    if (rc > 0) {
        *len = rc;
        return 0;
    }
    return rc;
}

static int _string_json(const char *s, int indent, char *json, size_t max, size_t *len) {

    char *j = json;

    *j++ = '"';
    while (*s != '\0') {
        switch (*s) {
            case '\n':
                *j++ = '\\';
                *j++ = 'n';
                break;
            case '\b':
                *j++ = '\\';
                *j++ = 'b';
                break;
            case '\r':
                *j++ = '\\';
                *j++ = 'r';
                break;
            case '\t':
                *j++ = '\\';
                *j++ = 't';
                break;
            case '\\':
                *j++ = '\\';
                *j++ = '\\';
                break;
            case '"':
                *j++ = '\\';
                *j++ = '"';
                break;
            default:
                *j++ = *s;
        }
        s++;
    }
    *j++ = '"';
    *len = j - json;
    return 0;
}

static int _tag_json(tag *t, int indent, char *json, size_t max, size_t *len) {
    int rc;
    switch (t->type) {
        case tag_null:
            rc = snprintf(json, max, "null");
            break;
        case tag_bool:
            rc = snprintf(json, max, t->bool_value ? "true" : "false");
            break;
        case tag_number:
            rc = snprintf(json, max, "%d", t->num_value);
            break;
        case tag_string:
            return _string_json(t->string_value, indent, json, max, len);
            break;
    }
    if (rc > 0) {
        *len = rc;
        return 0;
    }
    return rc;
}

static int _json_json(const char *s, int indent, char *json, size_t max, size_t *len) {
    int rc = snprintf(json, max, "%s", s);
    if (rc > 0) {
        *len = rc;
        return 0;
    }
    return rc;
}

static int _timeval_json(timestamp *t, int indent, char *json, size_t max, size_t *len) {
    struct tm tm2;
#if _WIN32
    _gmtime32_s(&tm2, &t->tv_sec);
#else
    gmtime_r(&t->tv_sec, &tm2);
#endif

    int rc = snprintf(json, max, "\"%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ\"",
                      tm2.tm_year + 1900, tm2.tm_mon + 1, tm2.tm_mday,
                      tm2.tm_hour, tm2.tm_min, tm2.tm_sec, t->tv_usec);
    *len = rc;
    return 0;
}

#define mk_indent(p, indent) do { for (int j=0; j < (indent); j++, *p++ = '\t'); } while(0)

static int _map_json(model_map *map, int indent, char *json, size_t max, size_t *len) {
    char *p = json;
    *p++ = '{';

    const char *key;
    const char *val;
    size_t l;
    char *last_coma = NULL;
    MODEL_MAP_FOREACH(key, val, map) {
        *p++ = '\n';
        mk_indent(p, indent + 1);
        _string_json(key, indent, p, json + max - p, &l);
        p += l;
        *p++ = ':';
        _json_json(val, indent, p, json + max - p, &l);
        p += l;
        *p++ = ',';
        last_coma = p - 1;
    }
    if (last_coma) { *last_coma = '\n'; }
    mk_indent(p, indent);
    *p++ = '}';
    *len = p - json;
    return 0;
}

static void _free_noop(void *v) {}

static void _free_string(char **s) {
    if (*s != NULL) {
        free(*s);
        *s = NULL;
    }
}

static void _free_tag(tag *t) {
    if (t != NULL) {
        if (t->type == tag_string) {
            FREE(t->string_value);
        }
    }
}

struct model_map_entry {
    char *key;
    uint key_hash;
    void *value;
    LIST_ENTRY(model_map_entry) _next;
    LIST_ENTRY(model_map_entry) _tnext;
    struct model_impl_s *_impl;
};

typedef LIST_HEAD(entries_s, model_map_entry) entries_t;

struct model_impl_s {
    entries_t entries;
    entries_t *table;
    int buckets;
    size_t size;
};

static uint key_hash0(const char *key) {
    uint h = 0;
    char b;
    while ((b = *key++)) {
        h = ((h << 5U) + h) + b;
    }
    return h;
}

static const int DEFAULT_MAP_BUCKETS = 16;
static uint (*key_hash)(const char *key) = key_hash0;

static void map_resize_table(model_map* m) {
    if (m->impl == NULL) return;

    int orig_buckets = m->impl->buckets;
    m->impl->buckets *= 2;
    m->impl->table = realloc(m->impl->table, m->impl->buckets * sizeof(entries_t));
    memset(m->impl->table, 0, sizeof(entries_t) * m->impl->buckets);

    struct model_map_entry *el;
    LIST_FOREACH(el, &m->impl->entries, _next) {
        uint idx = el->key_hash % m->impl->buckets;
        entries_t *bucket = m->impl->table + idx;
        LIST_INSERT_HEAD(bucket, el, _tnext);
    }
}

static struct model_map_entry *find_map_entry(model_map *m, const char *key, uint *hash_out) {
    uint kh = key_hash(key);
    if (hash_out) {
        *hash_out = kh;
    }
    uint idx = kh % m->impl->buckets;
    entries_t *bucket = m->impl->table + idx;
    struct model_map_entry *entry;
    LIST_FOREACH(entry, bucket, _tnext) {
        if (kh == entry->key_hash && strcmp(key, entry->key) == 0) {
            return entry;
        }
    }
    return NULL;
}

void *model_map_set(model_map *m, const char *key, void *val) {
    if (m->impl == NULL) {
        m->impl = calloc(1, sizeof(struct model_impl_s));
        m->impl->buckets = DEFAULT_MAP_BUCKETS;
        m->impl->table = calloc(m->impl->buckets, sizeof(entries_t));
    }

    uint kh;
    struct model_map_entry *el = find_map_entry(m, key, &kh);
    if (el != NULL) {
        void *old_val = el->value;
        el->value = val;
        return old_val;
    }

    el = malloc(sizeof(struct model_map_entry));
    el->value = val;
    el->key = strdup(key);
    el->key_hash = kh;
    el->_impl = m->impl;
    uint idx = el->key_hash % m->impl->buckets;

    entries_t *bucket = m->impl->table + idx;
    LIST_INSERT_HEAD(&m->impl->entries, el, _next);
    LIST_INSERT_HEAD(bucket, el, _tnext);
    m->impl->size++;

    if (m->impl->size > m->impl->buckets * 2) {
        map_resize_table(m);
    }

    return NULL;
}

void* model_map_get(model_map *m, const char* key) {
    if (m->impl == NULL) {
        return NULL;
    }

    struct model_map_entry *el = find_map_entry(m, key, NULL);
    return el ? el->value : NULL;
}

void *model_map_remove(model_map *m, const char *key) {
    if (m->impl == NULL) {
        return NULL;
    }

    void *val = NULL;
    struct model_map_entry *el = find_map_entry(m, key, NULL);
    if (el != NULL) {
        val = el->value;
        LIST_REMOVE(el, _next);
        LIST_REMOVE(el, _tnext);
        free(el->key);
        free(el);
        m->impl->size--;
    }
    return val;
}

void model_map_clear(model_map *map, _free_f free_func) {
    if (map->impl == NULL) { return; }

    while (!LIST_EMPTY(&map->impl->entries)) {
        struct model_map_entry *el = LIST_FIRST(&map->impl->entries);
        LIST_REMOVE(el, _next);
        FREE(el->key);
        if (free_func) {
            free_func(el->value);
        }
        FREE(el->value);
        FREE(el);
    }
    FREE(map->impl->table);
    FREE(map->impl);
}

model_map_iter model_map_iterator(model_map *m) {
    if (m->impl == NULL) { return NULL; }
    return LIST_FIRST(&m->impl->entries);
}

const char *model_map_it_key(model_map_iter *it) {
    return it != NULL ? ((struct model_map_entry *) it)->key : NULL;
}

void *model_map_it_value(model_map_iter it) {
    return it != NULL ? ((struct model_map_entry *) it)->value : NULL;
}

model_map_iter model_map_it_next(model_map_iter it) {
    return it != NULL ? LIST_NEXT((struct model_map_entry *) it, _next) : NULL;
}

model_map_iter model_map_it_remove(model_map_iter it) {
    model_map_iter next = model_map_it_next(it);
    if (it != NULL) {
        struct model_map_entry *e = (struct model_map_entry *) it;
        e->_impl->size--;
        LIST_REMOVE(e, _next);
        LIST_REMOVE(e, _tnext);
        free(e->key);
        free(e);
    }
    return next;
}

static int model_map_compare(model_map *lh, model_map *rh, type_meta *m) {
    null_checks(lh, rh)

    int rc = 0;
    for (model_map_iter lit = model_map_iterator(lh), rit = model_map_iterator(rh);
         lit != NULL && rit != NULL;
         lit = model_map_it_next(lit), rit = model_map_it_next(rit)) {

        if (lit == NULL) { rc -= 1; }
        if (rit == NULL) { rc += 1; }
    }

    //
    if (rc == 0) {
        model_map_iter it = model_map_iterator(lh);
        while (it != NULL && rc == 0) {
            char *lhv = model_map_it_value(it);
            char *rhv = model_map_get(rh, model_map_it_key(it));
            if (rhv == NULL) {
                rc = 1;
            }
            else {
                if (m == get_string_meta() || m == get_json_meta()) {
                    rc = m->comparer(&lhv, &rhv);
                }
                else {
                    rc = m->comparer ? m->comparer(lhv, rhv) : model_cmp(lhv, rhv, m);
                }
            }

            it = model_map_it_next(it);
        }
    }

    return rc;
}

static int _parse_map(model_map *m, const char *json, jsmntok_t *tok) {
    if (tok->type != JSMN_OBJECT) {
        ZITI_LOG(ERROR, "unexpected JSON token near '%.*s', expecting object", 20, json + tok->start);
        return -1;
    }

    int tokens_processed = 1;
    int children = tok->size;
    tok++;
    for (int i = 0; i < children; i++) {
        if (tok->type != JSMN_STRING) {
            ZITI_LOG(ERROR, "parsing[map] error: unexpected token starting at `%.*s'\n", 20, json + tok->start);
            return -1;
        }
        const char *key = json + tok->start;
        size_t keylen = tok->end - tok->start;

        tok++;
        tokens_processed++;
        char *value = NULL;
        int rc = _parse_json(&value, json , tok);
        if (rc < 0) {
            return rc;
        }
        tok += rc;
        tokens_processed += rc;
        char *k = calloc(1, keylen + 1);
        strncpy(k, key, keylen);
        model_map_set(m, k, value);
        free(k);
    }
    return tokens_processed;
}

static void _free_map(model_map *m) {
    model_map_clear(m, NULL);
}

static type_meta bool_META = {
        .size = sizeof(bool),
        .comparer = (_cmp_f) _cmp_bool,
        .parser = (_parse_f) (_parse_bool),
        .jsonifier = (_to_json_f) (_bool_json),
        .destroyer = _free_noop,
};

static type_meta int_META = {
        .size = sizeof(int),
        .comparer = (_cmp_f) _cmp_int,
        .parser = (_parse_f) _parse_int,
        .jsonifier = (_to_json_f) _int_json,
        .destroyer = _free_noop,
};

static type_meta string_META = {
        .size = sizeof(char *),
        .comparer = (_cmp_f) _cmp_string,
        .parser = (_parse_f) _parse_string,
        .jsonifier = (_to_json_f) _string_json,
        .destroyer = (_free_f) _free_string,
};

static type_meta timestamp_META = {
        .size = sizeof(struct timeval),
        .comparer = (_cmp_f) _cmp_timeval,
        .parser = (_parse_f) _parse_timeval,
        .jsonifier = (_to_json_f) _timeval_json,
        .destroyer = (_free_f) _free_noop,
};

static type_meta json_META = {
        .size = sizeof(char *),
        .comparer = (_cmp_f) _cmp_string,
        .parser = (_parse_f) _parse_json,
        .jsonifier = (_to_json_f) _json_json,
        .destroyer = (_free_f) _free_string,
};

static type_meta map_META = {
        .size = sizeof(model_map),
        .comparer = (_cmp_f) _cmp_map,
        .parser = (_parse_f) _parse_map,
        .jsonifier = (_to_json_f) _map_json,
        .destroyer = (_free_f) _free_map,
};

static type_meta tag_META = {
        .size = sizeof(tag),
        .comparer = (_cmp_f) _cmp_tag,
        .parser = (_parse_f) _parse_tag,
        .jsonifier = (_to_json_f) _tag_json,
        .destroyer = (_free_f) _free_tag,

};

type_meta *get_bool_meta() { return &bool_META; }

type_meta *get_int_meta() { return &int_META; }

type_meta *get_string_meta() { return &string_META; }

type_meta *get_timestamp_meta() { return &timestamp_META; }

type_meta *get_json_meta() { return &json_META; }

type_meta *get_model_map_meta() { return &map_META; }

type_meta *get_tag_meta() { return &tag_META; }