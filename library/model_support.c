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
#include <buffer.h>
#include <utils.h>

#if _WIN32
#include <time.h>
#define timegm(v) _mkgmtime(v)
#else
#define _GNU_SOURCE //add time.h include after defining _GNU_SOURCE

#include <time.h>

#endif

#define RUNE_MASK 0b00111111
#define RUNE_B1 0b10000000
#define RUNE_B2 0b11000000
#define RUNE_B3 0b11100000
#define RUNE_B4 0b11110000

#define null_checks(lh, rh) \
    if ((lh) == (rh)) { return 0; } \
    if ((lh) == NULL) { return -1; } \
    if ((rh) == NULL) { return 1; }

static int parse_obj(void *obj, const char *json, jsmntok_t *tok, type_meta *meta);

jsmntok_t* parse_tokens(jsmn_parser *parser, const char *json, size_t len, size_t *ntok) {
    size_t tok_cap = 256;
    jsmn_init(parser);

    jsmntok_t *toks = calloc(tok_cap, sizeof(jsmntok_t));

    int rc = jsmn_parse(parser, json, len, toks, tok_cap);
    while (rc == JSMN_ERROR_NOMEM) {
        toks = realloc(toks, (tok_cap *= 2) * sizeof(jsmntok_t));
        ZITI_LOG(TRACE, "reallocating token array, new size = %zd", tok_cap);
        rc = jsmn_parse(parser, json, len, toks, tok_cap);
    }

    *ntok = rc;
    if (rc < 0) {
        int lvl = (rc == JSMN_ERROR_PART) ? DEBUG : ERROR;
        ZITI_LOG(lvl, "jsmn_parse() failed: %d", rc);
        free(toks);
        toks = NULL;
    } else {
        if (*ntok == tok_cap) {
            toks = realloc(toks, (tok_cap + 1) * sizeof(jsmntok_t));
        }
        toks[*ntok].type = JSMN_UNDEFINED;
    }
    return toks;
}

int model_cmp(const void *lh, const void *rh, type_meta *meta) {
    null_checks(lh, rh)

    if (meta->comparer) {
        return meta->comparer(lh, rh);
    }

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
                        if (fm->meta() == get_string_meta()) {
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
    int result = -1;
    int children = 0;
    jsmntok_t *tokens = parse_tokens(&parser, json, len, &ntoks);
    void **arr = NULL;
    if (tokens == NULL) {
        result = ntoks;
        goto done;
    }

    jsmntok_t *tok = tokens;
    if (tok->type != JSMN_ARRAY) {
        goto done;
    }
    result = tokens[0].end;
    children = tok->size;
    arr = calloc(tokens[0].size + 1, sizeof(void *));
    tok++;
    for (int i = 0; i < children; i++) {
        arr[i] = calloc(1, meta->size);
        int rc = parse_obj(arr[i], json, tok, meta);
        if (rc < 0) {
            result = rc;
            goto done;
        }
        tok += rc;
    }
    *arrp = arr;
    done:
    if (result < 0) {
        if (arr != NULL) {
            for (int i = 0; i < children; i++) {
                if (arr[i] != NULL) {
                    model_free(arr[i], meta);
                    FREE(arr[i]);
                }
            }
            FREE(arr);
        }
    }
    FREE(tokens);
    return result;
}

int model_parse(void *obj, const char *json, size_t len, type_meta *meta) {
    jsmn_parser parser;
    size_t ntoks;
    jsmntok_t *tokens = parse_tokens(&parser, json, len, &ntoks);
    int res = tokens != NULL ? parse_obj(obj, json, tokens, meta) : ntoks;
    int result = res > 0 ? tokens[0].end : res;
    FREE(tokens);
    return result;
}

static int write_model_to_buf(const void *obj, const type_meta *meta, string_buf_t *buf, int indent, int flags);

char *model_to_json(const void *obj, const type_meta *meta, int flags, size_t *len) {
    if (obj == NULL) {
        if (len) *len = 0;
        return NULL;
    }

    string_buf_t json;
    string_buf_init(&json);
    char *result = NULL;
    if (write_model_to_buf(obj, meta, &json, 0, flags) == 0) {
        result = string_buf_to_string(&json, len);
    }
    string_buf_free(&json);
    return result;
}

ssize_t model_to_json_r(const void *obj, const type_meta *meta, int flags, char *outbuf, size_t max) {
    if (obj == NULL) {
        return 0;
    }

    string_buf_t json;
    string_buf_init_fixed(&json, outbuf, max);
    ssize_t result = -1;
    if (write_model_to_buf(obj, meta, &json, 0, flags) == 0) {
        result = string_buf_size(&json);
    }
    string_buf_free(&json);
    return result;
}


#define PRETTY_INDENT(b, ind)  do { \
for (int j = 0; (flags & MODEL_JSON_COMPACT) == 0 && j <= (ind); j++) BUF_APPEND_B(b, '\t'); \
} while(0)

#define PRETTY_NL(b) do { \
if ((flags & MODEL_JSON_COMPACT) == 0) BUF_APPEND_B(b, '\n'); \
} while(0)


#define BUF_APPEND_B(b, s) CHECK_APPEND(string_buf_append_byte(b,s))
#define BUF_APPEND_S(b, s) CHECK_APPEND(string_buf_append(b,s))

#define CHECK_APPEND(op) do { int res = (op); if (res != 0) return res; } while(0)

int write_model_to_buf(const void *obj, const type_meta *meta, string_buf_t *buf, int indent, int flags) {

    BUF_APPEND_S(buf, "{");
    char *last_coma = NULL;
    bool comma = false;
    for (int i = 0; i < meta->field_count; i++) {
        field_meta *fm = meta->fields + i;
        type_meta *ftm = fm->meta();

        void **f_addr = (void **) ((char *) obj + fm->offset);
        void *f_ptr = fm->mod == none_mod ? f_addr : (void *) (*f_addr);

        if (ftm == get_string_meta() || ftm == get_json_meta()) {
            f_ptr = (void *) (*f_addr);
        }

        if (f_ptr == NULL) {
            continue;
        }

        if (comma) {
            BUF_APPEND_S(buf, ",");
        }
        PRETTY_NL(buf);

        PRETTY_INDENT(buf, indent);

        BUF_APPEND_B(buf, '\"');
        BUF_APPEND_S(buf, fm->path);
        BUF_APPEND_S(buf, "\":");

        if (fm->mod == none_mod || fm->mod == ptr_mod) {
            size_t flen;
            if (ftm->jsonifier) {
                CHECK_APPEND(ftm->jsonifier(f_ptr, buf, indent + 1, flags));
            }
            else {
                CHECK_APPEND(write_model_to_buf(f_ptr, ftm, buf, indent + 1, flags));
            }
        }
        else if (fm->mod == map_mod) {
            indent++;
            model_map *map = (model_map *) f_addr;
            const char *k;
            void *v;
            BUF_APPEND_B(buf, '{');
            bool need_comma = false;
            MODEL_MAP_FOREACH(k, v, map) {
                if (need_comma) {
                    BUF_APPEND_B(buf, ',');
                }
                PRETTY_NL(buf);
                PRETTY_INDENT(buf, indent);

                BUF_APPEND_B(buf, '\"');
                BUF_APPEND_S(buf, k);
                BUF_APPEND_S(buf, "\":");
                if (ftm->jsonifier) {
                    CHECK_APPEND(ftm->jsonifier(v, buf, indent + 1, flags));
                }
                else {
                    CHECK_APPEND(write_model_to_buf(v, ftm, buf, indent + 1, flags));
                }
                need_comma = true;
            }
            BUF_APPEND_B(buf, '}');
            indent--;
        }
        else if (fm->mod == array_mod) {
            void **arr = (void **) (*f_addr);

            int idx = 0;
            BUF_APPEND_B(buf, '[');
            for (idx = 0; true; idx++) {
                f_ptr = arr[idx];
                if (f_ptr == NULL) { break; }
                if (idx > 0) {
                    BUF_APPEND_B(buf, ',');
                }

                size_t ellen;
                if (ftm->jsonifier) {
                    CHECK_APPEND(ftm->jsonifier(f_ptr, buf, indent + 1, flags));
                }
                else {
                    CHECK_APPEND(write_model_to_buf(f_ptr, ftm, buf, indent + 1, flags));
                }
            }
            BUF_APPEND_B(buf, ']');
        }
        else {
            ZITI_LOG(ERROR, "unsupported mod[%d] for field[%s]", fm->mod, fm->name);
            return -1;
        }
        comma = true;
    }
    PRETTY_NL(buf);
    PRETTY_INDENT(buf, indent);
    BUF_APPEND_B(buf, '}');
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
                    if (fm->meta() == get_string_meta()) {
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
                if (fm->meta() == get_string_meta() || fm->meta() == get_json_meta()) {
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

            if (fm->meta() == get_string_meta()) {
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
    if (meta->parser) {
        return meta->parser(obj, json, tok);
    }

    if (tok->type != JSMN_OBJECT) {
        return -1;
    }
    int tokens_processed = 1;
    int children = tok->size;
    tok++;
    while (children != 0) {
        if (tok->type != JSMN_STRING) {
            ZITI_LOG(ERROR, "parsing[%s] error: unexpected token starting at `%.*s'", meta->name, 20, json + tok->start);
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
        tok++;
        if (tok->type == JSMN_PRIMITIVE && json[tok->start] == 'n') {
            tok++;
            tokens_processed++;
        } else if (fm != NULL) {
            void *field = (char *) obj + fm->offset;
            if (fm->mod == array_mod) {
                rc = parse_array(field, json, tok, fm->meta());
            } else if (fm->mod == map_mod) {
                rc = parse_map(field, json, tok, fm->meta());
            }
            else {
                char *memobj = NULL;
                if (fm->mod == none_mod) {
                    memobj = (char *) (field);
                } else if (fm->mod == ptr_mod) {
                    memobj = (char *) calloc(1, fm->meta()->size);
                    *(char **) field = memobj;
                }
                if (memobj == NULL) {
                    ZITI_LOG(ERROR, "member[%s] not found", fm->name);
                    return -1;
                }

                if (fm->meta()->parser != NULL) {
                    rc = fm->meta()->parser(memobj, json, tok);
                } else {
                    rc = parse_obj(memobj, json, tok, fm->meta());
                }
            }
            if (rc < 0) {
                return rc;
            }
            tok += rc;
            tokens_processed += rc;
        } else {
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
                    case 'u': {
                        uint32_t rune = 0;
                        for (int i = 0; i<4; i++) {
                            uint8_t c = *++in;
                            if (c >= '0' && c <= '9') {
                                rune = (rune << 4) + (c - '0');
                            } else if (c >= 'a' && c <= 'f') {
                                rune = (rune << 4) + (c - 'a' + 10);
                            } else if (c >= 'A' && c <= 'F') {
                                rune = (rune << 4) + (c - 'A' + 10);
                            } else {
                                ZITI_LOG(ERROR, "invalid '\\u' escape");
                                return -1;
                            }
                        }

                        if (rune < (1<<7) - 1) {
                            *out++ = (uint8_t)rune;
                        } else if (rune < (1<<11) - 1) {
                            *out++ = (uint8_t) ( (RUNE_B2) | (rune >> 6) );
                            *out++ = (uint8_t) ( RUNE_B1 | (rune & RUNE_MASK) );
                        } else if (rune < (1<<16) - 1) {
                            *out++ = (uint8_t) ( RUNE_B3 | (rune >> 12) );
                            *out++ = (uint8_t) ( RUNE_B1 | ((rune >> 6) & RUNE_MASK));
                            *out++ = (uint8_t) ( RUNE_B1 | (rune & RUNE_MASK) );
                        } else {
                            *out++ = (uint8_t) ( RUNE_B4 | (rune >> 18) );
                            *out++ = (uint8_t) ( RUNE_B1 | ((rune >> 12) & RUNE_MASK) );
                            *out++ = (uint8_t) ( RUNE_B1 | ((rune >> 6) & RUNE_MASK));
                            *out++ = (uint8_t) ( RUNE_B1 | (rune & RUNE_MASK) );
                        }
                        break;
                    }
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


static int _cmp_bool(const bool *lh, const bool *rh) {
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
    null_checks(*lh, *rh)

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

static int null_to_json(string_buf_t *buf, int indent, int flags) {
    return string_buf_append(buf, "null");
}

static int bool_to_json(bool *v, string_buf_t *buf, int indent, int flags) {
    return string_buf_append(buf, *v ? "true" : "false");
}

static int int_to_json(const int *v, string_buf_t *buf, int indent, int flags) {

    char b[16];
    int rc = snprintf(b, sizeof(b), "%d", *v);
    if (rc > 0) {
        return string_buf_append(buf, b);
    }
    return rc;
}

static int string_to_json(const char *str, string_buf_t *buf, int indent, int flags) {
    static char hex[] = "0123456789abcdef";

    BUF_APPEND_B(buf, '\"');
    const unsigned char *s = (const unsigned char *) str;

    while (*s != '\0') {
        switch (*s) {
            case '\n':
                BUF_APPEND_S(buf, "\\n");
                break;
            case '\b':
                BUF_APPEND_S(buf, "\\b");
                break;
            case '\r':
                BUF_APPEND_S(buf, "\\r");
                break;
            case '\t':
                BUF_APPEND_S(buf, "\\t");
                break;
            case '\\':
                BUF_APPEND_S(buf, "\\\\");
                break;
            case '"':
                BUF_APPEND_S(buf, "\\\"");
                break;
            default:
                if (*s < ' ') {
                    BUF_APPEND_B(buf, '\\');
                    BUF_APPEND_S(buf, "u00");
                    BUF_APPEND_B(buf, hex[*s >> 4]);
                    BUF_APPEND_B(buf, hex[*s & 0xF]);
                } else {
                    BUF_APPEND_B(buf, *s);
                }
        }
        s++;
    }
    BUF_APPEND_B(buf, '"');
    return 0;
}

static int tag_to_json(tag *t, string_buf_t *buf, int indent, int flags) {
    int rc;
    switch (t->type) {
        case tag_null:
            rc = string_buf_append(buf, "null");
            break;
        case tag_bool:
            rc = string_buf_append(buf, t->bool_value ? "true" : "false");
            break;
        case tag_number:
            rc = int_to_json(&t->num_value, buf, indent, flags);
            break;
        case tag_string:
            return string_to_json(t->string_value, buf, indent, flags);
            break;
    }
    return rc;
}

static int json_to_json(const char *s, string_buf_t *buf, int indent, int flags) {
    return string_buf_append(buf, s);
}

static int timeval_to_json(timestamp *t, string_buf_t *buf, int indent, int flags) {
    struct tm tm2;
#if _WIN32
    _gmtime32_s(&tm2, &t->tv_sec);
#else
    gmtime_r(&t->tv_sec, &tm2);
#endif

    char json[32];
    int rc = snprintf(json, sizeof(json), "\"%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ\"",
                      tm2.tm_year + 1900, tm2.tm_mon + 1, tm2.tm_mday,
                      tm2.tm_hour, tm2.tm_min, tm2.tm_sec, t->tv_usec);

    return string_buf_append(buf, json);
}

static int map_to_json(model_map *map, string_buf_t *buf, int indent, int flags) {
    BUF_APPEND_B(buf, '{');

    const char *key;
    const char *val;
    size_t l;
    bool comma = false;
    MODEL_MAP_FOREACH(key, val, map) {
        if (comma) {
            BUF_APPEND_B(buf, ',');
        }
        PRETTY_NL(buf);
        PRETTY_INDENT(buf, indent + 1);
        string_to_json(key, buf, indent, flags);
        BUF_APPEND_B(buf, ':');

        json_to_json(val, buf, indent, flags);
        comma = true;
    }
    PRETTY_INDENT(buf, indent);
    BUF_APPEND_B(buf, '}');
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

struct generic_enum_s {
    const char* (*name)(int v);
    int (*value_of)(const char* n);
    int (*value_ofn)(const char* s, size_t len);
};

int parse_enum(void *ptr, const char *json, void *tok, const void *enum_type) {
    const struct generic_enum_s *en = enum_type;
    int *enum_p = ptr;
    jsmntok_t *token = tok;

    if (token->type == JSMN_STRING) {
        *enum_p = en->value_ofn(json + token->start, token->end - token->start);
    } else {
        return -1;
    }
    return 1;
}

int json_enum(const void *ptr, void *bufp, int indent, int flags, const void *enum_type) {
    string_buf_t *buf = bufp;
    int en_val = *(int *) ptr;
    const struct generic_enum_s *en = enum_type;

    if (en_val == 0) { // Enum_Unknown
        return null_to_json(buf, indent, flags);
    }

    return string_to_json(en->name(en_val), buf, indent, flags);
}


int model_map_compare(const model_map *lh, const model_map *rh, type_meta *m) {
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
            ZITI_LOG(ERROR, "parsing[map] error: unexpected token starting at `%.*s'", 20, json + tok->start);
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
        .jsonifier = (_to_json_f) (bool_to_json),
        .destroyer = _free_noop,
};

static type_meta int_META = {
        .size = sizeof(int),
        .comparer = (_cmp_f) _cmp_int,
        .parser = (_parse_f) _parse_int,
        .jsonifier = (_to_json_f) int_to_json,
        .destroyer = _free_noop,
};

static type_meta string_META = {
        .size = sizeof(char *),
        .comparer = (_cmp_f) _cmp_string,
        .parser = (_parse_f) _parse_string,
        .jsonifier = (_to_json_f) string_to_json,
        .destroyer = (_free_f) _free_string,
};

static type_meta timestamp_META = {
        .size = sizeof(struct timeval),
        .comparer = (_cmp_f) _cmp_timeval,
        .parser = (_parse_f) _parse_timeval,
        .jsonifier = (_to_json_f) timeval_to_json,
        .destroyer = (_free_f) _free_noop,
};

static type_meta json_META = {
        .size = sizeof(char *),
        .comparer = (_cmp_f) _cmp_string,
        .parser = (_parse_f) _parse_json,
        .jsonifier = (_to_json_f) json_to_json,
        .destroyer = (_free_f) _free_string,
};

static type_meta map_META = {
        .size = sizeof(model_map),
        .comparer = (_cmp_f) _cmp_map,
        .parser = (_parse_f) _parse_map,
        .jsonifier = (_to_json_f) map_to_json,
        .destroyer = (_free_f) _free_map,
};

static type_meta tag_META = {
        .size = sizeof(tag),
        .comparer = (_cmp_f) _cmp_tag,
        .parser = (_parse_f) _parse_tag,
        .jsonifier = (_to_json_f) tag_to_json,
        .destroyer = (_free_f) _free_tag,

};

type_meta *get_bool_meta() { return &bool_META; }

type_meta *get_int_meta() { return &int_META; }

type_meta *get_string_meta() { return &string_META; }

type_meta *get_timestamp_meta() { return &timestamp_META; }

type_meta *get_json_meta() { return &json_META; }

type_meta *get_model_map_meta() { return &map_META; }

type_meta *get_tag_meta() { return &tag_META; }