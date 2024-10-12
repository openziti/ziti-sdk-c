// Copyright (c) 2020-2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include <ziti/model_support.h>
#include <buffer.h>
#include <utils.h>

#if _WIN32
#include <time.h>
#define timegm(v) _mkgmtime(v)
#else
//add time.h include after defining _GNU_SOURCE
#define _GNU_SOURCE // NOLINT

#include <time.h>

#endif

#define null_checks(lh, rh) \
    if ((lh) == (rh)) { return 0; } \
    if ((lh) == NULL) { return -1; } \
    if ((rh) == NULL) { return 1; }

// NOLINTNEXTLINE(misc-no-recursion)
int model_cmp(const void *lh, const void *rh, const type_meta *meta) {
    null_checks(lh, rh)

    if (meta->comparer) {
        return meta->comparer(lh, rh);
    }

    int rc = 0;
    for (int i = 0; rc == 0 && i < meta->field_count; i++) {
        field_meta *fm = meta->fields + i;
        const type_meta *ftm = fm->meta();

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
        } else if (fm->mod == list_mod) {
            model_list *ll = (model_list *) (lf_addr);
            model_list *rl = (model_list *) (rf_addr);

            model_list_iter lit = model_list_iterator(ll);
            model_list_iter rit = model_list_iterator(rl);

            if (lit == NULL && rit != NULL) { rc = 1; }
            else {
                while (rc == 0) {
                    lf_ptr = model_list_it_element(lit);
                    lit = model_list_it_next(lit);
                    rf_ptr = model_list_it_element(rit);
                    rit = model_list_it_next(rit);
                    if (rf_ptr == NULL && lf_ptr == NULL) { break; }

                    if (ftm->comparer) {
                        if (fm->meta() == get_model_string_meta() ||
                            fm->meta() == get_json_meta() ||
                            fm->meta() == get_model_number_meta() ||
                            fm->meta() == get_model_bool_meta()) {
                            rc = ftm->comparer(&lf_ptr, &rf_ptr);
                        } else {
                            rc = ftm->comparer(lf_ptr, rf_ptr);
                        }
                    } else {
                        rc = model_cmp(lf_ptr, rf_ptr, ftm);
                    }
                }
            }

        } else if (fm->mod == array_mod) {
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
                        if (fm->meta() == get_model_string_meta()) {
                            rc = ftm->comparer(&lf_ptr, &rf_ptr);
                        }
                        else {
                            rc = ftm->comparer(lf_ptr, rf_ptr);
                        }
                    } else {
                        rc = model_cmp(lf_ptr, rf_ptr, ftm);
                    }
                }
            }
        }
    }

    return rc;
}

int model_parse_list(model_list *list, const char *json, size_t len, const type_meta *meta) {
    struct json_tokener *tok = json_tokener_new();
    json_object *j = json_tokener_parse_ex(tok, json, (int)len);
    int res;
    if (j == NULL) {
        res = (json_tokener_get_error(tok) == json_tokener_continue) ?
              MODEL_PARSE_PARTIAL : MODEL_PARSE_INVALID;
        json_tokener_free(tok);
        return res;
    }

    size_t end = json_tokener_get_parse_end(tok);

    int result = model_list_from_json(list, j, meta);
    if (result < 0) {
        model_list_iter it = model_list_iterator(list);
        while (it != NULL) {
            void *el = model_list_it_element(it);
            it = model_list_it_remove(it);
            if (el != NULL) {
                model_free(el, meta);
                FREE(el);
            }
        }
    }
    json_tokener_free(tok);
    json_object_put(j);
    return result == 0 ? (int)end : result;
}

int model_parse_array(void ***arrp, const char *json, size_t len, const type_meta *meta) {
    struct json_tokener *tok = json_tokener_new();
    json_object *j = json_tokener_parse_ex(tok, json, (int)len);
    int res;
    if (j == NULL) {
        res = (json_tokener_get_error(tok) == json_tokener_continue) ?
                  MODEL_PARSE_PARTIAL : MODEL_PARSE_INVALID;
        json_tokener_free(tok);
        return res;
    }

    size_t end = json_tokener_get_parse_end(tok);

    void **arr = NULL;
    res = (int)json_tokener_get_parse_end(tok);
    if (model_array_from_json(&arr, j, meta) != 0) {
        res = -1;
        for (int i = 0; arr != NULL && arr[i] != NULL; i++) {
            model_free(arr[i], meta);
            free(arr[i]);
        }
        FREE(arr);
    }
    *arrp = arr;
    json_tokener_free(tok);
    json_object_put(j);
    return res == 0 ? (int)end : res;
}

int model_parse(void *obj, const char *json, size_t len, const type_meta *meta) {
    struct json_tokener *tok = json_tokener_new();
    struct json_object *j = json_tokener_parse_ex(tok, json, (int) len);
    int res;
    if (j == NULL) {
        enum json_tokener_error e = json_tokener_get_error(tok);
        if (e == json_tokener_continue) {
            res = MODEL_PARSE_PARTIAL;
        } else {
            ZITI_LOG(WARN, "json parse error: %s", json_tokener_error_desc(e));
            res = MODEL_PARSE_INVALID;
        }
    } else {
        res = (int)json_tokener_get_parse_end(tok);
        if (model_from_json(obj, j, meta) == -1) {
            model_free(obj, meta);
            res = -1;
        }
    }
    size_t end = json_tokener_get_parse_end(tok);

    json_tokener_free(tok);
    json_object_put(j);
    return res == 0 ? (int)end : res;
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
        result = (ssize_t)string_buf_size(&json);
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

    if (meta->jsonifier) {
        return meta->jsonifier(obj, buf, indent, flags);
    }

    BUF_APPEND_S(buf, "{");
    bool comma = false;
    for (int i = 0; i < meta->field_count; i++) {
        field_meta *fm = meta->fields + i;

        if (fm->path == NULL || fm->path[0] == 0) {
            continue;
        }
        const type_meta *ftm = fm->meta();

        void **f_addr = (void **) ((char *) obj + fm->offset);
        void *f_ptr = fm->mod == none_mod ? f_addr : (void *) (*f_addr);

        if (ftm == get_model_string_meta() || ftm == get_json_meta()) {
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
                } else {
                    CHECK_APPEND(write_model_to_buf(v, ftm, buf, indent + 1, flags));
                }
                need_comma = true;
            }
            BUF_APPEND_B(buf, '}');
            indent--;
        } else if (fm->mod == list_mod) {
            model_list *list = (model_list *) (f_addr);

            int idx = 0;
            BUF_APPEND_B(buf, '[');
            MODEL_LIST_FOREACH(f_ptr, *list) {
                if (f_ptr == NULL) { break; }
                if (idx++ > 0) {
                    BUF_APPEND_B(buf, ',');
                }

                if (ftm->jsonifier) {
                    if (ftm == get_model_number_meta() || ftm == get_model_bool_meta()) {
                        CHECK_APPEND(ftm->jsonifier(&f_ptr, buf, indent + 1, flags));
                    } else {
                        CHECK_APPEND(ftm->jsonifier(f_ptr, buf, indent + 1, flags));
                    }
                } else {
                    CHECK_APPEND(write_model_to_buf(f_ptr, ftm, buf, indent + 1, flags));
                }
            }
            BUF_APPEND_B(buf, ']');
        } else if (fm->mod == array_mod) {
            void **arr = (void **) (*f_addr);

            BUF_APPEND_B(buf, '[');
            for (int idx = 0; true; idx++) {
                f_ptr = arr[idx];
                if (f_ptr == NULL) { break; }
                if (idx > 0) {
                    BUF_APPEND_B(buf, ',');
                }

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

void model_free_array(void ***ap, const type_meta *meta) {
    if (ap == NULL || *ap == NULL) { return; }

    void **el = *ap;
    while (*el != NULL) {
        model_free(*el, meta);
        free(*el);
        el++;
    }
    FREE(*ap);
}

void model_free(void *obj, const type_meta *meta) {
    if (obj == NULL) { return; }

    if (meta->destroyer != NULL) {
        return meta->destroyer(obj);
    }

    for (int i = 0; i < meta->field_count; i++) {
        field_meta *fm = &meta->fields[i];
        void **f_addr = (void **) ((char *) obj + fm->offset);
        void *f_ptr = NULL;
        const type_meta *field_meta = fm->meta();
        if (fm->mod == none_mod) {
            f_ptr = f_addr;
            model_free(f_ptr, field_meta);
        }
        else if (fm->mod == ptr_mod) {
            f_ptr = (void *) (*f_addr);
            *f_addr = NULL;
            if (f_ptr != NULL) {
                model_free(f_ptr, field_meta);
                free(f_ptr);
            }
        }
        else if (fm->mod == array_mod) {
            void **arr = (void **) (*f_addr);
            *f_addr = NULL;
            if (arr != NULL) {
                for (int idx = 0; arr[idx] != NULL; idx++) {
                    f_ptr = arr + idx;
                    if (field_meta == get_model_string_meta()) {
                        model_free(f_ptr, field_meta);
                    }
                    else {
                        void *mem_ptr = (void *) (*(void **) f_ptr);
                        model_free(mem_ptr, field_meta);
                        free(mem_ptr);
                    }
                }
                free(arr);
            }
        } else if (fm->mod == list_mod) {
            model_list *list = (model_list *) f_addr;
            model_list_iter it = model_list_iterator(list);
            bool str_type = (field_meta == get_model_string_meta() || field_meta == get_json_meta());
            while (it != NULL) {
                void *el = model_list_it_element(it);
                it = model_list_it_remove(it);
                if (str_type) {
                    field_meta->destroyer(&el);
                }
                else if (field_meta->destroyer) {
                    field_meta->destroyer(el);
                }
                else {
                    model_free(el, field_meta);
                    free(el);
                }
            }
            model_list_clear(list, NULL);
        } else if (fm->mod == map_mod) {
            model_map *map = (model_map *) f_addr;
            _free_f ff = NULL;
            model_map_iter it = model_map_iterator(map);
            while (it != NULL) {
                void *v = model_map_it_value(it);
                if (field_meta == get_model_string_meta() || field_meta == get_json_meta()) {
                    field_meta->destroyer(&v);
                }
                else if (field_meta->destroyer) {
                    field_meta->destroyer(v);
                }
                else {
                    model_free(v, field_meta);
                }
                free(v);

                it = model_map_it_remove(it);
            }

            if (field_meta == get_model_string_meta()) {
                ff = free;
            }
            else {
                ff = field_meta->destroyer;
            }
            model_map_clear(map, ff);
        }
    }
}


int model_array_from_json(void ***arr, json_object *json, const type_meta *el_meta) {
    if (json_object_get_type(json) != json_type_array) {
        ZITI_LOG(ERROR, "unexpected token, array as expected");
        return -1;
    }
    size_t children = json_object_array_length(json);
    void **elems = calloc(children + 1, sizeof(void *));
    int idx;
    int rc = 0;
    for (idx = 0; idx < children; idx++) {
        json_object *ch = json_object_array_get_idx(json, idx);
        void *el;
        if (el_meta != get_model_string_meta()) {
            el = calloc(1, el_meta->size);
            elems[idx] = el;
        } else {
            el = &elems[idx];
        }
        if (el_meta->from_json != NULL) {
            rc = el_meta->from_json(el, ch, el_meta);
        } else {
            rc = model_from_json(el, ch, el_meta);
        }
        if (rc < 0) {
            break;
        }
    }
    if (rc != 0) {
        for (int i = 0; elems[i] != NULL; i++) {
            model_free(elems[i], el_meta);
            free(elems[i]);
        }
        FREE(elems);
    }
    *arr = elems;
    return rc;
}

int model_list_from_json (model_list *list, json_object *json, const type_meta *el_meta) {
    if (json_object_get_type(json) != json_type_array) {
        ZITI_LOG(ERROR, "unexpected token, array as expected");
        return -1;
    }
    size_t children = json_object_array_length(json);
    int idx;
    int rc = 0;
    for (idx = 0; idx < children; idx++) {
        json_object *ch = json_object_array_get_idx(json, idx);
        void *value = NULL;
        if (el_meta == get_model_string_meta() ||
            el_meta == get_json_meta() ||
            el_meta == get_model_number_meta() ||
            el_meta == get_model_bool_meta()) {
            rc = el_meta->from_json(&value, ch, el_meta);
        } else {
            value = calloc(1, el_meta->size);
            rc = el_meta->from_json ?
                 el_meta->from_json(value, ch, el_meta) :
                 model_from_json(value, ch, el_meta);
        }
        if (rc < 0) {
            break;
        }
        model_list_append(list, value);
    }

    if (rc != 0) {
        model_list_iter it = model_list_iterator(list);
        while (it) {
            void* val = model_list_it_element(it);
            model_free(val, el_meta);
            free(val);
            it = model_list_it_remove(it);
        }
    }
    return rc;
}

static int parse_map_from_json(void *mapp, json_object *json, type_meta *el_meta) {
    if (json_object_get_type(json) != json_type_object) {
        ZITI_LOG(ERROR, "unexpected token: object as expected, received %d", json_object_get_type(json));
        return -1;
    }
    model_map *map = mapp;
    json_object_object_foreach(json, key, child) {
        void *value = NULL;
        int rc;
        if (el_meta == get_model_string_meta()) {
            rc = get_model_string_meta()->from_json(&value, child, el_meta);
        }
        else if (el_meta == get_json_meta()) {
            rc = get_json_meta()->from_json(&value, child, el_meta);
        }
        else {
            value = calloc(1, el_meta->size);
            rc = el_meta->from_json ?
                 el_meta->from_json(value, child, el_meta) :
                 model_from_json(value, child, el_meta);
        }
        if (rc < 0) {
            FREE(value);
            return rc;
        }
        model_map_set(map, key, value);
    }
    return 0;
}

int model_from_json(void *obj, json_object *json, const type_meta *meta) {
    int rc = 0;
    memset(obj, 0, meta->size);
    if (meta->from_json) {
        rc = meta->from_json(obj, json, meta);
        goto done;
    }

    if (json_object_get_type(json) != json_type_object) {
        rc = -1;
        goto done;
    }

    for (int fi = 0; fi < meta->field_count; fi++) {
        // field is not mapped to JSON
        const field_meta *fm = &meta->fields[fi];
        if (fm->path == NULL || fm->path[0] == 0)
            continue;

        json_object *child = json_object_object_get(json, fm->path);
        if (child == NULL || json_object_get_type(child) == json_type_null)
            continue;

        void *field = (char *) obj + fm->offset;
        void *ch_obj = field;
        const type_meta *ch_meta = fm->meta();
        from_json_func parser = ch_meta->from_json;
        if (parser == NULL) {
            parser = model_from_json;
        }
        
        switch (fm->mod) {
            case none_mod:
                break;
            case ptr_mod:
                ch_obj = calloc(1, ch_meta->size);
                *(char**)field = ch_obj;
                break;
            case array_mod:
                parser = (from_json_func) model_array_from_json;
                break;
            case map_mod:
                parser = (from_json_func) parse_map_from_json;
                break;
            case list_mod:
                parser = (from_json_func) model_list_from_json;
                break;
        }
        rc = parser(ch_obj, child, ch_meta);
        if (rc != 0) {
            break;
        }
    }

    done:
    if (rc != 0) {
        model_free(obj, meta);
    }
    return rc;
}

static int int_from_json(model_number *val, const json_object *j, const type_meta * UNUSED(meta)) {
    if (json_object_get_type(j) == json_type_int) {
        *val = (model_number)json_object_get_int64(j);
        return 0;
    }
    return -1;
}

static json_object* int_to_json(const model_number *val) {
    if (val == NULL) {
        return NULL;
    }
    return json_object_new_int64(*val);
}

static int bool_from_json(bool *val, struct json_object *json, const type_meta * UNUSED(meta)) {
    if (json_object_get_type(json) == json_type_boolean) {
        *val = json_object_get_boolean(json);
        return 0;
    }
    return -1;
}

static json_object* bool_to_json(const bool *val) {
    if (val == NULL) {
        return NULL;
    }
    return json_object_new_boolean(*val);
}

static int json_from_json(model_string *val, json_object *j, type_meta * UNUSED(meta)) {
    *val = strdup(json_object_to_json_string(j));
    return 0;
}

static json_object* json_to_json(model_string val) {
    return json_tokener_parse(val);
}

static int string_from_json (model_string *str, json_object *j, const type_meta * UNUSED(meta)) {
    if (json_object_get_type(j) == json_type_string) {
        *str = strdup(json_object_get_string(j));
        return 0;
    }
    return -1;
}

static json_object * string_to_json(model_string str) {
    return json_object_new_string(str);
}

static json_object* tag_to_json(const tag *t) {
    switch (t->type) {
        case tag_null:
            return json_object_new_null();
        case tag_bool:
            return json_object_new_boolean(t->bool_value);
        case tag_number:
            return json_object_new_int64(t->num_value);
        case tag_string:
            return json_object_new_string(t->string_value);
    }
    return NULL;
}

static int tag_from_json(tag *t, json_object *j, type_meta * UNUSED(m)) {
    int rc;
    switch (json_object_get_type(j)) {
        case json_type_boolean:
            rc = bool_from_json(&t->bool_value, j, get_model_bool_meta());
            t->type = tag_bool;
            break;
        case json_type_int:
            rc = int_from_json(&t->num_value, j, get_model_number_meta());
            t->type = tag_number;
            break;
        case json_type_string:
            rc = string_from_json(&t->string_value, j, get_model_string_meta());
            t->type = tag_string;
            break;
        default:
            rc = -1;
    }
    return rc;
}

static int timeval_from_json(timestamp *t, json_object *j, type_meta * UNUSED(meta)) {
    if (json_object_get_type(j) == json_type_string) {
        struct tm t2 = {0};
        // "2019-08-05T14:02:52.337619Z"
        unsigned long usec;
        sscanf(json_object_get_string(j), "%d-%d-%dT%d:%d:%d.%ldZ",
               &t2.tm_year, &t2.tm_mon, &t2.tm_mday,
               &t2.tm_hour, &t2.tm_min, &t2.tm_sec, &usec);
        t2.tm_year -= 1900;
        t2.tm_mon -= 1;

        t->tv_sec = timegm(&t2);
        t->tv_usec = (int)usec;
        return 0;
    }
    return -1;
}

static int m_cmp_bool(const bool *lh, const bool *rh) {
    null_checks(lh, rh)
    if (*lh == *rh) { return 0; }
    if (!*lh) { return -1; }
    return 1;
}

static int m_cmp_int(const model_number *lh, const model_number *rh) {
    null_checks(lh, rh)
    return (int)(*lh - *rh);
}

static int m_cmp_timeval(const timestamp *lh, const timestamp *rh) {
    null_checks(lh, rh)
    return (int) (lh->tv_sec == rh->tv_sec ? (lh->tv_usec - rh->tv_usec) : (lh->tv_sec - rh->tv_sec));
}

static int m_cmp_string(const char * const * const lh, const char * const * const rh) {
    null_checks(lh, rh)
    null_checks(*lh, *rh)

    return strcmp(*lh, *rh);
}

static int m_cmp_tag(const tag *lh, const tag *rh) {
    null_checks(lh, rh)

    if (lh->type != rh->type) {
        return (int) lh->type - (int) rh->type;
    }

    switch (lh->type) {
        case tag_bool:
            return m_cmp_bool(&lh->bool_value, &rh->bool_value);
        case tag_number:
            return m_cmp_int(&lh->num_value, &rh->num_value);
        case tag_string:
            return m_cmp_string(&lh->string_value, &rh->string_value);
        case tag_null:
            return 0;
    }
}

static int null_to_json(string_buf_t *buf, int UNUSED(indent), int UNUSED(flags)) {
    return string_buf_append(buf, "null");
}

static int m_bool_to_json(const bool *v, string_buf_t *buf, int UNUSED(indent), int UNUSED(flags)) {
    return string_buf_append(buf, *v ? "true" : "false");
}

static int m_int_to_json(const model_number *v, string_buf_t *buf, int UNUSED(indent), int UNUSED(flags)) {

    char b[16];
    int rc = snprintf(b, sizeof(b), "%" PRId64, *v);
    if (rc > 0) {
        return string_buf_append(buf, b);
    }
    return rc;
}

static int m_string_to_json(const char *str, string_buf_t *buf, int UNUSED(indent), int UNUSED(flags)) {
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

static int m_tag_to_json(tag *t, string_buf_t *buf, int indent, int flags) {
    int rc;
    switch (t->type) {
        case tag_null:
            rc = string_buf_append(buf, "null");
            break;
        case tag_bool:
            rc = string_buf_append(buf, t->bool_value ? "true" : "false");
            break;
        case tag_number:
            rc = m_int_to_json(&t->num_value, buf, indent, flags);
            break;
        case tag_string:
            rc = m_string_to_json(t->string_value, buf, indent, flags);
            break;
        default:
            rc = -1;
    }
    return rc;
}

static int m_json_to_json(const char *s, string_buf_t *buf, int UNUSED(indent), int UNUSED(flags)) {
    return string_buf_append(buf, s);
}
static json_object * timeval_to_json(timestamp *t) {
    struct tm tm2;
#if _WIN32
    _gmtime32_s(&tm2, &t->tv_sec);
#else
    gmtime_r(&t->tv_sec, &tm2);
#endif

    char json[32];
    int rc = snprintf(json, sizeof(json), "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
                      tm2.tm_year + 1900, tm2.tm_mon + 1, tm2.tm_mday,
                      tm2.tm_hour, tm2.tm_min, tm2.tm_sec, (unsigned long)t->tv_usec);

    return json_object_new_string_len(json, rc);
}

static int m_timeval_to_json(timestamp *t, string_buf_t *buf, int UNUSED(indent), int UNUSED(flags)) {
    struct tm tm2;
#if _WIN32
    _gmtime32_s(&tm2, &t->tv_sec);
#else
    gmtime_r(&t->tv_sec, &tm2);
#endif

    int rc =  string_buf_fmt(buf, "\"%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ\"",
                             tm2.tm_year + 1900, tm2.tm_mon + 1, tm2.tm_mday,
                             tm2.tm_hour, tm2.tm_min, tm2.tm_sec, (unsigned long)t->tv_usec);
    return rc > 0 ? 0 : -1;
}

static void m_free_noop(void *UNUSED(v)) {}

static void m_free_string(char **s) {
    if (*s != NULL) {
        free(*s);
        *s = NULL;
    }
}

static void m_free_tag(tag *t) {
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

int enum_from_json(void *ptr, json_object *j, const void *enum_type) {
    if (json_object_get_type(j) == json_type_string) {
        const struct generic_enum_s *en = enum_type;
        int *enum_p = ptr;
        *enum_p = en->value_of(json_object_get_string(j));
        return 0;
    }
    return -1;
}

json_object* enum_to_json(const void* ptr, const void *enum_type) {
    const struct generic_enum_s *en = enum_type;
    const int *enum_p = ptr;
    return json_object_new_string(en->name(*enum_p));
}

int json_enum(const void *ptr, void *bufp, int indent, int flags, const void *enum_type) {
    string_buf_t *buf = bufp;
    int en_val = *(int *) ptr;
    const struct generic_enum_s *en = enum_type;

    if (en_val == 0) { // Enum_Unknown
        return null_to_json(buf, indent, flags);
    }

    return m_string_to_json(en->name(en_val), buf, indent, flags);
}


int model_map_compare(const model_map *lh, const model_map *rh, const type_meta *m) {
    null_checks(lh, rh)

    int rc = (int)(model_map_size(lh) - model_map_size(rh));

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
                if (m == get_model_string_meta() || m == get_json_meta()) {
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

static type_meta bool_META = {
        .name = "bool",
        .size = sizeof(bool),
        .comparer = (_cmp_f) m_cmp_bool,
        .jsonifier = (_to_json_f) (m_bool_to_json),
        .destroyer = m_free_noop,
        .from_json = (from_json_func) bool_from_json,
        .to_json = (to_json_func) bool_to_json,
};

static type_meta int_META = {
        .name = "number",
        .size = sizeof(model_number),
        .comparer = (_cmp_f) m_cmp_int,
        .jsonifier = (_to_json_f) m_int_to_json,
        .destroyer = m_free_noop,
        .from_json = (from_json_func) int_from_json,
        .to_json = (to_json_func) int_to_json,
};

static type_meta string_META = {
        .name = "string",
        .size = sizeof(char *),
        .comparer = (_cmp_f) m_cmp_string,
        .jsonifier = (_to_json_f) m_string_to_json,
        .destroyer = (_free_f) m_free_string,
        .from_json = (from_json_func) string_from_json,
        .to_json = (to_json_func) string_to_json,
};

static type_meta timestamp_META = {
        .name = "timestamp",
        .size = sizeof(struct timeval),
        .comparer = (_cmp_f) m_cmp_timeval,
        .jsonifier = (_to_json_f) m_timeval_to_json,
        .destroyer = (_free_f) m_free_noop,
        .from_json = (from_json_func) timeval_from_json,
        .to_json = (to_json_func) timeval_to_json,
};

static type_meta json_META = {
        .name = "json",
        .size = sizeof(char *),
        .comparer = (_cmp_f) m_cmp_string,
        .jsonifier = (_to_json_f) m_json_to_json,
        .destroyer = (_free_f) m_free_string,
        .from_json = (from_json_func) json_from_json,
        .to_json = (to_json_func) json_to_json,
};

static type_meta tag_META = {
        .name = "tag",
        .size = sizeof(tag),
        .comparer = (_cmp_f) m_cmp_tag,
        .jsonifier = (_to_json_f) m_tag_to_json,
        .destroyer = (_free_f) m_free_tag,
        .from_json = (from_json_func)tag_from_json,
        .to_json = (to_json_func)tag_to_json,
};

const type_meta *get_model_bool_meta() { return &bool_META; }

const type_meta *get_model_number_meta() { return &int_META; }

const type_meta *get_model_string_meta() { return &string_META; }

const type_meta *get_timestamp_meta() { return &timestamp_META; }

const type_meta *get_json_meta() { return &json_META; }

const type_meta *get_tag_meta() { return &tag_META; }

static int cmp_duration (const duration *lh, const duration *rh) {
    null_checks(lh, rh)
    duration diff = *lh - *rh;
    return diff < 0 ? -1 : (diff > 0 ? 1 : 0);
}

static int duration_from_json(duration *val, json_object *j, type_meta * UNUSED(meta)) {
    if (json_object_get_type(j) != json_type_string)
        return -1;

    const char *start = json_object_get_string(j);
    const char *end = start + strlen(start);
    char *endp;
    duration v = (duration) strtol(start, &endp, 10);
    size_t tu_len = end - endp;
    if (tu_len == 1) { // single char timeunit: s,m,h
        switch (*endp) {
            case 's': v *= SECOND; break;
            case 'm': v *= MINUTE; break;
            case 'h': v *= HOUR; break;
            default: return -1;
        }
    } else if (tu_len == 2) {
        if (strncmp(endp, "ms", 2) == 0) {
            v *= MILLISECOND;
        } else {
            return -1;
        }
    } else {
        return -1;
    }

    *val = v;
    return 0;
}

static json_object* duration_to_json(const duration *d) {
    char json[32];
    int rc = snprintf(json, sizeof(json), "%lldms", (long long)DURATION_MILLISECONDS(*d));
    return json_object_new_string_len(json, rc);
}

static int m_duration_to_json(const duration *d, string_buf_t *buf, int UNUSED(indent), int UNUSED(flags)) {
    char json[32];
    int rc = snprintf(json, sizeof(json), "\"%lldms\"", (long long)DURATION_MILLISECONDS(*d));
    if (rc < 0) return -1;
    return string_buf_appendn(buf, json, rc);
}

const type_meta *get_duration_meta() {
    static type_meta _meta = {
            .name = "duration",
            .comparer = (_cmp_f) cmp_duration,
            .jsonifier = (_to_json_f) m_duration_to_json,
            .destroyer = m_free_noop,
            .from_json = (from_json_func) duration_from_json,
            .to_json = (to_json_func) duration_to_json,
    };
    return &_meta;
}
