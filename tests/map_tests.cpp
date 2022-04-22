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

#include "catch2/catch.hpp"

#include <ziti/model_map.h>
#include <string.h>


static const int buckets = 64;

TEST_CASE("model bench", "[model]") {
    char key[128];
    model_map m = {nullptr};
    for (int i = 0; i < 50000; i++) {
        snprintf(key, sizeof(key), "key%d", i);
        model_map_set(&m, key, strdup(key));
    }

    model_map_iter it = model_map_iterator(&m);

    int i = 0;
    while(it != nullptr) {
        void *val = model_map_it_value(it);
        if (i++ % 2 == 0) {
            free(val);
            it = model_map_it_remove(it);
        } else {
            it = model_map_it_next(it);
        }
    }

    for (i = 0; i < 50000; i++) {
        snprintf(key, sizeof(key), "key%d", i);
        void *val = model_map_remove(&m, key);
        if (val) { free(val); }
    }

    model_map_clear(&m, nullptr);
}

TEST_CASE("map[long->str] bench", "[model]") {
    char key[128];
    model_map m = {nullptr};
    for (int i = 0; i < 50000; i++) {
        snprintf(key, sizeof(key), "%d", i);
        model_map_setl(&m, i, strdup(key));
    }

    for (int i = 0; i < 50000; i++) {
        const char *val = static_cast<const char *>(model_map_getl(&m, i));
        CHECK(i == atol(val));
    }

    model_map_iter it = model_map_iterator(&m);

    while (it != nullptr) {
        char *val = static_cast<char *>(model_map_it_value(it));
        long k = model_map_it_lkey(it);
        REQUIRE(k == atol(val));
        if (k % 2 == 0) {
            free(val);
            it = model_map_it_remove(it);
        } else {
            it = model_map_it_next(it);
        }
    }

    model_map_clear(&m, nullptr);
}

TEST_CASE("remove last element", "[model]") {
    model_map m = {nullptr};
    char key[128];
    for (int i = 0; i < 50; i++) {
        snprintf(key, sizeof(key), "%d", i);
        model_map_setl(&m, i, strdup(key));
    }

    for (int i = 0; i < 50; i++) {
        auto val = model_map_removel(&m, i);
        free(val);
    }

    REQUIRE(m.impl == nullptr);
}

TEST_CASE("it remove last element", "[model]") {
    model_map m = {nullptr};
    char key[128];
    for (int i = 0; i < 50; i++) {
        snprintf(key, sizeof(key), "%d", i);
        model_map_setl(&m, i, strdup(key));
    }

    auto it = model_map_iterator(&m);
    while(it != nullptr) {
        auto val = model_map_it_value(it);
        it = model_map_it_remove(it);
        free(val);
    }

    REQUIRE(m.impl == nullptr);
}