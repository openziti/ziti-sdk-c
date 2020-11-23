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

#include <ziti/model_support.h>
#include <string.h>


static const int buckets = 64;

TEST_CASE("model bench", "[model]") {
    char key[128];
    model_map m = {nullptr};
    for (int i = 0; i < 50000; i++) {
        snprintf(key, sizeof(key), "key%d", i);
        model_map_set(&m, key, strdup(key));
    }

    for (int i = 0; i < 50000; i++) {
        snprintf(key, sizeof(key), "key%d", i);
        void *val = model_map_remove(&m, key);
        free(val);
    }

    model_map_clear(&m, nullptr);
}
