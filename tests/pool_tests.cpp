/*
Copyright (c) 2022 NetFoundry, Inc.

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
#include <pool.h>
#include <cstring>

struct foo {
    uint32_t num;
    char *str;
};

void clear_foo(void *f) {
    auto *f1 = static_cast<foo *>(f);
    free(f1->str);
}

TEST_CASE("pool1", "[util]") {
    pool_t *pool = pool_new(sizeof(foo), 2, clear_foo);

    struct foo *f1, *f2, *f3;

    f1 = (foo *) pool_alloc_obj(pool);
    CHECK(f1->num == 0);
    CHECK(f1->str == nullptr);
    f1->num = 100;
    f1->str = strdup("this is a message");
    pool_return_obj(f1);

    f1 = (foo *) pool_alloc_obj(pool);
    CHECK(f1->num == 0);
    CHECK(f1->str == nullptr);

    f2 = (foo *) pool_alloc_obj(pool);
    CHECK(f2->num == 0);
    CHECK(f2->str == nullptr);

    f3 = (foo *) pool_alloc_obj(pool);
    CHECK(f3 == nullptr);

    pool_return_obj(f1);
    pool_return_obj(f2);
    pool_destroy(pool);
}
