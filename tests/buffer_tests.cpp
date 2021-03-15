/*
Copyright (c) 2021 NetFoundry, Inc.

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

#include <buffer.h>
#include <iostream>

#define WRITE_BUF(name) struct name { \
    buffer *buf; \
    uint8_t *chunk; \
    uint8_t *wp; \
}

#define WRITE_BUF_APPEND(b, s, n) do{ \
    if ((b)->chunk == NULL) {             \
        (b)->chunk = malloc(16);              \
        (b)->wp = chunk;\
    }                               \
    if ((b)->wp - (b)->chunk + (n) > 16) {\
        if ((b)->buf == NULL) (b)->buf = new_buffer(); \
        buffer_append((b)->buf, (b)->chunk, wp - (b)->chunk);\
    }\
} while(0)

TEST_CASE("buffer append", "[util]") {
    write_buf_t json_buf;
    write_buf_init(&json_buf);

    std::string test_str;

    for (int i = 0; i < 10; i++) {
        write_buf_append(&json_buf, "this is a string\n");
        test_str += "this is a string\n";
    }

    size_t len;
    char *result = write_buf_to_string(&json_buf, &len);

    CHECK_THAT(result, Catch::Equals(test_str));
    CHECK(len == test_str.size());

    write_buf_free(&json_buf);
}

