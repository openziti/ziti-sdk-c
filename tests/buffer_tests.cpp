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

TEST_CASE("buffer append", "[util]") {
    string_buf_t json_buf;
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

TEST_CASE("buffer fmt", "[util]") {
    string_buf_t fmt_buf;
    write_buf_init(&fmt_buf);

    fmt_buf.chunk_size = 160;

    std::string test_str;

    for (int i = 0; i < 1000; i++) {
        write_buf_fmt(&fmt_buf, "%04d\n", i);
        char num[16];
        snprintf(num, 16, "%04d\n", i);
        test_str += num;
    }

    size_t size = write_buf_size(&fmt_buf);
    CHECK(size == test_str.size());
    CHECK(size == 1000*5);

    size_t len;
    char *result = write_buf_to_string(&fmt_buf, &len);
    CHECK(len == test_str.size());
    CHECK(write_buf_size(&fmt_buf) == 0);
    CHECK_THAT(result, Catch::Equals(test_str));

    free(result);
    write_buf_free(&fmt_buf);
}



