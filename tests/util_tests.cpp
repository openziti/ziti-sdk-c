// Copyright (c) 2023.  NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "catch2/catch_test_macros.hpp"
#include "catch2/matchers/catch_matchers_string.hpp"
#include "utils.h"
#include "internal_model.h"
#include "zt_internal.h"

#if _WIN32
#include <io.h>
#define dup2(o,n) _dup2(o,n)
#else
#include <unistd.h>
#endif

TEST_CASE("read_file", "[util]") {
    const char *test_path = TO_STRING(ZITI_TEST_DIR) "/ctrl_tests.cpp";
    char *content = nullptr;
    size_t size;
    int rc = load_file(test_path, 0, &content, &size);
    CHECK(rc == 0);
    CHECK(size > 0);

    char *orig_content = content;
    size_t orig_size = size;
    CHECK(load_file(test_path, 0, &content, &size) == 0);
    CHECK(orig_content == content); // copy into provided buffer
    CHECK(orig_size == size);

    size = size / 2;
    CHECK(load_file(test_path, 0, &content, &size) == UV_ENOMEM);

    free(content);
}

TEST_CASE("read_file_not_found", "[util]") {
    const char *test_path = TO_STRING(ZITI_TEST_DIR) "/ctrl_tests.cpp.not-there";
    char *content = nullptr;
    size_t size;
    int rc = load_file(test_path, 0, &content, &size);
    CHECK(rc == UV_ENOENT);
    CHECK(content == nullptr);
}

TEST_CASE("read_file_stdin", "[util]") {
    const char *test_path = TO_STRING(ZITI_TEST_DIR) "/ctrl_tests.cpp";
    uv_fs_t req = {0};
    REQUIRE(uv_fs_stat(nullptr, &req, test_path, nullptr) == 0);
    auto file_size = req.statbuf.st_size;
    uv_fs_req_cleanup(&req);

    auto input = uv_fs_open(nullptr, &req, test_path, 0, O_RDONLY, nullptr);
    REQUIRE(input > 0);
    REQUIRE(dup2(input, fileno(stdin)) == 0);


    char *content = nullptr;
    size_t size;
    int rc = load_file("-", 0, &content, &size);
    CHECK(rc == UV_EINVAL);
    CHECK(content == nullptr);

    size = file_size + 16;
    content = static_cast<char *>(malloc(size));
    rc = load_file("-", 0, &content, &size);
    CHECK(rc == 0);
    CHECK(content != nullptr);
    CHECK(size == file_size);

    free(content);
    uv_fs_req_cleanup(&req);
}

TEST_CASE("check hostname/domainname") {

    const ziti_env_info *info = get_env_info();
    REQUIRE(info != nullptr);
    CHECK(info->hostname != nullptr);
    CHECK(info->domain != nullptr);

    printf("hostname = %s\n", info->hostname);
    printf("domain = %s\n", info->domain);
}