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

#if _WIN32
#include <io.h>
#define dup2(o,n) _dup2(o,n)
#else
#include <unistd.h>
#endif

TEST_CASE("read_file", "[util]") {
    const char *test_path = TO_STRING(ZITI_TEST_DIR) "/buffer_tests.cpp";
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
    const char *test_path = TO_STRING(ZITI_TEST_DIR) "/buffer_tests.cpp";
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

// The shared retry predicate. Three call sites depend on it: the OIDC auth-flow
// classifier (library/oidc.c auth_error_is_temporary) and the internal and
// external token-refresh paths (oidc.c / ext_oidc.c). Only resp->code and the
// body are read, so a zeroed response with a code set is a faithful input.
TEST_CASE("http_error_is_temporary", "[util]") {
    auto classify = [](int code, const char *body_json = nullptr) {
        tlsuv_http_resp_t resp{};
        resp.code = code;
        json_object *body = body_json ? json_tokener_parse(body_json) : nullptr;
        bool result = ziti_http_error_is_temporary(&resp, body);
        if (body) json_object_put(body);
        return result;
    };

    SECTION("transport errors are temporary") {
        CHECK(classify(UV_ECONNRESET));
        CHECK(classify(UV_ETIMEDOUT));
    }

    SECTION("5xx is temporary") {
        CHECK(classify(500));
        CHECK(classify(502));
        CHECK(classify(503));
    }

    SECTION("429 is temporary: the server is pacing us, not rejecting us") {
        CHECK(classify(429));
    }

    SECTION("400 is temporary only for zitadel's generic server_error") {
        CHECK(classify(400, R"({"error":"server_error"})"));
        CHECK_FALSE(classify(400, R"({"error":"invalid_request"})"));
        CHECK_FALSE(classify(400, R"({})"));
        CHECK_FALSE(classify(400));
    }

    SECTION("credential rejections are not temporary on their own") {
        // oidc.c widens 401/403/404 for the cert-login leg only; the shared
        // predicate must not do it for everyone
        CHECK_FALSE(classify(401));
        CHECK_FALSE(classify(403));
        CHECK_FALSE(classify(404));
    }

    SECTION("success and other 4xx are not temporary") {
        CHECK_FALSE(classify(200));
        CHECK_FALSE(classify(409));
    }
}
