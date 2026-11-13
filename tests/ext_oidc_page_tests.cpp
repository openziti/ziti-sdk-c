// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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

// The page the browser gets when external login fails (library/ext_oidc.c, ext_oidc_client_finalize): with a
// "Show details" block that carries the claims of the token the controller turned down.

#include "catch2_includes.hpp"

#include <string>

#include <json-c/json.h>
#include <uv.h>

#if _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "ext_oidc.h"
#include "totp_jwt.h"

namespace {

void close_sock(uv_os_sock_t s) {
#if _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

std::string read_to_eof(uv_os_sock_t s) {
    std::string out;
    char buf[1024];
    for (;;) {
        auto n = recv(s, buf, (int) sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, (size_t) n);
    }
    return out;
}

// an unsigned token with these claims: the SDK never checks the signature of what it shows
std::string jwt_with(const std::string &claims) {
    return totp_test::b64url(R"({"alg":"none"})") + "." + totp_test::b64url(claims) + ".sig";
}

// what the browser reads when the verdict on a login is a failure and the IdP had handed out `access_token`
std::string failure_page(const std::string &access_token, const char *error) {
    uv_os_sock_t fds[2];
    REQUIRE(uv_socketpair(SOCK_STREAM, 0, fds, 0, 0) == 0);

    json_object *tokens = json_object_new_object();
    json_object_object_add(tokens, "access_token", json_object_new_string(access_token.c_str()));

    ext_oidc_client_t clt{};
    clt.pending_sock = fds[0]; // finalize writes the page into it and closes it
    clt.signer_cfg.target_token = ziti_target_token_access_token;
    clt.tokens = tokens;

    ext_oidc_client_finalize(&clt, false, error);

    std::string page = read_to_eof(fds[1]);
    close_sock(fds[1]);
    json_object_put(tokens);
    return page;
}

bool has(const std::string &page, const char *text) {
    return page.find(text) != std::string::npos;
}

} // namespace

TEST_CASE("the failure page shows the claims of the token the controller turned down", "[ext-oidc]") {
    std::string page = failure_page(
            jwt_with(R"({"iss":"https://idp.example","sub":"alice","scope":"openid","jti":"j-1234","sid":"s-5678","nonce":"n-9012"})"),
            "controller said no");

    CHECK(page.rfind("HTTP/1.0 401 Unauthorized", 0) == 0);
    CHECK(has(page, "controller said no"));
    CHECK(has(page, "Token claims"));
    // the claims are there, html escaped
    CHECK(has(page, "&quot;iss&quot;:&quot;https://idp.example&quot;"));
    CHECK(has(page, "&quot;sub&quot;:&quot;alice&quot;"));
    // the session correlation claims are not
    CHECK_FALSE(has(page, "j-1234"));
    CHECK_FALSE(has(page, "s-5678"));
    CHECK_FALSE(has(page, "n-9012"));
}

TEST_CASE("the failure page escapes what a token claims", "[ext-oidc]") {
    std::string page = failure_page(jwt_with(R"({"iss":"https://idp.example","name":"<b>x</b>"})"), "no");

    CHECK(has(page, "Token claims"));
    CHECK_FALSE(has(page, "<b>x</b>"));
    CHECK(has(page, "&lt;b&gt;x&lt;/b&gt;"));
}

TEST_CASE("the failure page has no claims for a token that is not a JWT", "[ext-oidc]") {
    std::string page = failure_page("an-opaque-token", "controller said no");

    CHECK(page.rfind("HTTP/1.0 401 Unauthorized", 0) == 0);
    CHECK(has(page, "controller said no"));
    CHECK_FALSE(has(page, "Token claims"));
    CHECK_FALSE(has(page, "an-opaque-token"));
}
