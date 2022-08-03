// Copyright (c) 2022.  NetFoundry Inc.
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

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>

#include <ziti/zitilib.h>
#include "catch2/reporters/catch_reporters_all.hpp"
#include "catch2/matchers/catch_matchers.hpp"
#include "catch2/matchers/catch_matchers_string.hpp"

#if _WIN32
#else
#include <unistd.h>
#endif

class testRunListener : public Catch::EventListenerBase {
protected:
    static ziti_context _ztx;
public:
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const &) override {
        Ziti_lib_init();
        const char *id = getenv("ZITI_TEST_IDENTITY");
        if (id) {
            _ztx = Ziti_load_context(id);
        }
    }

    void testRunEnded(const Catch::TestRunStats &testRunStats) override {
        Ziti_lib_shutdown();
    }

    static ziti_context ztx() {
        return _ztx;
    }
};

ziti_context testRunListener::_ztx;

CATCH_REGISTER_LISTENER(testRunListener)
using namespace Catch::Matchers;

TEST_CASE("httpbin.ziti", "[zitilib]") {
    ziti_socket_t sock = Ziti_socket(SOCK_STREAM);
    REQUIRE(Ziti_connect_addr(sock, "httpbin.ziti", 80) == 0);

    auto req = "GET /json HTTP/1.1\r\n"
               "Accept: */*\r\n"
               "Accept-Encoding: gzip, deflate\r\n"
               "Connection: keep-alive\r\n"
               "Host: httpbin.org\r\n"
               "User-Agent: HTTPie/3.1.0\r\n"
               "\r\n";
#if _WIN32
    send(sock, req, strlen(req), 0);
#else
    write(sock, req, strlen(req));
#endif

    char resp[1024];
    size_t rlen = 0;
    int r;
    do {
#if _WIN32
        r = recv(sock, resp + rlen, sizeof(resp) - rlen, 0);
#else
        r = (int)read(sock, resp + rlen, sizeof(resp) - rlen);
#endif
        if (r < 0) {
            fprintf(stderr, "failed to read: %d\n", errno);
            break;
        }
        rlen += r;
    } while (r > 0);
    resp[rlen] = '\0';

#if _WIN32
     closesocket(sock);
#else
    close(sock);
#endif

    CHECK_THAT(resp, StartsWith("HTTP/1.1 200 OK"));
    CHECK_THAT(resp, ContainsSubstring(R"("title": "Sample Slide Show")"));
}