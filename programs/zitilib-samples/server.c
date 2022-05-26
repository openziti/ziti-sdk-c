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

#include <ziti/zitilib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>


// This sample runs a simple byte counting server
// - binds to the service
// - for each client receives all data from client
// - replies with message how many bytes where received
// - clients are processed on at a time, client queue is managed by Ziti server socket implementation.

// set this to 1 to verify that Ziti server socket works in non-blocking mode
#define NON_BLOCKING_SERVER 0

#define CHECK(desc, op) do{ \
int rc = (op);                      \
if (rc != 0) {              \
int err = Ziti_last_error(); \
const char *msg = rc > 0 ? strerror(err) : ziti_errorstr(err); \
fprintf(stderr, desc"{" #op "} err=%d(%s)\n", err, msg); \
goto DONE;\
}                      \
} while(0)

static ziti_socket_t non_blocking_accept(ziti_socket_t srv) {
    int opt = fcntl(srv, F_GETFL);
    fcntl(srv, F_SETFL, opt | O_NONBLOCK);

    fd_set rdfds;
    FD_ZERO(&rdfds);
    FD_SET(srv, &rdfds);
    struct timeval to = {
            .tv_sec = 60 * 60, // one hour
    };
    int src = select(srv + 1, &rdfds, NULL, NULL, &to);
    if (src < 0) {
        perror("select");
        return -1;
    }

    if (src == 0) {
        perror("timeout");
        return -1;
    }

    if (!FD_ISSET(srv, &rdfds)) {
        fprintf(stderr, "select failure");
        return -1;
    }

    // srv socket is readable, accept should succeed
    return Ziti_accept(srv);
}

int main(int argc, char *argv[]) {

    Ziti_lib_init();

    ziti_context ztx = Ziti_load_context(argv[1]);
    ziti_socket_t srv = Ziti_socket(SOCK_STREAM);

    CHECK("bind", Ziti_bind(srv, ztx, argv[2]));

    CHECK("listen", Ziti_listen(srv, 10));

    ziti_socket_t clt;
    char readbuf[8 * 1024];

    do {
#if NON_BLOCKING_SERVER
        CHECK("non blocking accept", (clt = non_blocking_accept(srv)) < 0);
#else
        CHECK("accept", (clt = Ziti_accept(srv)) < 0);
#endif

        printf("client connected\n");
        size_t count = 0;
        size_t total = 0;
        do {
            CHECK("read", (count = read(clt, readbuf, sizeof(readbuf))) < 0);
            total += count;
        } while (count > 0);

        char msg[128];
        int len = snprintf(msg, sizeof(msg), "you sent %zd bytes", total);
        write(clt, msg, len);
        close(clt);
        printf("client is done after sending %zd bytes\n", total);
    } while (1);

    DONE:
    close(srv);
    Ziti_lib_shutdown();
}