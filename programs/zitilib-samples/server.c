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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _WIN32
#include <winsock2.h>
#define close(s) closesocket(s)
#define write(s,b,l) send(s,b,l,0)
#define read(s,b,l) recv(s,b,l,0)
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

// This sample runs a simple byte counting server
// - binds to the service
// - for each client receives all data from client
// - replies with message how many bytes where received
// - clients are processed on at a time, client queue is managed by Ziti server socket implementation.

// set this to 1 to verify that Ziti server socket works in non-blocking mode
#define NON_BLOCKING_SERVER 1

#define CHECK(desc, op) do{ \
if ((op) != 0) {              \
int err = Ziti_last_error(); \
const char *msg = rc > 0 ? strerror(err) : ziti_errorstr(err); \
fprintf(stderr, desc"{" #op "} err=%d(%s)\n", err, msg); \
goto DONE;\
}                      \
} while(0)

static ziti_socket_t non_blocking_accept(ziti_socket_t srv, char *caller, int caller_len) {
#if _WIN32
    u_long opt = 1;
    ioctlsocket(srv, FIONBIO, &opt);
#else
    int opt = fcntl(srv, F_GETFL);
    fcntl(srv, F_SETFL, opt | O_NONBLOCK);
#endif

    fd_set rdfds;
    FD_ZERO(&rdfds);
    FD_SET(srv, &rdfds);
    struct timeval to = {
            .tv_sec = 60 * 60, // one hour
    };
    do {
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
            break;
        }
        // srv socket is readable, accept should succeed
        ziti_socket_t clt = Ziti_accept(srv, caller, caller_len);
        if (clt != SOCKET_ERROR) { return clt; }

        if (Ziti_last_error() != EWOULDBLOCK) {
            break;
        }
    } while (1);

    return -1;
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <id_file> <service> [terminator]\n", argv[0]);
        exit(1);
    }

    Ziti_lib_init();
    const char *service = argv[2];
    const char *terminator = argc > 3 ? argv[3] : NULL;

    ziti_handle_t ztx;
    int rc = Ziti_load_context(&ztx, argv[1]);
    if (rc != 0) {
        fprintf(stderr, "failed to load ziti context from %s: %s\n", argv[1], ziti_errorstr(rc));
        exit(1);
    }

    ziti_socket_t srv = socket(AF_INET, SOCK_STREAM, 0);

    CHECK("socket", srv == SOCKET_ERROR);

    CHECK("bind", Ziti_bind(srv, ztx, service, terminator));

    CHECK("listen", Ziti_listen(srv, 10));

    ziti_socket_t clt;
    char readbuf[8 * 1024];
    int keep_going = 1;

    do {
        char caller[128];
#if NON_BLOCKING_SERVER
        CHECK("non blocking accept", (clt = non_blocking_accept(srv, caller, sizeof(caller))) < 0);
#else
        CHECK("accept", (clt = Ziti_accept(srv, caller, sizeof(caller))) < 0);
#endif

        printf("client[%s] connected\n", caller);
        long count = 0;
        size_t total = 0;
        char msg[128];
        int len;
        do {
            count = read(clt, readbuf, sizeof(readbuf));
            if (count > 0) {
                printf("read %zd bytes\n", count);
                if (strncmp("quit", readbuf, strlen("quit")) == 0) {
                    keep_going = 0;
                    break;
                }
                total += count;
                len = snprintf(msg, sizeof(msg), "you[%s] sent %zd bytes", caller, total);
                if (write(clt, msg, len) != len) {;
                    fprintf(stderr, "incomplete write\n");
                    exit(1);
                }
            }
        } while (count > 0);

        len = snprintf(msg, sizeof(msg), "you[%s] sent %zd total bytes", caller, total);
        if (write(clt, msg, len) != len) {
            fprintf(stderr, "incomplete write\n");
        }
        close(clt);
        printf("client is done after sending %zd bytes\n", total);
    } while (keep_going);

    DONE:
    if (srv != SOCKET_ERROR)
        Ziti_close(srv);
    Ziti_lib_shutdown();
}