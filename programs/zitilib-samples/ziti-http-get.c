// Copyright (c) 2022-2023.  NetFoundry Inc.
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
#include <ziti/ziti.h>
#include <tlsuv/http.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "common.h"

#if !defined(_WIN32)

#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>

#else

#include <WinSock2.h>
#include <io.h>

#define write(s,b,l) send(s,b,l,0)
#define read(s,b,l)  recv(s,b,l,0)
#define close(s)     closesocket(s)

#define SHUT_WR SD_SEND
#endif

int main(int argc, char *argv[]) {
    if (argc < 3) { return -1; }

    const char *prog = strrchr(argv[0], '/');
    if (prog == NULL) {
        prog = argv[0];
    }
    else {
        prog++;
    }

    const char *path = argv[1];

    struct tlsuv_url_s url = {0};
    tlsuv_parse_url(&url, argv[2]);

    char hostname[256];
    snprintf(hostname, sizeof(hostname), "%.*s", (int) url.hostname_len, url.hostname);
    int port = (url.port != 0) ? url.port : 80;

    Ziti_lib_init();
    ziti_handle_t ztx = init_context(path);

    ziti_socket_t soc = socket(AF_INET, SOCK_STREAM, 0); //Ziti_socket(SOCK_STREAM);

    long rc = Ziti_connect_addr(soc, hostname, port);

    if (rc != 0) {
        fprintf(stderr, "failed to connect: %ld(%s)\n", rc, ziti_errorstr((int)rc));
        goto DONE;
    }

    char req[1024];
    int len = snprintf(req, sizeof(req),
                       "GET %.*s HTTP/1.1\r\n"
                       "Host: %.*s\r\n"
                       "User-Agent: %s/%s\r\n"
                       "Connection: close\r\n"
                       "Accept: */*\r\n\r\n",
                       (int) (url.path_len ? url.path_len : 1), url.path ? url.path : "/",
                       (int) url.hostname_len, url.hostname,
                       prog, ziti_get_version()->version);

    rc = write(soc, req, len);
    fprintf(stderr, "rc = %ld, errno = %d\n", rc, errno);

    //shutdown(socket, SHUT_WR);
    char buf[1024] = {};
    do {
        rc = read(soc, buf, sizeof(buf));
        if (rc > 0) {
            fprintf(stdout, "%.*s", (int) rc, buf);
            fflush(stdout);
        }
    } while (rc > 0);
    if (rc < 0) {
        fprintf(stderr, "rc = %ld, errno = %d\n", rc, errno);
    }

    DONE:
    close(soc);
    Ziti_lib_shutdown();
}
