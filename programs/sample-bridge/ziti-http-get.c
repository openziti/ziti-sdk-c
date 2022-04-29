// Copyright (c) 2022.  NetFoundry, Inc.
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

#include <ziti/socket.h>
#include <ziti/ziti.h>
#include <http_parser.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#if !defined(_WIN32)

#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>

#else

#include <WinSock2.h>
#include <io.h>

#define write(s,b,l) _write(s,b,l)
#define read(s,b,l)  _read(s,b,l)
#define close(s)     _close(s)

#define SHUT_WR SD_SEND
#endif

int main(int argc, char *argv[]) {
    if (argc < 3) { return -1; }

    const char *prog = strrchr(argv[0], '/');
    if (prog == NULL) {
        prog = argv[0];
    } else {
        prog++;
    }

    const char *path = argv[1];

    struct http_parser_url url = {0};
    http_parser_parse_url(argv[2], strlen(argv[2]), 0, &url);

    char hostname[256];
    snprintf(hostname, sizeof(hostname), "%.*s", (int) url.field_data[UF_HOST].len, argv[2] + url.field_data[UF_HOST].off);
    int port = (url.port != 0) ? url.port : 80;

    Ziti_lib_init();

    ziti_context ztx = Ziti_load_context(path);
    if (ztx == NULL) {
        int err = Ziti_last_error();
        fprintf(stderr, "failed to load Ziti: %d(%s)\n", err, ziti_errorstr(err));
    }
    ziti_socket_t socket = Ziti_socket(SOCK_STREAM);

    long rc = Ziti_connect_addr(socket, hostname, port);

    if (rc != 0) {
        fprintf(stderr, "failed to connect: %ld(%s)\n", rc, ziti_errorstr(rc));
        goto DONE;
    }

    char req[1024];
    int len = snprintf(req, sizeof(req),
                       "GET %.*s HTTP/1.1\r\n"
                       "Host: %.*s\r\n"
                       "User-Agent: %s/%s\r\n"
                       "Connection: close\r\n"
                       "Accept: */*\r\n\r\n",
                       url.field_data[UF_PATH].len, argv[2] + url.field_data[UF_PATH].off,
                       url.field_data[UF_HOST].len, argv[2] + url.field_data[UF_HOST].off,
                       prog, ziti_get_version()->version);

    write(socket, req, len);
    shutdown(socket, SHUT_WR);
    char buf[1024];
    do {
        rc = read(socket, buf, sizeof(buf));
        if (rc > 0) {
            printf("%.*s", (int) rc, buf);
        }
    } while (rc > 0);
    if (rc < 0) {
        fprintf(stderr, "rc = %ld, errno = %d\n", rc, errno);
    }

    DONE:
    close(socket);
    Ziti_lib_shutdown();
}
