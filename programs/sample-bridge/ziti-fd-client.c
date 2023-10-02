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

#define write(s,b,l) send(s,b,l,0)
#define read(s,b,l)  recv(s,b,l,0)
#define close(s)     closesocket(s)

#define SHUT_WR SD_SEND
#endif

int main(int argc, char *argv[]) {
    if (argc < 3) { return -1; }

    const char *path = argv[1];
    const char *service = NULL;
    const char *hostname = NULL;
    int port = -1;
    if (argc == 3) {
        service = argv[2];
    } else if (argc == 4) {
        hostname = argv[2];
        port = atol(argv[3]);
    }

    Ziti_lib_init();

    ziti_context ztx = Ziti_load_context(path);
    if (ztx == NULL) {
        int err = Ziti_last_error();
        fprintf(stderr, "failed to load Ziti: %d(%s)\n", err, ziti_errorstr(err));
    }
    ziti_socket_t socket = Ziti_socket(SOCK_STREAM);

    long rc = service ? Ziti_connect(socket, ztx, service, "ziggy") : Ziti_connect_addr(socket, hostname, port);

    if (rc != 0) {
        fprintf(stderr, "failed to connect: %ld(%s)\n", rc, ziti_errorstr(Ziti_last_error()));
        goto DONE;
    }

    const char msg[] = "this is a test";
    write(socket, msg, strlen(msg));
    shutdown(socket, SHUT_WR);
    char buf[1024];
    do {
        rc = read(socket, buf, sizeof(buf));
        if (rc > 0) {
            printf("read rc=%ld(%.*s)\n", rc, (int)rc, buf);
        }
    } while (rc > 0);
    printf("rc = %ld, errno = %d\n", rc, errno);

    DONE:
    close(socket);
    Ziti_lib_shutdown();
}
