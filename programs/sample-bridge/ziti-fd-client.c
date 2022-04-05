/*
Copyright (c) 2022 NetFoundry, Inc.

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

#include <ziti/socket.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#if !defined(_WIN32)

#include <unistd.h>

#else

#include <WinSock2.h>

#define SHUT_WR SD_SEND

static long write(ziti_socket_t s, const char* buf, size_t len) {
    long outlen = send(s, buf, len, 0);
    if (outlen == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    }
    return outlen;
}

static long read(ziti_socket_t s, char *buf, size_t len) {
    int outlen = recv(s, buf, len, 0);

    if (outlen == SOCKET_ERROR ){
        errno = WSAGetLastError();
        return -1;
    }
    return outlen;
}
#endif

int main(int argc, char *argv[]) {
    if (argc < 3) { return -1; }

    const char *path = argv[1];
    const char *service = argv[2];

    Ziti_lib_init();

    ziti_context ztx = Ziti_load_context(path);
    ziti_socket_t socket = Ziti_socket();

    long rc = Ziti_connect(socket, ztx, service);

    if (rc != 0) {
        fprintf(stderr, "failed to connect: %ld(%s)\n", rc, ziti_errorstr(rc));
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
    Ziti_lib_shutdown();
}
