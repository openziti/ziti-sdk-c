// Copyright (c) 2022-2026.  NetFoundry Inc
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.

#include <ziti/zitilib.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#if !defined(_WIN32)

#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

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

    int blocking = getenv("ZITI_SAMPLE_BLOCKING") != NULL;

#if _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

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
    ziti_socket_t soc = socket(AF_INET6, SOCK_STREAM, 0);

    Ziti_lib_init();

    ziti_handle_t ztx;
    int err = Ziti_load_context(&ztx, path);
    if (err != ZITI_OK) {
        err = Ziti_last_error();
        fprintf(stderr, "failed to load Ziti: %d(%s)\n", err, ziti_errorstr(err));
        goto DONE;
    }

    if (!blocking) {
#if _WIN32
        u_long mode = 1;  // 1 to enable non-blocking socket
        ioctlsocket(soc, FIONBIO, &mode);
#else
        int opt = fcntl(soc, F_GETFL);
        fcntl(soc, F_SETFL, opt | O_NONBLOCK);
#endif
    }

    long rc = service ? Ziti_connect(soc, ztx, service, "ziggy") : Ziti_connect_addr(soc, hostname, port);
    err = errno;
    if (rc == -1 && err == EINPROGRESS) {
        printf("polling for connect to complete...\n");
        struct pollfd p = { .fd = soc, .events = POLLOUT };
        rc = poll(&p, 1, 10000);
        if (rc == 0) {
            fprintf(stderr, "connect timed out\n");
            goto DONE;
        } else if (rc < 0) {
            fprintf(stderr, "poll failed: %d(%s)\n", errno, strerror(errno));
            goto DONE;
        }
        getsockopt(soc, SOL_SOCKET, SO_ERROR, &err, &(socklen_t){sizeof(err)});
        if (err != 0) {
            fprintf(stderr, "failed to connect: %d(%s)\n", err, strerror(err));
            goto DONE;
        }
    } else if (rc != 0) {
        err = errno;
        fprintf(stderr, "failed to connect: %d(%s)\n", err, strerror(err));
        goto DONE;
    } else {
        printf("connected immediately\n");
    }

    const char msg[] = "this is a test";
    rc = write(soc, msg, sizeof(msg) - 1);
    if (rc < 0) {
        fprintf(stderr, "write failed: %d(%s)\n", errno, strerror(errno));
        goto DONE;
    }
    shutdown(soc, SHUT_WR);
    do {
        char buf[1024];

        if (!blocking) {
            printf("polling for data to read...\n");

            struct pollfd p = {.fd = soc, .events = POLLIN};
            rc = poll(&p, 1, 10000);
            if (rc == 0) {
                fprintf(stderr, "read timed out\n");
                break;
            } else if (rc < 0) {
                fprintf(stderr, "poll failed: %d(%s)\n", errno, strerror(errno));
                break;
            }
        }
        rc = read(soc, buf, sizeof(buf));
        if (rc > 0) {
            printf("read rc=%ld\n%.*s\n", rc, (int)rc, buf);
            fflush(stdout);
        }
    } while (rc > 0);
    printf("rc = %ld, errno = %d\n", rc, errno);

    DONE:
    fflush(stderr);
    close(soc);
    Ziti_lib_shutdown();
}
