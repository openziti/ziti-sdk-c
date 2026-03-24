// Copyright (c) 2026.  NetFoundry Inc
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

//
//

#include "utils.h"
#include "zl.h"
#include <fcntl.h>
#include <stdbool.h>
#include <ziti/ziti_log.h>

#if !defined(_WIN32)
#include <poll.h>
#endif

#if _WIN32
#include <winsock2.h>
static const char * fmt_win32err(int err) {
    static char wszMsgBuff[512];  // Buffer for text.

    // Try to get the message from the system errors.
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  WSAGetLastError(),
                  0,
                  wszMsgBuff,
                  512,
                  NULL);
    return wszMsgBuff;
}
#endif

bool zl_is_blocking(ziti_socket_t s) {
#if _WIN32
    /*
     * Win32 does not have a method of testing if socket was put into non-blocking state.
     */
    DWORD timeout;
    DWORD fast_check = 1;
    int tolen = sizeof(timeout);
    int rc = getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, &tolen);
    rc = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &fast_check, sizeof(fast_check));
    char b;
    int r = recv(s, &b, 0, MSG_OOB);
    int err = WSAGetLastError();
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(fast_check));

    if (r == 0)
        return true;
    else if (r == -1) {
        if (err == WSAEWOULDBLOCK) return false;
        if (err == WSAETIMEDOUT) return true;
    }
    return true;
#else
    int flags = fcntl(s, F_GETFL, 0);
    return (flags & O_NONBLOCK) == 0;
#endif
}

int zl_socket_af(ziti_socket_t s) {
#if _WIN32
    WSAPROTOCOL_INFO pi;
    int optlen = sizeof(pi);
    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFO, (char *)&pi, &optlen) != 0) {
        return -1;
    }
    return pi.iAddressFamily;
#else
    struct sockaddr_storage addr = {0};
    socklen_t addrlen = sizeof(addr);
    if (getsockname(s, (struct sockaddr *) &addr, &addrlen) != 0) {
        return -1;
    }
    return addr.ss_family;
#endif
}

int connect_socket(int af, ziti_socket_t clt_sock, ziti_socket_t *ziti_sock) {
    int rc;
    ziti_socket_t
        lsock = SOCKET_ERROR, // listener
        ssock = SOCKET_ERROR; // server side

#if _WIN32

    PREPF(WSOCK, fmt_win32err);

    u_long nonblocking = 1;
    TRY(WSOCK, (lsock = socket(af, SOCK_STREAM, 0)) == SOCKET_ERROR);
    ioctlsocket(lsock, FIONBIO, &nonblocking);

    struct sockaddr_storage laddr = {.ss_family = af };
    int laddrlen = sizeof(laddr);
    switch (af) {
    case AF_INET:
        ((struct sockaddr_in *) &laddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
        laddrlen = sizeof(struct sockaddr_in);
        break;

    case AF_INET6:
        ((struct sockaddr_in6 *) &laddr)->sin6_addr = in6addr_loopback;
        laddrlen = sizeof(struct sockaddr_in6);
        break;

    default: TRY(WSOCK, SOCKET_ERROR);
    }

    TRY(WSOCK, bind(lsock, (const struct sockaddr *) &laddr, laddrlen));
    TRY(WSOCK, getsockname(lsock, (struct sockaddr *) &laddr, &laddrlen));
    TRY(WSOCK, listen(lsock, 1));

    ioctlsocket(clt_sock, FIONBIO, &nonblocking);

    // this should return an error(WSAEWOULDBLOCK)
    rc = connect(clt_sock, (const struct sockaddr *) &laddr, laddrlen);
    TRY(WSOCK, WSAGetLastError() != WSAEWOULDBLOCK);
    rc = 0;

    TRY(WSOCK, (ssock = accept(lsock, NULL, NULL)) == SOCKET_ERROR);

    nonblocking = 0;
    ioctlsocket(clt_sock, FIONBIO, &nonblocking);

    CATCH(WSOCK) {
        rc  = WSAGetLastError();
        if (ssock != SOCKET_ERROR) closesocket(ssock);
    }

    if (lsock != SOCKET_ERROR) closesocket(lsock);

    *ziti_sock = ssock;

#else // _WIN32

    PREPF(WSOCK, strerror);

    int clt_flags = fcntl(clt_sock, F_GETFL, NULL);
    TRY(WSOCK, fcntl(clt_sock, F_SETFL, clt_flags | O_NONBLOCK));

    TRY(WSOCK, (lsock = socket(af, SOCK_STREAM, 0)) == SOCKET_ERROR);

    struct sockaddr_storage laddr = {.ss_family = af };
    socklen_t laddrlen = sizeof(laddr);
    switch (af) {
    case AF_INET:
        ((struct sockaddr_in *) &laddr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        laddrlen = sizeof(struct sockaddr_in);
        break;

    case AF_INET6:
        ((struct sockaddr_in6 *)&laddr)->sin6_addr = in6addr_loopback;
        laddrlen = sizeof(struct sockaddr_in6);
        break;

    default: TRY(WSOCK, EAFNOSUPPORT);
    }

    TRY(WSOCK, bind(lsock, (const struct sockaddr *) &laddr, laddrlen));
    TRY(WSOCK, getsockname(lsock, (struct sockaddr *) &laddr, &laddrlen));
    TRY(WSOCK, listen(lsock, 1));

    // this should return an error(EWOULDBLOCK)
    rc = connect(clt_sock, (const struct sockaddr *) &laddr, laddrlen);
    TRY(WSOCK, errno != EWOULDBLOCK);
    rc = 0;

    TRY(WSOCK, (ssock = accept(lsock, NULL, NULL)) == SOCKET_ERROR);

    CATCH(WSOCK) {
        rc  = errno;
        if (ssock != SOCKET_ERROR)
            close(ssock);
        ssock = SOCKET_ERROR;
    }

    if (lsock != SOCKET_ERROR) {
        close(lsock);
    }

    *ziti_sock = ssock;
#endif
    return rc;
}

