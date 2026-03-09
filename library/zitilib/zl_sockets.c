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

#include "zl.h"
#include <fcntl.h>
#include <stdbool.h>
#include <ziti/ziti_log.h>

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

int connect_socket(ziti_socket_t clt_sock, ziti_socket_t *ziti_sock) {
    int rc;
#if _WIN32
    ziti_socket_t
        lsock = SOCKET_ERROR, // listener
        ssock = SOCKET_ERROR; // server side

    PREPF(WSOCK, fmt_win32err);

    u_long nonblocking = 1;
    TRY(WSOCK, (lsock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR);
    ioctlsocket(lsock, FIONBIO, &nonblocking);

    struct sockaddr_in laddr;
    int laddrlen = sizeof(laddr);
    laddr.sin_port = 0;
    laddr.sin_family = AF_INET;
    laddr.sin_addr = in4addr_loopback;

    TRY(WSOCK, bind(lsock, (const struct sockaddr *) &laddr, laddrlen));
    TRY(WSOCK, getsockname(lsock, (struct sockaddr *) &laddr, &laddrlen));
    TRY(WSOCK, listen(lsock, 1));

    ioctlsocket(clt_sock, FIONBIO, &nonblocking);

    // this should return an error(WSAEWOULDBLOCK)
    rc = connect(clt_sock, (const struct sockaddr *) &laddr, laddrlen);
    TRY(WSOCK, WSAGetLastError() != WSAEWOULDBLOCK);
    rc = 0;

    fd_set fds = {0};
    FD_SET(lsock, &fds);
    const struct timeval timeout = {
        .tv_sec = 1,
    };
    TRY(WSOCK, select(0, &fds, NULL, NULL, &timeout) != 1);
    TRY(WSOCK, !FD_ISSET(lsock, &fds));
    TRY(WSOCK, (ssock = accept(lsock, NULL, NULL)) == SOCKET_ERROR);

    nonblocking = 0;
    ioctlsocket(clt_sock, FIONBIO, &nonblocking);

    CATCH(WSOCK) {
        rc  = WSAGetLastError();
        if (ssock != SOCKET_ERROR) closesocket(ssock);
    }

    if (lsock != SOCKET_ERROR) closesocket(lsock);

    *ziti_sock = ssock;
#else

#if defined(SOCKET_PAIR_ALT)
    ziti_socket_t
        lsock = SOCKET_ERROR, // listener
        ssock = SOCKET_ERROR; // server side

    PREPF(WSOCK, strerror);

    int clt_flags = fcntl(clt_sock, F_GETFL, NULL);
    TRY(WSOCK, fcntl(clt_sock, F_SETFL, clt_flags | O_NONBLOCK));

    TRY(WSOCK, (lsock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR);

    struct sockaddr_in laddr;
    int laddrlen = sizeof(laddr);
    laddr.sin_port = 0;
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    TRY(WSOCK, bind(lsock, (const struct sockaddr *) &laddr, laddrlen));
    TRY(WSOCK, getsockname(lsock, (struct sockaddr *) &laddr, &laddrlen));
    TRY(WSOCK, listen(lsock, 1));

    // this should return an error(WSAEWOULDBLOCK)
    rc = connect(clt_sock, (const struct sockaddr *) &laddr, laddrlen);
    TRY(WSOCK, errno != EWOULDBLOCK);
    rc = 0;

    fd_set fds = {0};
    FD_SET(lsock, &fds);
    const struct timeval timeout = {
        .tv_sec = 1,
    };
    TRY(WSOCK, select(0, &fds, NULL, NULL, &timeout) != 1);
    TRY(WSOCK, !FD_ISSET(lsock, &fds));
    TRY(WSOCK, (ssock = accept(lsock, NULL, NULL)) == SOCKET_ERROR);

    TRY(WSOCK, fcntl(clt_sock, F_SETFL, clt_flags));

    CATCH(WSOCK) {
        rc  = errno;
        if (ssock != SOCKET_ERROR) close(ssock);
    }

    if (lsock != SOCKET_ERROR) close(lsock);

    *ziti_sock = ssock;
    return rc;
#endif

    ZITI_LOG(VERBOSE, "connecting client socket[%d]", clt_sock);
    int fds[2] = {-1, -1};
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (rc) {
        ZITI_LOG(WARN, "socketpair failed[%d/%s]", errno, strerror(errno));
        return errno;
    }

    rc = dup2(fds[0], clt_sock);
    if (rc == -1) {
        ZITI_LOG(WARN, "dup2 failed[%d/%s]", errno, strerror(errno));
        close(fds[0]);
        close(fds[1]);
        return errno;
    }
    close(fds[0]);
#if defined(SO_NOSIGPIPE)
    int nosig = 1;
    setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, (void *)&nosig, sizeof(int));
#endif

    *ziti_sock = fds[1];
    ZITI_LOG(VERBOSE, "connected client socket[%d] <-> ziti_fd[%d]", clt_sock, *ziti_sock);
#endif
    return 0;
}

