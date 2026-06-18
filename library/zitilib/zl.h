// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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

//
//

#ifndef ZITI_SDK_ZL_H
#define ZITI_SDK_ZL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ziti/zitilib.h>
#include <ziti/ziti.h>

#include "util/future.h"

#include <stc/cstr.h>

#if _WIN32
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;
#if !defined(__MINGW32__)
#pragma comment(lib, "ws2_32.lib")
#include <afunix.h>
#endif
#include <WinSock2.h>
#define close(s) closesocket(s)
#define poll(f,d,t) WSAPoll(f,d,t)
static inline void set_errno(int e) {
    ZITI_LOG(VERBOSE, "setting WSA error: %d/%s", e, strerror(e));
    switch(e) {
    case EINVAL: WSASetLastError(WSAEINVAL); break;
    case EALREADY: WSASetLastError(WSAEALREADY); break;
    case EWOULDBLOCK: WSASetLastError(WSAEWOULDBLOCK); break;
    case EPROTOTYPE: WSASetLastError(WSAEPROTOTYPE); break;
    case EAFNOSUPPORT: WSASetLastError(WSAEAFNOSUPPORT); break;
    case EADDRNOTAVAIL: WSASetLastError(WSAEADDRNOTAVAIL); break;
    case EBADF: WSASetLastError(WSAENOTSOCK); break;
    default:
        WSASetLastError(e);
    }
}
#define sock_error() WSAGetLastError()
#ifndef THREAD_LOCAL
#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__)
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL
#endif
#endif
static THREAD_LOCAL char wsa_err_buf[256];
static const char *wsa_error(int err) {
    wsa_err_buf[0] = 0;
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   wsa_err_buf, sizeof(wsa_err_buf), NULL);
    if (wsa_err_buf[0] == 0) {
        snprintf(wsa_err_buf, sizeof(wsa_err_buf), "Unknown error %d", err);
    }
    return wsa_err_buf;
}
#define err(e) (WSA ## e)
#define strerror(e) wsa_error(e)
#else
#include <poll.h>
#include <unistd.h>
#define SOCKET_ERROR (-1)
#define set_errno(e) errno = (e)
#define sock_error() errno
#define err(e) e
#endif

typedef struct ztx_wrap {
    ziti_options opts;
    ziti_context ztx;
    future_t *auth_future;
    future_t *enroll_future;
    ziti_enroll_mode enroll_mode;
    const char *signer_name;

    bool services_loaded;
    future_t *services_loaded_f;
    model_map intercepts;
    char **signers;
} ztx_wrap_t;

typedef struct ziti_sock_s {
    ziti_socket_t fd;
    ziti_socket_t ziti_fd;
    future_t *f;
    ziti_context ztx;
    ziti_connection conn;

    cstr service;
    bool server;
    int max_pending;
    model_list backlog;
    model_list accept_q;

} ziti_sock_t;

extern model_map ziti_contexts;

extern model_map ziti_sockets;

typedef void (*loop_work_cb)(void *arg, future_t *f, uv_loop_t *l);
future_t *schedule_on_loop(loop_work_cb cb, void *arg, bool wait);

ztx_wrap_t *zl_find_wrap(ziti_handle_t handle);

/**
 * create bridge socket and connect client socket to it
 * @param af address family
 * @param clt_sock client socket
 * @param ziti_sock[out] bridge socket
 * @return
 */
int connect_socket(int af, ziti_socket_t clt_sock, ziti_socket_t *ziti_sock);
bool zl_is_blocking(ziti_socket_t s);
int zl_socket_af(ziti_socket_t s);
void zl_set_error(int err);
bool zl_check_daemon();

ZITI_FUNC
const char *Ziti_lookup(in_addr_t addr);

#ifdef __cplusplus
}
#endif

#endif // ZITI_SDK_ZL_H
