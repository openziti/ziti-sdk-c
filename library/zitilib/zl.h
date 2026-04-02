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
#else
#include <unistd.h>
#define SOCKET_ERROR (-1)
#endif

typedef struct ztx_wrap {
    ziti_options opts;
    ziti_context ztx;
    future_t *auth_future;
    future_t *enroll_future;
    ziti_enroll_mode enroll_mode;
    const char *signer_name;

    future_t *services_loaded;
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

ZITI_FUNC
const char *Ziti_lookup(in_addr_t addr);

#ifdef __cplusplus
}
#endif

#endif // ZITI_SDK_ZL_H
