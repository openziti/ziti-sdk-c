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


#ifndef ZITI_SDK_SOCKET_H
#define ZITI_SDK_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "externs.h"
#include "errors.h"

typedef struct ziti_ctx *ziti_context;

#if _WIN32
#include <WinSock2.h>
typedef SOCKET ziti_socket_t;
#else
typedef int ziti_socket_t;
#endif

/**
 * @brief Initialize Ziti library.
 *
 * Creates a background processing thread for Ziti processing.
 */
ZITI_FUNC
void Ziti_lib_init(void);

/**
 * @brief return Ziti error code for last failed operation.
 * Use [ziti_errorstr] to get error message.
 * @return
 */
ZITI_FUNC
int Ziti_last_error(void);

/**
 * @brief Load Ziti identity.
 * @param identity location of identity configuration
 * @return Ziti Context handle
 */
ZITI_FUNC
ziti_context Ziti_load_context(const char *identity);

/**
 * @brief creates a socket handle(Windows) or file descriptor(*nix) suitable for connecting to a Ziti service
 * @param type socket type which defines communication semantics, only SOCK_STREAM and SOCK_DGRAM are supported at this time (see socket(2))
 * @return native socket handle
 */
ZITI_FUNC
ziti_socket_t Ziti_socket(int type);

/**
 * @brief Connect socket to a Ziti service
 * @param socket socket handle created with [Ziti_socket()]
 * @param ztx Ziti context
 * @param service service name provided by [ztx]
 * @return 0 on sucess, negative error code on failure
 */
ZITI_FUNC
int Ziti_connect(ziti_socket_t socket, ziti_context ztx, const char *service);

/**
 * @brief Connect socket to a Ziti service with the given intercept address
 * @param socket socket handle created with [Ziti_socket()]
 * @param host target hostname
 * @param port target port
 * @return
 */
ZITI_FUNC
int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port);

/**
 * @brief Shutdown Ziti library.
 *
 * All loaded contexts are shutdown and background thread is terminated.
 */
ZITI_FUNC
void Ziti_lib_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_SOCKET_H
