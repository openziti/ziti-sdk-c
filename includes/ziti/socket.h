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

ZITI_FUNC
void Ziti_lib_init(void);

ZITI_FUNC
ziti_context Ziti_load_context(const char *identity);

ZITI_FUNC
ziti_socket_t Ziti_socket();

ZITI_FUNC
int Ziti_connect(ziti_socket_t socket, ziti_context ztx, const char *service);

ZITI_FUNC
void Ziti_lib_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_SOCKET_H
