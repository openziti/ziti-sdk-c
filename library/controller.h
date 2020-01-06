/*
Copyright 2019-2020 Netfoundry, Inc.

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

#ifndef ZT_SDK_CONTROLLER_H
#define ZT_SDK_CONTROLLER_H

#include <nf/ziti.h>

typedef int (*ctrl_req)(struct nf_ctx *, uv_os_sock_t sock, tls_engine *ssl);

int ziti_ctrl_process(nf_context ctx, ...);

int ziti_ctrl_version(nf_context ctx, uv_os_sock_t, tls_engine *);
int ziti_ctrl_login(nf_context ctx, uv_os_sock_t, tls_engine *);

int ziti_ctrl_logout(nf_context ctx, uv_os_sock_t, tls_engine *);

int ziti_ctrl_get_services(nf_context ctx, uv_os_sock_t, tls_engine *);

int ziti_ctrl_get_network_sessions(nf_context ctx, uv_os_sock_t, tls_engine *);

int ziti_logout(nf_context ctx);
#endif //ZT_SDK_CONTROLLER_H
