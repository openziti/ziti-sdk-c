//
// Created by eugene on 3/1/19.
//

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
