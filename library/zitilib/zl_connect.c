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

#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include <ziti/zitilib.h>

#include "util/future.h"
#include "connect.h"
#include "zl.h"

#include <uv.h>
#include <stc/cstr.h>

struct conn_req_s {
    ziti_socket_t fd;

    ziti_handle_t ziti_handle;
    cstr service;
    cstr terminator;

    const char *host;
    uint16_t port;
    ziti_dial_opts opts;
};

static void on_ziti_connect(ziti_connection conn, int status);

static void conn_req_drop(struct conn_req_s *req) {
    cstr_drop(&req->service);
    cstr_drop(&req->terminator);
    ziti_dial_opts_free(&req->opts);
}

static void do_ziti_connect(struct conn_req_s *req, future_t *f, uv_loop_t *l) {
    ZITI_LOG(DEBUG, "connecting fd[%d] to %s:%d", req->fd, req->host, req->port);
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));
    if (zs != NULL) {
        ZITI_LOG(WARN, "socket %lu already connecting/connected", (unsigned long) req->fd);
        fail_future(f, EALREADY);
        return;
    }
    ztx_wrap_t *wrap = zl_find_wrap(req->ziti_handle);

    int proto = 0;
    socklen_t optlen = sizeof(proto);
    if (getsockopt(req->fd, SOL_SOCKET, SO_TYPE, (void *) &proto, &optlen)) {
        ZITI_LOG(WARN, "unknown socket type fd[%d]: %d(%s)", req->fd, errno, strerror(errno));
    }
    ziti_protocol zproto = ziti_protocol_Unknown;
    switch (proto) {
    case SOCK_STREAM: zproto = ziti_protocols.tcp;break;
    case SOCK_DGRAM: zproto = ziti_protocols.udp;break;
    default: break;
    }

    in_addr_t ip;
    const char *host = NULL;
    if (uv_inet_pton(AF_INET, req->host, &ip) == 0) { // try reverse lookup
        host = Ziti_lookup(ip);
    }
    if (host == NULL) {
        host = req->host;
    }

    if (wrap == NULL) {
        MODEL_MAP_FOR(it, ziti_contexts) {
            wrap = model_map_it_value(it);
            const ziti_service *svc = ziti_dial_opts_for_addr(
                &req->opts, wrap->ztx,
                zproto, host, req->port, NULL, 0);

            if (svc != NULL) {
                cstr_assign(&req->service, svc->name);
                break;
            }
            wrap = NULL;
        }
    }

    if (wrap != NULL && !cstr_is_empty(&req->service)) {
        zs = calloc(1, sizeof(*zs));
        zs->fd = req->fd;
        zs->f = f;
        cstr_copy(&zs->service, req->service);

        model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);

        ziti_conn_init(wrap->ztx, &zs->conn, zs);

        ZITI_LOG(DEBUG, "connecting fd[%d] to service[%s]", zs->fd, cstr_str(&req->service));
        ZITI_LOG(VERBOSE, "appdata[%.*s]", (int)req->opts.app_data_sz, (char*)req->opts.app_data);
        ZITI_LOG(VERBOSE, "identity[%s]", req->opts.identity);
        ziti_dial_with_options(zs->conn, cstr_str(&req->service), &req->opts, on_ziti_connect, NULL);
    } else {
        ZITI_LOG(WARN, "no service for target address[%s:%s:%d]",
                 ziti_protocols.name(zproto), req->host, req->port);
        fail_future(f, ECONNREFUSED);
    }
}

int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port) {
    if (host == NULL) { return EINVAL; }
    if (port == 0 || port > UINT16_MAX) { return EINVAL; }

    const char *id;
    ztx_wrap_t *wrap;
    MODEL_MAP_FOREACH(id, wrap, &ziti_contexts) {
        await_future(wrap->services_loaded, NULL);
    }

    struct conn_req_s req = {
        .ziti_handle = ZITI_INVALID_HANDLE,
        .fd = socket,
        .host = host,
        .port = port,
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);

    int err = 0;
    if (f) {
        err = await_future(f, NULL);
        zl_set_error(err);
        destroy_future(f);
    }
    conn_req_drop(&req);
    return err ? -1 : 0;
}

int Ziti_connect(ziti_socket_t socket, ziti_handle_t zh, const char *service, const char *terminator) {

    if (zh == ZITI_INVALID_HANDLE) return EINVAL;
    if (service == NULL) return EINVAL;

    struct conn_req_s req = {
        .fd = socket,
        .ziti_handle = zh,
        .service = cstr_from(service),
        .terminator = terminator ? cstr_from(terminator) : cstr_init(),
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);
    int err = await_future(f, NULL);
    zl_set_error(err);
    destroy_future(f);
    conn_req_drop(&req);
    return err ? -1 : 0;
}

static void on_bridge_close(void *ctx) {
    ziti_sock_t *zs = ctx;
    ZITI_LOG(DEBUG, "closed conn for socket(%d)", zs->fd);
    model_map_remove_key(&ziti_sockets, &zs->fd, sizeof(zs->fd));
#if _WIN32
    closesocket(zs->ziti_fd);
#else
    close(zs->ziti_fd);
#endif
    cstr_drop(&zs->service);
    free(zs);
}

static void on_ziti_connect(ziti_connection conn, int status) {
    ziti_sock_t *zs = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        int rc = connect_socket(zs->fd, &zs->ziti_fd);
        if (rc != 0) {
            ZITI_LOG(ERROR, "failed to connect client socket: %d/%s", rc, strerror(rc));
            fail_future(zs->f, rc);
            return;
        }

        ZITI_LOG(DEBUG, "bridge connected to ziti fd[%d]->ziti_fd[%d]->conn[%d]->service[%s]",
                 zs->fd, zs->ziti_fd, zs->conn->conn_id, cstr_str(&zs->service));
        ziti_conn_bridge_fds(conn, (uv_os_fd_t) zs->ziti_fd, (uv_os_fd_t) zs->ziti_fd, on_bridge_close, zs);
        complete_future(zs->f, conn, 0);
    } else {
        ZITI_LOG(WARN, "failed to establish ziti connection: %d(%s)", status, ziti_errorstr(status));
        fail_future(zs->f, status);
        ziti_close(zs->conn, NULL);
        on_bridge_close(zs);
    }
}
