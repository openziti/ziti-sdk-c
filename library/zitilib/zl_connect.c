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

#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include <ziti/zitilib.h>

#include "connect.h"
#include "util/future.h"
#include "utils.h"
#include "zl.h"

#include <stc/cstr.h>
#include <uv.h>

#ifdef _WIN32
#include <WinSock2.h>
#define close(s) closesocket(s)
#define poll(f,d,t) WSAPoll(f,d,t)
#else
#include <poll.h>
#endif

// create ephemeral acceptor socket and bind to appropriate loopback address
static ziti_socket_t mk_acceptor(struct sockaddr *addr, socklen_t *len);

struct conn_req_s {
    ziti_socket_t app_fd;
    ziti_socket_t accept_fd;
    ziti_socket_t ziti_fd;
    ziti_connection conn;
    int so_type;

    ziti_handle_t ziti_handle;
    cstr service;
    cstr terminator;

    cstr host;
    uint16_t port;
    ziti_dial_opts opts;
    uv_loop_t *loop;
};

static void on_ziti_connect(ziti_connection conn, int status);

static void conn_req_drop(struct conn_req_s *req) {
    close(req->accept_fd);
    cstr_drop(&req->service);
    cstr_drop(&req->terminator);
    cstr_drop(&req->host);
    ziti_dial_opts_free(&req->opts);
}

static void do_ziti_connect(struct conn_req_s *req, future_t *f, uv_loop_t *l) {
    if (cstr_is_empty(&req->service)) {
        ZITI_LOG(DEBUG, "connecting fd[%d] to %s:%d", req->app_fd,
                 cstr_str(&req->host), req->port);
    } else {
        ZITI_LOG(DEBUG, "connecting fd[%d] to service[%s] terminator[%s]", req->app_fd,
                 cstr_str(&req->service), cstr_str(&req->terminator));
    }
    req->loop = l;
    ztx_wrap_t *wrap = zl_find_wrap(req->ziti_handle);

    ziti_protocol zproto = ziti_protocol_Unknown;
    switch (req->so_type) {
    case SOCK_STREAM: zproto = ziti_protocols.tcp;break;
    case SOCK_DGRAM: zproto = ziti_protocols.udp;break;
    default: break;
    }

    in_addr_t ip;
    cstr host = cstr_init();
    if (uv_inet_pton(AF_INET, cstr_str(&req->host), &ip) == 0) {
        // try reverse lookup
        const char *h = Ziti_lookup(ip);
        if (h != NULL) {
            cstr_assign(&host, h);
        }
    }
    if (cstr_is_empty(&host)) {
        cstr_copy(&host, req->host);
    }

    if (wrap == NULL) {
        MODEL_MAP_FOR(it, ziti_contexts) {
            wrap = model_map_it_value(it);
            const ziti_service *svc = ziti_dial_opts_for_addr(
                &req->opts, wrap->ztx,
                zproto, cstr_str(&host), req->port, NULL, 0);

            if (svc != NULL) {
                cstr_assign(&req->service, svc->name);
                break;
            }
            wrap = NULL;
        }
    }
    cstr_drop(&host);

    int rc = ZITI_SERVICE_UNAVAILABLE;
    if (wrap != NULL && !cstr_is_empty(&req->service)) {
        ziti_connection conn;
        ziti_conn_init(wrap->ztx, &conn, req);
        ZITI_LOG(DEBUG, "connecting fd[%d] to service[%s]", req->app_fd, cstr_str(&req->service));
        ZITI_LOG(VERBOSE, "appdata[%.*s]", (int)req->opts.app_data_sz, (char*)req->opts.app_data);
        ZITI_LOG(VERBOSE, "identity[%s]", req->opts.identity);
        rc = ziti_dial_with_options(conn, cstr_str(&req->service), &req->opts, on_ziti_connect, NULL);
    }

    if (rc != ZITI_OK) {
        ZITI_LOG(WARN, "no service for target address[%s:%s:%d]: %s",
                 ziti_protocols.name(zproto), cstr_str(&req->host), req->port, ziti_errorstr(rc));
        // this will close the acceptor socket
        // and cause ECONNREFUSED on the client socket
        conn_req_drop(req);
        free(req);
    }
}

int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port) {
    if (host == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (port == 0 || port > UINT16_MAX) {
        errno = EINVAL;
        return -1;
    }

    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    getsockopt(socket, SOL_SOCKET, SO_TYPE, (void*)&so_type, &so_type_len);

    int af = zl_socket_af(socket);
    struct sockaddr_storage accept_addr = {.ss_family = af,};
    socklen_t addr_len = sizeof(accept_addr);
    ziti_socket_t accept_fd = mk_acceptor((struct sockaddr *)&accept_addr, &addr_len);
    if (accept_fd == SOCKET_ERROR) {
        return -1;
    }

    const char *id;
    ztx_wrap_t *wrap;
    MODEL_MAP_FOREACH(id, wrap, &ziti_contexts) {
        await_future(wrap->services_loaded, NULL);
    }

    NEWP(req, struct conn_req_s);
    *req = (struct conn_req_s) {
        .app_fd = socket,
        .accept_fd = accept_fd,
        .so_type = so_type,
        .ziti_handle = ZITI_INVALID_HANDLE,
        .host = cstr_from(host),
        .port = port,
    };

    schedule_on_loop((loop_work_cb) do_ziti_connect, req, false);
    return connect(req->app_fd, (struct sockaddr *)&accept_addr, addr_len);
}

int Ziti_connect(ziti_socket_t socket, ziti_handle_t zh, const char *service, const char *terminator) {
    if (zh == ZITI_INVALID_HANDLE || service == NULL) {
        errno = EINVAL;
        return -1;
    }
    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    getsockopt(socket, SOL_SOCKET, SO_TYPE, (void*)&so_type, &so_type_len);

    int af = zl_socket_af(socket);
    struct sockaddr_storage addr = { .ss_family = af, };
    socklen_t addr_len = sizeof(addr);
    ziti_socket_t accept_fd = mk_acceptor((struct sockaddr *)&addr, &addr_len);
    if (accept_fd == SOCKET_ERROR) {
        return -1;
    }

    NEWP(req, struct conn_req_s);
    *req = (struct conn_req_s) {
        .app_fd = socket,
        .accept_fd = accept_fd,
        .so_type = so_type,
        .ziti_handle = zh,
        .service = cstr_from(service),
        .terminator = terminator ? cstr_from(terminator) : cstr_init(),
    };

    // connect could be blocking so start this
    schedule_on_loop((loop_work_cb)do_ziti_connect, req, false);
    return connect(req->app_fd, (struct sockaddr *)&addr, addr_len);
}

static void connect_work_done(uv_work_t *w, int status) {
    struct conn_req_s *req = w->data;
    free(w);
    if (status != 0) {
        ZITI_LOG(ERROR, "error in connect work: %d/%s", status, uv_strerror(status));
    } else  if (req->ziti_fd == SOCKET_ERROR) {
        ZITI_LOG(ERROR, "failed to accept connection on bridge socket: %d/%s", errno, strerror(errno));
    } else {
        ziti_conn_bridge_fds(req->conn, req->ziti_fd, req->ziti_fd, NULL, NULL);
    }

    conn_req_drop(req);
    free(req);
}

// worker thread to avoid blocking the loop
static void connect_work(uv_work_t *w) {
    struct conn_req_s *req = w->data;
    struct pollfd p = {.fd = req->accept_fd, .events = POLLIN};

    if (listen(req->accept_fd, 1) == 0 &&
        poll(&p, 1, 3000) == 1) {
        ziti_socket_t zfd = accept(req->accept_fd, NULL, NULL);
        if (zfd == SOCKET_ERROR) {
            ZITI_LOG(ERROR, "failed to accept connection on bridge socket");
            return;
        }

        // verify connection is from the expected client before bridging
        struct sockaddr_storage peer, clt;
        socklen_t peer_len = sizeof(peer), clt_len = sizeof(clt);
        if (getpeername(zfd, (struct sockaddr *)&peer, &peer_len) == 0 &&
            getsockname(req->app_fd, (struct sockaddr *)&clt, &clt_len) == 0 &&
            memcmp(&peer, &clt, clt_len) == 0) {
            req->ziti_fd = zfd;
        } else {
            ZITI_LOG(WARN, "unexpected connection on bridge socket");
            close(zfd);
            return;
        }
    }
}

static void on_ziti_connect(ziti_connection conn, int status) {
    struct conn_req_s *req = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        req->ziti_fd = SOCKET_ERROR;
        req->conn = conn;
        uv_work_t * w = calloc(1, sizeof(*w));
        w->data = req;
        if (uv_queue_work(req->loop, w, connect_work, connect_work_done) == 0) {
            return;
        }
        free(w);
        ZITI_LOG(ERROR, "failed to queue work for ziti connect");
    }

    ZITI_LOG(WARN, "failed to establish ziti connection: %d(%s)", status, ziti_errorstr(status));
    ziti_close(conn, NULL);

    conn_req_drop(req);
    free(req);
}

static ziti_socket_t mk_acceptor(struct sockaddr *addr, socklen_t *len) {
    socklen_t addr_len  = 0;
    switch (addr->sa_family) {
    case AF_INET:
        addr_len = sizeof(struct sockaddr_in);
        ((struct sockaddr_in *) addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        break;
    case AF_INET6:
        addr_len = sizeof(struct sockaddr_in6);
        ((struct sockaddr_in6 *) addr)->sin6_addr = in6addr_loopback;
        break;
    default:
        errno = EAFNOSUPPORT;
        return SOCKET_ERROR;
    }

    ziti_socket_t s = socket(addr->sa_family, SOCK_STREAM, 0);
    if (s < 0 ||
        bind(s, (const struct sockaddr *)addr, addr_len) != 0 ||
        getsockname(s, (struct sockaddr *)addr, len) !=0 ) {
        ZITI_LOG(ERROR, "failed to create ephemeral socket for acceptor: %d(%s)", errno, strerror(errno));
        if (s >= 0) close(s);
        return -1;
    }

#if _WIN32
     u_long mode = 1;  // 1 to enable non-blocking socket
     ioctlsocket(s, FIONBIO, &mode);
#else
    int opt = fcntl(s, F_GETFL);
    fcntl(s, F_SETFL, opt | O_NONBLOCK);
#endif

    return s;
}
