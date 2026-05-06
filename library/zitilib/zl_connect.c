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

static int zl_set_non_blocking(ziti_socket_t sock);

struct conn_srv_s {
    int so_type;
    struct sockaddr_storage app_addr;
    struct sockaddr *zl_addr;

    ziti_connection conn;
    ziti_handle_t ziti_handle;
    cstr service;
    cstr terminator;

    uv_handle_t *bridge_handle;
    uv_os_sock_t srv_fd;
    uv_loop_t *loop;
};

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

static void conn_srv_drop(struct conn_srv_s *srv) {
    if (srv == NULL) {
        return;
    }
    cstr_drop(&srv->service);
    cstr_drop(&srv->terminator);
}

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
static void zl_on_bridge_close(uv_handle_t *h) {
    uv_close(h, (uv_close_cb)free);
}

static void zl_on_ziti_connect(ziti_connection conn, int status) {
    struct conn_srv_s *req = ziti_conn_data(conn);
    if (req == NULL) {
        ZITI_LOG(DEBUG, "canceled already");
        ziti_close(conn, NULL);
        return;
    }

    if (status == ZITI_OK) {
        if (req->bridge_handle == NULL) {

            struct pollfd pfd = {
                .fd = req->srv_fd,
                .events = POLLIN,
            };

            // this should be ready immediately but do a quick poll to avoid blocking the loop
            if (poll(&pfd, 1, 1) != 1 || (pfd.revents & POLLIN) == 0) {
                ZITI_LOG(WARN, "client not connected in time");
                ziti_close(conn, NULL);
                goto cleanup;
            }

            struct sockaddr_storage accept_addr = {};
            socklen_t aa_len = sizeof(accept_addr);
            uv_os_sock_t bridge_fd = accept(req->srv_fd, (struct sockaddr *)&accept_addr, &aa_len);
            if (bridge_fd == SOCKET_ERROR) {
                ziti_close(conn, NULL);
                goto cleanup;
            }

            if(memcmp(&accept_addr, &req->app_addr, aa_len) != 0) {
                ZITI_LOG(WARN, "accept address mismatch");
                close(bridge_fd);
                ziti_close(conn, NULL);
                goto cleanup;
            }

            NEWP(h, uv_tcp_t);
            if (uv_tcp_init(req->loop, h) != 0) {
                ZITI_LOG(WARN, "failed to init bridge handle");
                free(h);
                close(bridge_fd);
                ziti_close(conn, NULL);
                goto cleanup;
            }
            if (uv_tcp_open(h, bridge_fd) != 0) {
                ZITI_LOG(WARN, "failed to init bridge handle");
                uv_close((uv_handle_t *) h, (uv_close_cb) free);
                close(bridge_fd);
                ziti_close(conn, NULL);
                goto cleanup;
            }
            req->bridge_handle = (uv_handle_t *) h;
        }
        ziti_conn_bridge(conn, req->bridge_handle, zl_on_bridge_close);
    }

    if (status != ZITI_OK) {
        ziti_close(conn, NULL);
        if (req->bridge_handle != NULL) {
            uv_close(req->bridge_handle, (uv_close_cb)free);
        }
    }

    cleanup:
    if (req->srv_fd != SOCKET_ERROR) {
        close(req->srv_fd);
    }
    conn_srv_drop(req);
    free(req);
}

static void zl_connect(struct conn_srv_s *req, future_t *f, uv_loop_t *l) {
    if (req->app_addr.ss_family != AF_INET && req->app_addr.ss_family != AF_INET6) {
        ZITI_LOG(WARN, "unsupported address family: %d", req->app_addr.ss_family);
        fail_future(f, EAFNOSUPPORT);
        return;
    }

    if (req->so_type != SOCK_STREAM && req->so_type != SOCK_DGRAM) {
        ZITI_LOG(WARN, "unsupported socket type: %d", req->so_type);
        fail_future(f, EPROTOTYPE);
        return;
    }

    ztx_wrap_t *wrap = zl_find_wrap(req->ziti_handle);
    if (wrap == NULL) {
        ZITI_LOG(WARN, "ziti handle[%d] not found", req->ziti_handle);
        fail_future(f, EINVAL);
        goto err_cleanup;
    }

    req->loop = l;
    ziti_dial_opts opts = {
        .stream = req->so_type == SOCK_STREAM,
        .identity = cstr_is_empty(&req->terminator) ? NULL : (char *) cstr_str(&req->terminator),
    };
    if (ziti_conn_init(wrap->ztx, &req->conn, req) != ZITI_OK ||
        ziti_dial_with_options(req->conn, cstr_str(&req->service), &opts, zl_on_ziti_connect, NULL) != ZITI_OK) {
        ZITI_LOG(WARN, "failed to init/dial connection");
        fail_future(f, ECONNREFUSED);
        goto err_cleanup;
    }

    int addr_len;
    struct sockaddr *addr = req->zl_addr;
    if (req->app_addr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *) addr;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr_len = sizeof(struct sockaddr_in);
    } else if (req->app_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;
        a6->sin6_family = AF_INET6;
        a6->sin6_addr = in6addr_loopback;
        addr_len = sizeof(struct sockaddr_in6);
    }

    if (req->so_type == SOCK_DGRAM) {
        NEWP(udp, uv_udp_t);
        if (uv_udp_init(l, udp) != 0) {
            free(udp);
            fail_future(f, EINVAL);
            goto err_cleanup;
        }

        if (uv_udp_bind(udp, (struct sockaddr *) addr, 0) != 0 ||
            uv_udp_getsockname(udp, (struct sockaddr *) addr, &addr_len) != 0 ||
            uv_udp_connect(udp, (struct sockaddr *) &req->app_addr) != 0
            ) {
            ZITI_LOG(WARN, "failed to bind/udp connect bridge socket");
            uv_close((uv_handle_t *) udp, (uv_close_cb)free);
            fail_future(f, EADDRNOTAVAIL);
            goto err_cleanup;
        }

        req->bridge_handle = (uv_handle_t *) udp;
        udp->data = req;
        req->srv_fd = SOCKET_ERROR;

    } else if (req->so_type == SOCK_STREAM) {
        uv_os_sock_t srv_fd = socket(req->app_addr.ss_family, SOCK_STREAM, 0);
        if (srv_fd == SOCKET_ERROR) {
            ZITI_LOG(WARN, "failed to create accept socket: %d/%s", errno, strerror(errno));
            fail_future(f, errno);
            goto err_cleanup;
        }

        if (bind(srv_fd, addr, addr_len) != 0 ||
            listen(srv_fd, 1) != 0){
            ZITI_LOG(WARN, "failed to bind/listen TCP socket");
            close(srv_fd);
            fail_future(f, errno);
            goto err_cleanup;
        }
        // these should be safe
        socklen_t alen = addr_len;
        getsockname(srv_fd, (struct sockaddr *) addr, &alen);
        zl_set_non_blocking(srv_fd);
        req->srv_fd = srv_fd;
    }

    complete_future(f, NULL, 0);
    return;

err_cleanup:
    if (req->conn) {
        ziti_conn_set_data(req->conn, NULL);
        ziti_close(req->conn, NULL);
    }
    conn_srv_drop(req);
    free(req);
}

int Ziti_connect(ziti_socket_t socket, ziti_handle_t zh, const char *service, const char *terminator) {
    if (zh == ZITI_INVALID_HANDLE || service == NULL) {
        errno = EINVAL;
        return -1;
    }
    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (getsockopt(socket, SOL_SOCKET, SO_TYPE, (void*)&so_type, &so_type_len) != 0) {
        return -1;
    }

    if (so_type != SOCK_STREAM && so_type != SOCK_DGRAM) {
        errno = EPROTOTYPE;
        return -1;
    }

    int af = zl_socket_af(socket);
    if (af != AF_INET && af != AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    struct sockaddr_storage addr = { .ss_family = af, };
    socklen_t addr_len = sizeof(addr);
    if (af == AF_INET) {
        ((struct sockaddr_in *)&addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr_len = sizeof(struct sockaddr_in);
    } else {
        ((struct sockaddr_in6 *)&addr)->sin6_addr = in6addr_loopback;
        addr_len = sizeof(struct sockaddr_in6);
    }

    NEWP(req, struct conn_srv_s);
    if (bind(socket, (struct sockaddr*)&addr, addr_len) != 0 ||
        getsockname(socket, (struct sockaddr *)&req->app_addr, &addr_len) != 0) {
        free(req);
        return -1;
    }

    struct sockaddr_storage zl_addr = {};
    req->zl_addr = (struct sockaddr *) &zl_addr;
    req->so_type = so_type;
    req->ziti_handle = zh;
    req->service = cstr_from(service);
    req->terminator = terminator ? cstr_from(terminator) : cstr_init();

    // connect could be blocking so start this
    future_t *f = schedule_on_loop((loop_work_cb)zl_connect, req, true);
    int rc = await_future(f, NULL);
    destroy_future(f);
    if (rc != 0 || zl_addr.ss_family == 0) {
        errno = rc;
        zl_set_error(ZITI_SERVICE_UNAVAILABLE);
        return -1;
    }

    addr_len = zl_addr.ss_family == AF_INET ?
               sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    return connect(socket, (struct sockaddr *)&zl_addr, addr_len);
}

static void connect_work_done(uv_work_t *w, int status) {
    struct conn_req_s *req = w->data;
    free(w);
    if (status != 0) {
        ZITI_LOG(ERROR, "error in connect work: %d/%s", status, uv_strerror(status));
        ziti_close(req->conn, NULL);
    } else  if (req->ziti_fd == SOCKET_ERROR) {
        ZITI_LOG(ERROR, "failed to accept connection on bridge socket: %d/%s", errno, strerror(errno));
        ziti_close(req->conn, NULL);
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

static int zl_set_non_blocking(ziti_socket_t sock) {
#if _WIN32
    u_long opt = 1;
    return ioctlsocket(sock, FIONBIO, &opt);
#else
    int opt = fcntl(sock, F_GETFL);
    if (opt == -1) {
        return -1;
    }
    opt |= O_NONBLOCK;
    return fcntl(sock, F_SETFL, opt);
#endif
}
