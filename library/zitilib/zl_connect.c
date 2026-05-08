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
static inline void set_errno(int e) {

    switch(e) {
    case EINVAL: WSASetLastError(WSAEINVAL); break;
    case EALREADY: WSASetLastError(WSAEALREADY); break;
    case EWOULDBLOCK: WSASetLastError(WSAEWOULDBLOCK); break;
    case EPROTOTYPE: WSASetLastError(WSAEPROTOTYPE); break;
    case EAFNOSUPPORT: WSASetLastError(WSAEAFNOSUPPORT); break;
    case EADDRNOTAVAIL: WSASetLastError(WSAEADDRNOTAVAIL); break;
    default:
        WSASetLastError(e);
    }
}
#define sock_error() WSAGetLastError()
static char wsa_err_buf[256];
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
#define set_errno(e) errno = (e)
#define sock_error() errno
#define err(e) e
#include <poll.h>
#endif

static int zl_set_non_blocking(ziti_socket_t sock);
static int zl_try_bind(ziti_socket_t socket, int af, struct sockaddr *addr, socklen_t *addrlen);

struct conn_srv_s {
    int so_type;
    struct sockaddr_storage app_addr;
    struct sockaddr *zl_addr;

    ziti_connection conn;
    ziti_handle_t ziti_handle;
    cstr service;
    cstr terminator;
    cstr host;
    uint16_t port;
    const struct sockaddr *addr;

    uv_handle_t *bridge_handle;
    uv_os_sock_t srv_fd;
    uv_loop_t *loop;
};

static void zl_on_ziti_connect(ziti_connection conn, int status);

static void conn_srv_drop(struct conn_srv_s *srv) {
    if (srv == NULL) {
        return;
    }
    cstr_drop(&srv->host);
    cstr_drop(&srv->service);
    cstr_drop(&srv->terminator);
}

// Sets up the loopback bridge socket (UDP or TCP listener) that the user's
// socket will connect to. On success, populates req->zl_addr with the bound
// loopback address and either req->bridge_handle (UDP) or req->srv_fd (TCP).
// Returns 0 on success, or a POSIX errno on failure.
static int setup_bridge_socket(struct conn_srv_s *req, uv_loop_t *l) {
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
    } else {
        return err(EAFNOSUPPORT);
    }

    if (req->so_type == SOCK_DGRAM) {
        NEWP(udp, uv_udp_t);
        if (uv_udp_init(l, udp) != 0) {
            free(udp);
            return err(EINVAL);
        }

        if (uv_udp_bind(udp, addr, 0) != 0 ||
            uv_udp_getsockname(udp, addr, &addr_len) != 0 ||
            uv_udp_connect(udp, (struct sockaddr *) &req->app_addr) != 0) {
            ZITI_LOG(WARN, "failed to bind/udp connect bridge socket");
            uv_close((uv_handle_t *) udp, (uv_close_cb)free);
            return err(EADDRNOTAVAIL);
        }

        req->bridge_handle = (uv_handle_t *) udp;
        udp->data = req;
        req->srv_fd = SOCKET_ERROR;
        return 0;
    }

    if (req->so_type == SOCK_STREAM) {
        uv_os_sock_t srv_fd = socket(req->app_addr.ss_family, SOCK_STREAM, 0);
        if (srv_fd == SOCKET_ERROR) {
            int e = sock_error();
            ZITI_LOG(WARN, "failed to create accept socket: %d/%s", e, strerror(e));
            return e;
        }

        if (bind(srv_fd, addr, addr_len) != 0 ||
            listen(srv_fd, 1) != 0) {
            int e = sock_error();
            ZITI_LOG(WARN, "failed to bind/listen TCP socket");
            close(srv_fd);
            return e;
        }
        // these should be safe
        socklen_t alen = addr_len;
        getsockname(srv_fd, addr, &alen);
        zl_set_non_blocking(srv_fd);
        req->srv_fd = srv_fd;
        return 0;
    }

    return err(EPROTOTYPE);
}

static void do_ziti_connect(struct conn_srv_s *req, future_t *f, uv_loop_t *l) {
    req->loop = l;
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

    ziti_dial_opts opts = {};
    const ziti_service *svc = NULL;
    ztx_wrap_t *wrap = NULL;
    MODEL_MAP_FOR(it, ziti_contexts) {
        wrap = model_map_it_value(it);
        svc = ziti_dial_opts_for_addr(
            &opts, wrap->ztx,
            zproto, cstr_str(&host), req->port, NULL, 0);

        if (svc != NULL) {
            break;
        }
        wrap = NULL;
        svc = NULL;
    }
    cstr_drop(&host);

    if (svc == NULL) {
        ZITI_LOG(WARN, "no service for target address[%s:%s:%d]",
                 ziti_protocols.name(zproto), cstr_str(&req->host), req->port);
        fail_future(f, err(ECONNREFUSED));
        goto err_cleanup;
    }

    ziti_conn_init(wrap->ztx, &req->conn, req);
    ZITI_LOG(VERBOSE, "appdata[%.*s]", (int)opts.app_data_sz, (char*)opts.app_data);
    ZITI_LOG(VERBOSE, "identity[%s]", opts.identity);
    int rc = ziti_dial_with_options(req->conn, svc->name, &opts, zl_on_ziti_connect, NULL);
    ziti_dial_opts_free(&opts);
    if (rc != ZITI_OK) {
        ZITI_LOG(WARN, "no service for target address[%s:%s:%d]: %s",
                 ziti_protocols.name(zproto), cstr_str(&req->host), req->port, ziti_errorstr(rc));
        fail_future(f, err(ECONNREFUSED));
        goto err_cleanup;
    }

    rc = setup_bridge_socket(req, l);
    if (rc != 0) {
        fail_future(f, rc);
        goto err_cleanup;
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

int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port) {
    if (host == NULL) {
        set_errno(err(EINVAL));
        return -1;
    }
    if (port == 0 || port > UINT16_MAX) {
        set_errno(err(EINVAL));
        return -1;
    }

    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    getsockopt(socket, SOL_SOCKET, SO_TYPE, (void*)&so_type, &so_type_len);
    if (so_type != SOCK_STREAM && so_type != SOCK_DGRAM) {
        set_errno(err(EPROTOTYPE));
        return -1;
    }

    int af = zl_socket_af(socket);
    if (af != AF_INET && af != AF_INET6) {
        set_errno(err(EAFNOSUPPORT));
        return -1;
    }

    NEWP(req, struct conn_srv_s);
    socklen_t addr_len = sizeof(req->app_addr);
    int bind_err = zl_try_bind(socket, af, (struct sockaddr *) &req->app_addr, &addr_len);
    if (bind_err != 0) {
        free(req);
        set_errno(bind_err);
        return -1;
    }

    req->so_type = so_type;
    req->host = cstr_from(host);
    req->port = port;

    struct sockaddr_storage zl_addr = {};
    req->zl_addr = (struct sockaddr *) &zl_addr;
    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, req, true);
    int rc = await_future(f, NULL);
    destroy_future(f);
    ZITI_LOG(DEBUG, "connect sock[%lu], rc = %d, family = %d",
             (unsigned long)socket, rc, zl_addr.ss_family);
    if (rc != 0 || zl_addr.ss_family == 0) {
        set_errno(rc);
        switch (rc) {
#if _WIN32
        case WSAEADDRNOTAVAIL:
        case WSAECONNREFUSED:
#endif
        case EADDRNOTAVAIL:
        case ECONNREFUSED:
            zl_set_error(ZITI_SERVICE_UNAVAILABLE);
            break;
#if _WIN32
        case WSAEINVAL:
#endif
        case EINVAL:
        default:
            zl_set_error(ZITI_INVALID_STATE);
        }
        return -1;
    }

    set_errno(0);
    addr_len = zl_addr.ss_family == AF_INET ?
               sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    return connect(socket, (struct sockaddr *)&zl_addr, addr_len);
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
        fail_future(f, err(EAFNOSUPPORT));
        return;
    }

    if (req->so_type != SOCK_STREAM && req->so_type != SOCK_DGRAM) {
        ZITI_LOG(WARN, "unsupported socket type: %d", req->so_type);
        fail_future(f, err(EPROTOTYPE));
        return;
    }

    ztx_wrap_t *wrap = zl_find_wrap(req->ziti_handle);
    if (wrap == NULL) {
        ZITI_LOG(WARN, "ziti handle[%d] not found", req->ziti_handle);
        fail_future(f, err(EINVAL));
        goto err_cleanup;
    }

    if (model_map_get(&wrap->intercepts, cstr_str(&req->service)) == NULL) {
        ZITI_LOG(WARN, "no service[%s]", cstr_str(&req->service));
        fail_future(f, err(ECONNREFUSED));
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
        fail_future(f, err(ECONNREFUSED));
        goto err_cleanup;
    }

    int rc = setup_bridge_socket(req, l);
    if (rc != 0) {
        fail_future(f, rc);
        goto err_cleanup;
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

#define CHECK_SOCKET(s) do { \
    int err = 0;             \
    socklen_t el = sizeof(err); \
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) == 0) { \
        if (err != 0)        \
                ZITI_LOG(WARN, "socket[%d]: error[%d] %s", (int)socket, err, strerror(err)); \
            else              \
        ZITI_LOG(WARN, "failed to check socket[%d]: err[%d] %s", socket, sock_error(), strerror(sock_error()));                     \
        }\
} while(0)

int Ziti_connect(ziti_socket_t socket, ziti_handle_t zh, const char *service, const char *terminator) {
    if (zh == ZITI_INVALID_HANDLE || service == NULL) {
        set_errno(err(EINVAL));
        return -1;
    }
    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (getsockopt(socket, SOL_SOCKET, SO_TYPE, (void*)&so_type, &so_type_len) != 0) {
        return -1;
    }

    if (so_type != SOCK_STREAM && so_type != SOCK_DGRAM) {
        set_errno(err(EPROTOTYPE));
        return -1;
    }

    int af = zl_socket_af(socket);
    if (af != AF_INET && af != AF_INET6) {
        set_errno(err(EAFNOSUPPORT));
        return -1;
    }

    CHECK_SOCKET(socket);

    NEWP(req, struct conn_srv_s);
    socklen_t addr_len = sizeof(req->app_addr);
    int bind_err = zl_try_bind(socket, af, (struct sockaddr *) &req->app_addr, &addr_len);
    if (bind_err != 0) {
        ZITI_LOG(WARN, "failed to bind client socket[%lu]: %d/%s",
                 (unsigned long)socket, bind_err, strerror(bind_err));
        free(req);
        set_errno(bind_err);
        return -1;
    }

    CHECK_SOCKET(socket);

    struct sockaddr_storage zl_addr = {};
    req->zl_addr = (struct sockaddr *) &zl_addr;
    req->so_type = so_type;
    req->ziti_handle = zh;
    req->service = cstr_from(service);
    req->terminator = terminator ? cstr_from(terminator) : cstr_init();

    CHECK_SOCKET(socket);

    // connect could be blocking so start this
    future_t *f = schedule_on_loop((loop_work_cb)zl_connect, req, true);

    CHECK_SOCKET(socket);

    int rc = await_future(f, NULL);
    destroy_future(f);
    ZITI_LOG(DEBUG, "connect sock[%lu], rc = %d, family = %d",
             (unsigned long)socket, rc, zl_addr.ss_family);

    if (rc != 0 || zl_addr.ss_family == 0) {
        set_errno(rc);
        switch (rc) {
        case err(EADDRNOTAVAIL):
        case err(ECONNREFUSED):
            zl_set_error(ZITI_SERVICE_UNAVAILABLE);
            break;
        case err(EINVAL):
        default:
             zl_set_error(ZITI_INVALID_STATE);
        }
        return -1;
    }

    CHECK_SOCKET(socket);

    addr_len = zl_addr.ss_family == AF_INET ?
               sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    int res = connect(socket, (struct sockaddr *)&zl_addr, addr_len);
    if (res != 0) {
        int e = sock_error();
        ZITI_LOG(DEBUG, "connect to bridge socket: %d/%s", e, strerror(e));
    }
    return res;
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

static void zl_connect_sockaddr(struct conn_srv_s *req, future_t *f, uv_loop_t *l) {
    char hbuf[128];
    const char *hostname = NULL;
    int port = 0;
    const void *addr_ptr = NULL;
    if (req->addr->sa_family == AF_INET) {
        hostname = Ziti_lookup(((const struct sockaddr_in*)req->addr)->sin_addr.s_addr);
        port = ntohs(((const struct sockaddr_in*)req->addr)->sin_port);
        addr_ptr = &((const struct sockaddr_in*)req->addr)->sin_addr;
    } else if (req->addr->sa_family == AF_INET6) {
        port = ntohs(((const struct sockaddr_in6*)req->addr)->sin6_port);
        addr_ptr = &((const struct sockaddr_in6*)req->addr)->sin6_addr;
    }
    if (hostname == NULL) {
        uv_inet_ntop(req->addr->sa_family, addr_ptr, hbuf, sizeof(hbuf));
        hostname = hbuf;
    }

    ziti_dial_opts opts = {};
    ziti_protocol zproto = req->so_type == SOCK_STREAM ?
                           ziti_protocols.tcp : ziti_protocols.udp;
    const ziti_service *svc = NULL;
    ztx_wrap_t *wrap = NULL;
    MODEL_MAP_FOR(it, ziti_contexts) {
        wrap = model_map_it_value(it);
        svc = ziti_dial_opts_for_addr(
            &opts, wrap->ztx,
            zproto, hostname, port, NULL, 0);

        if (svc != NULL) {
            break;
        }
        wrap = NULL;
        svc = NULL;
    }

    if (svc == NULL) {
        ZITI_LOG(WARN, "no service for target address[%s:%d]",
                 hostname, port);
        fail_future(f, ECONNREFUSED);
        goto err_cleanup;
    }

    req->loop = l;
    if (ziti_conn_init(wrap->ztx, &req->conn, req) != ZITI_OK ||
        ziti_dial_with_options(req->conn, svc->name, &opts, zl_on_ziti_connect, NULL) != ZITI_OK) {
        ZITI_LOG(WARN, "failed to init/dial connection");
        fail_future(f, ECONNREFUSED);
        goto err_cleanup;
    }
    ziti_dial_opts_free(&opts);

    int rc = setup_bridge_socket(req, l);
    if (rc != 0) {
        fail_future(f, rc);
        goto err_cleanup;
    }

    complete_future(f, NULL, 0);
    return;

err_cleanup:
    ziti_dial_opts_free(&opts);
    if (req->conn) {
        ziti_conn_set_data(req->conn, NULL);
        ziti_close(req->conn, NULL);
    }
    conn_srv_drop(req);
    free(req);
}

int Ziti_connect_sockaddr(ziti_socket_t socket, const struct sockaddr *addr, int addrlen) {
    // let standard connect handle unexpected parameters
    if (addr == NULL ||
        (addr->sa_family == AF_INET && addrlen != sizeof(struct sockaddr_in) ) ||
        (addr->sa_family == AF_INET6 && addrlen != sizeof(struct sockaddr_in6)) ||
        (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
        return connect(socket, addr, (socklen_t)addrlen);
    }
    
    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (getsockopt(socket, SOL_SOCKET, SO_TYPE, (void*)&so_type, &so_type_len) != 0) {
        return -1;
    }
    
    if (so_type != SOCK_STREAM && so_type != SOCK_DGRAM) {
        set_errno(EPROTOTYPE);
        return -1;
    }
    NEWP(req, struct conn_srv_s);
    socklen_t al = sizeof(req->app_addr);
    int bind_err = zl_try_bind(socket, addr->sa_family, (struct sockaddr *) &req->app_addr, &al);
    if (bind_err != 0) {
        free(req);
        set_errno(bind_err);
        return -1;
    }
    
    struct sockaddr_storage zl_addr = {};
    req->zl_addr = (struct sockaddr *) &zl_addr;
    req->addr = addr;
    req->so_type = so_type;
    future_t *f = schedule_on_loop((loop_work_cb)zl_connect_sockaddr, req, true);
    int rc = await_future(f, NULL);
    destroy_future(f);
    set_errno(0);
    if (rc == 0) { // found ziti service for given address: connect to bridge socket
        socklen_t zl_addr_len = zl_addr.ss_family == AF_INET ?
                                sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        return connect(socket, (struct sockaddr *)&zl_addr, zl_addr_len);
    }

    // ziti service not found for given address: try connecting to original
    return connect(socket, addr, (socklen_t)addrlen);
}

static int zl_try_bind(ziti_socket_t socket, int af, struct sockaddr *addr, socklen_t *addrlen) {
    struct sockaddr_storage a = { .ss_family = af, };
    socklen_t al = 0;
    if (af == AF_INET) {
        ((struct sockaddr_in *)&a)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        al = sizeof(struct sockaddr_in);
    } else {
        ((struct sockaddr_in6 *)&a)->sin6_addr = in6addr_loopback;
        al = sizeof(struct sockaddr_in6);
    }
    
    // ignore bind error (EINVAL) in case the app already bound the socket
    if ((bind(socket, (struct sockaddr*)&a, al) != 0 && (sock_error() != err(EINVAL)))
        || getsockname(socket, addr, addrlen) != 0) {
        int e = sock_error();
        ZITI_LOG(ERROR, "failed to bind socket[%lu] to loopback address: %d/%s",
                 (unsigned long)socket, e, strerror(e));
        return e;
    }

    return 0;
}
