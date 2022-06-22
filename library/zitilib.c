// Copyright (c) 2022.  NetFoundry Inc.
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


#include <uv_mbed/queue.h>

#include <stdbool.h>
#include <stdlib.h>
#include <uv.h>

#if _WIN32
#if !defined(__MINGW32__)
#pragma comment(lib, "ws2_32.lib")
#include <afunix.h>
#endif
#else
#include <unistd.h>
#endif

#include <ziti/zitilib.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include "utils.h"

typedef struct future_s {
    uv_mutex_t lock;
    uv_cond_t cond;
    bool completed;
    void *result;
    int err;

    TAILQ_ENTRY(future_s) _next;
} future_t;


static const char *configs[] = {
        ZITI_INTERCEPT_CFG_V1,
        ZITI_CLIENT_CFG_V1,
        NULL,
};


static future_t *new_future() {
    future_t *f = calloc(1, sizeof(future_t));
    uv_mutex_init(&f->lock);
    uv_cond_init(&f->cond);
    return f;
}

static void destroy_future(future_t *f) {
    uv_mutex_destroy(&f->lock);
    uv_cond_destroy(&f->cond);
    free(f);
}

static int await_future(future_t *f) {
    uv_mutex_lock(&f->lock);
    while (!f->completed) {
        uv_cond_wait(&f->cond, &f->lock);
    }
    int err = f->err;
    uv_mutex_unlock(&f->lock);
    return err;
}

static int complete_future(future_t *f, void *result) {
    int rc = UV_EINVAL;
    uv_mutex_lock(&f->lock);
    if (!f->completed) {
        f->completed = true;
        f->result = result;
        uv_cond_broadcast(&f->cond);
        rc = 0;
    }
    uv_mutex_unlock(&f->lock);
    return rc;
}

static int fail_future(future_t *f, int err) {
    int rc = UV_EINVAL;
    uv_mutex_lock(&f->lock);
    if (!f->completed) {
        f->completed = true;
        f->err = err;
        uv_cond_broadcast(&f->cond);
        rc = 0;
    }
    uv_mutex_unlock(&f->lock);
    return rc;
}

typedef void (*loop_work_cb)(void *arg, future_t *f, uv_loop_t *l);

typedef struct queue_elem_s {
    loop_work_cb cb;
    void *arg;
    future_t *f;
    LIST_ENTRY(queue_elem_s) _next;
} queue_elem_t;

static void internal_init();

static future_t *schedule_on_loop(loop_work_cb cb, void *arg, bool wait);

static void do_shutdown(void *args, future_t *f, uv_loop_t *l);

static uv_once_t init;
static uv_loop_t *lib_loop;
static uv_thread_t lib_thread;
static uv_key_t err_key;
static uv_mutex_t q_mut;
static uv_async_t q_async;
static LIST_HEAD(loop_queue, queue_elem_s) loop_q;

#if _WIN32

// define sockaddr_un if missing under MINGW
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
struct sockaddr_un {
     ADDRESS_FAMILY sun_family;
     char sun_path[UNIX_PATH_MAX];
};
#endif
#endif

typedef struct ztx_wrap {
    ziti_options opts;
    ziti_context ztx;
    TAILQ_HEAD(futures, future_s) futures;

    future_t *services_loaded;
    model_map intercepts;
} ztx_wrap_t;

struct backlog_entry_s {
    struct ziti_sock_s *parent;
    ziti_connection conn;
    char *caller_id;
    future_t *accept_f;
    TAILQ_ENTRY(backlog_entry_s) _next;
};

typedef struct ziti_sock_s {
    ziti_socket_t fd;
    ziti_socket_t ziti_fd;
    future_t *f;
    ziti_context ztx;
    ziti_connection conn;

    char *service;
    bool server;
    int pending;
    int max_pending;
    TAILQ_HEAD(, backlog_entry_s) backlog;
    TAILQ_HEAD(, future_s) accept_q;

} ziti_sock_t;

static model_map ziti_contexts;

static model_map ziti_sockets;

void Ziti_lib_init(void) {
    uv_once(&init, internal_init);
}

ZITI_FUNC
uv_thread_t Ziti_lib_thread() {
    return lib_thread;
}

int Ziti_last_error() {
    intptr_t p = (intptr_t) uv_key_get(&err_key);
    return (int)p;
}

static void set_error(int err) {
    uv_key_set(&err_key, (void *) (intptr_t) err);
}

static void on_ctx_event(ziti_context ztx, const ziti_event_t *ev) {
    ztx_wrap_t *wrap = ziti_app_ctx(ztx);
    if (ev->type == ZitiContextEvent) {
        int err = ev->event.ctx.ctrl_status;
        if (err == ZITI_OK) {
            wrap->ztx = ztx;
            future_t *f;
            while (!TAILQ_EMPTY(&wrap->futures)) {
                f = TAILQ_FIRST(&wrap->futures);
                TAILQ_REMOVE(&wrap->futures, f, _next);
                complete_future(f, ztx);
            }
        } else if (err == ZITI_PARTIALLY_AUTHENTICATED) {
            return;
        } else {
            future_t *f;
            while (!TAILQ_EMPTY(&wrap->futures)) {
                f = TAILQ_FIRST(&wrap->futures);
                TAILQ_REMOVE(&wrap->futures, f, _next);
                fail_future(f, err);
            }
            if (err == ZITI_DISABLED) {
                destroy_future(wrap->services_loaded);
                free(wrap);
            }
        }
    } else if (ev->type == ZitiServiceEvent) {

        for (int i = 0; ev->event.service.removed && ev->event.service.removed[i] != NULL; i++) {
            ziti_intercept_cfg_v1 *intercept = model_map_remove(&wrap->intercepts, ev->event.service.removed[i]->name);
            free_ziti_intercept_cfg_v1(intercept);
            FREE(intercept);
        }

        for (int i = 0; ev->event.service.changed && ev->event.service.changed[i] != NULL; i++) {
            ziti_service *s = ev->event.service.changed[i];
            ziti_intercept_cfg_v1 *intercept = alloc_ziti_intercept_cfg_v1();

            if (ziti_service_get_config(s, ZITI_INTERCEPT_CFG_V1, intercept, parse_ziti_intercept_cfg_v1) == ZITI_OK) {
                intercept = model_map_set(&wrap->intercepts, s->name, intercept);
            }

            free_ziti_intercept_cfg_v1(intercept);
            FREE(intercept);
        }

        for (int i = 0; ev->event.service.added && ev->event.service.added[i] != NULL; i++) {
            ziti_service *s = ev->event.service.added[i];
            ziti_intercept_cfg_v1 *intercept = alloc_ziti_intercept_cfg_v1();
            ziti_client_cfg_v1 clt_cfg = {0};

            if (ziti_service_get_config(s, ZITI_INTERCEPT_CFG_V1, intercept, parse_ziti_intercept_cfg_v1) == ZITI_OK) {
                intercept = model_map_set(&wrap->intercepts, s->name, intercept);
            } else if (ziti_service_get_config(s, ZITI_CLIENT_CFG_V1, &clt_cfg, parse_ziti_client_cfg_v1) == ZITI_OK) {
                ziti_intercept_from_client_cfg(intercept, &clt_cfg);
                intercept = model_map_set(&wrap->intercepts, s->name, intercept);
                free_ziti_client_cfg_v1(&clt_cfg);
            }

            free_ziti_intercept_cfg_v1(intercept);
            FREE(intercept);
        }

        if (!wrap->services_loaded->completed) {
            complete_future(wrap->services_loaded, NULL);
        }
    }
}

static void load_ziti_ctx(void *arg, future_t *f, uv_loop_t *l) {
    int rc = 0;
    struct ztx_wrap *wrap = model_map_get(&ziti_contexts, arg);
    if (wrap == NULL) {
        wrap = calloc(1, sizeof(struct ztx_wrap));
        wrap->opts.app_ctx = wrap;
        wrap->opts.config = arg;
        wrap->opts.event_cb = on_ctx_event;
        wrap->opts.events = ZitiContextEvent | ZitiServiceEvent;
        wrap->opts.refresh_interval = 60;
        wrap->opts.config_types = configs;
        wrap->services_loaded = new_future();
        TAILQ_INIT(&wrap->futures);

        rc = ziti_init_opts(&wrap->opts, l);
        if (rc != ZITI_OK) {
            fail_future(f, rc);
            ZITI_LOG(WARN, "identity file[%s] not found", (const char *) arg);
            free(wrap);
            return;
        }
        model_map_set(&ziti_contexts, arg, wrap);
        TAILQ_INSERT_TAIL(&wrap->futures, f, _next);
    } else if (wrap->ztx) {
        complete_future(f, wrap->ztx);
    } else {
        TAILQ_INSERT_TAIL(&wrap->futures, f, _next);
    }
}

ziti_context Ziti_load_context(const char *identity) {
    future_t *f = schedule_on_loop(load_ziti_ctx, (void *) identity, true);
    int err = await_future(f);
    set_error(err);
    ziti_context ztx = (ziti_context) f->result;
    if (err == 0) {
        ztx_wrap_t *wrap = ziti_app_ctx(ztx);
        await_future(wrap->services_loaded);
    }
    destroy_future(f);
    return ztx;
}

#if _WIN32
static const char * fmt_win32err(int err) {
    static char wszMsgBuff[512];  // Buffer for text.

    // Try to get the message from the system errors.
    FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   WSAGetLastError(),
                   0,
                   wszMsgBuff,
                   512,
                   NULL );
    return wszMsgBuff;
}
#endif

#ifdef __MINGW32__
static const IN_ADDR in4addr_loopback;
static void init_in4addr_loopback() {
    IN_ADDR *lo = (IN_ADDR *)&in4addr_loopback;
    lo->S_un.S_addr = htonl(INADDR_LOOPBACK);
}
#else
#define init_in4addr_loopback() {}
#endif

static int make_socketpair(int type, ziti_socket_t *fd0, ziti_socket_t *fd1) {
    int rc = 0;
#if _WIN32
    ziti_socket_t
            lsock = SOCKET_ERROR, // listener
            ssock = SOCKET_ERROR, // server side
            csock = SOCKET_ERROR; // client side

    PREPF(WSOCK, fmt_win32err);

    u_long nonblocking = 1;
    TRY(WSOCK, (lsock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR);
    ioctlsocket(lsock, FIONBIO, &nonblocking);

    struct sockaddr_in laddr;
    int laddrlen = sizeof(laddr);
    laddr.sin_port = 0;
    laddr.sin_family = AF_INET;
    laddr.sin_addr = in4addr_loopback;

    TRY(WSOCK, bind(lsock, (const struct sockaddr *) &laddr, laddrlen));
    TRY(WSOCK, getsockname(lsock, (struct sockaddr *) &laddr, &laddrlen));
    TRY(WSOCK, listen(lsock, 1));
    TRY(WSOCK, (csock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR);

    ioctlsocket(csock, FIONBIO, &nonblocking);

    // this should return an error(WSAEWOULDBLOCK)
    connect(csock, (const struct sockaddr *) &laddr, laddrlen);
    TRY(WSOCK, WSAGetLastError() != WSAEWOULDBLOCK);

    fd_set fds = {0};
    FD_SET(lsock, &fds);
    const struct timeval timeout = {
            .tv_sec = 1,
    };
    TRY(WSOCK, select(0, &fds, NULL, NULL, &timeout) != 1);
    TRY(WSOCK, !FD_ISSET(lsock, &fds));
    TRY(WSOCK, (ssock = accept(lsock, NULL, NULL)) == SOCKET_ERROR);

    nonblocking = 0;
    ioctlsocket(csock, FIONBIO, &nonblocking);

    CATCH(WSOCK) {
        rc  = WSAGetLastError();
        if (csock != SOCKET_ERROR) closesocket(csock);
        if (ssock != SOCKET_ERROR) closesocket(ssock);
    }

    if (lsock != SOCKET_ERROR) closesocket(lsock);
    *fd0 = csock;
    *fd1 = ssock;
#else
    int fds[2] = {-1, -1};
    rc = socketpair(AF_UNIX, type, 0, fds);
    *fd0 = fds[0];
    *fd1 = fds[1];
#endif
    return rc;
}

static void new_ziti_socket(void *arg, future_t *f, uv_loop_t *l) {
    int socktype = (int)(uintptr_t)arg;

    ziti_socket_t fd0, fd1;
    int rc = make_socketpair(socktype, &fd0, &fd1);
    if (rc == 0) {
        NEWP(zs, ziti_sock_t);
        zs->fd = fd0;
        zs->ziti_fd = fd1;
        model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);
        complete_future(f, zs);
    } else {
        ZITI_LOG(WARN, "failed to create socketpair(%x)! %d/%s", socktype, errno, strerror(errno));
        fail_future(f, errno);
    }
}

ziti_socket_t Ziti_socket(int type) {
    ziti_socket_t fd = -1;
    future_t *f = schedule_on_loop(new_ziti_socket, (void*)(uintptr_t)type, true);
    int err = await_future(f);
    set_error(err);
    if (err == 0) {
        ziti_sock_t *zs = f->result;
        fd = zs->fd;
    }
    destroy_future(f);
    return fd;
}

struct conn_req_s {
    ziti_socket_t fd;

    ziti_context ztx;
    const char *service;
    const char *terminator;

    const char *host;
    uint16_t port;
};

static void on_bridge_close(void *ctx) {
    ziti_sock_t *zs = ctx;
    model_map_removel(&ziti_sockets, zs->fd);
#if _WIN32
    closesocket(zs->ziti_fd);
#else
    close(zs->ziti_fd);
#endif
    free(zs->service);
    free(zs);
}

static void on_ziti_connect(ziti_connection conn, int status) {
    ziti_sock_t *zs = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        ZITI_LOG(DEBUG, "bridge connected to ziti service[%s]", zs->service);
        ziti_conn_bridge_fds(conn, (uv_os_fd_t) zs->ziti_fd, (uv_os_fd_t) zs->ziti_fd, on_bridge_close, zs);
        complete_future(zs->f, conn);
    } else {
        ZITI_LOG(WARN, "failed to establish ziti connection: %d(%s)", status, ziti_errorstr(status));
        fail_future(zs->f, status);
        ziti_close(zs->conn, NULL);
        on_bridge_close(zs);
    }
}

static const char* find_service(ztx_wrap_t *wrap, int type, const char *host, uint16_t port) {
    const char *service;
    ziti_intercept_cfg_v1 *intercept;

    const char* proto;
    switch (type) {
        case SOCK_STREAM:
            proto = "tcp";
            break;
        case SOCK_DGRAM:
            proto = "udp";
            break;
        default:
            return NULL;
    }

    int i;
    MODEL_MAP_FOREACH(service, intercept, &wrap->intercepts) {
        bool proto_match = false;
        bool port_match = false;
        bool host_match = false;
        for (i = 0; !proto_match && intercept->protocols[i] != NULL; i++) {
            proto_match = strcasecmp(proto, intercept->protocols[i]) == 0;
        }
        if (!proto_match) continue;

        for (i = 0; !port_match && intercept->port_ranges[i] != NULL; i++) {
            ziti_port_range *range = intercept->port_ranges[i];
            port_match = range->low <= port && port <= range->high;
        }
        if (!port_match) continue;

        host_match = ziti_address_match_array(host, intercept->addresses);

        if (host_match)
            return service;
    }
    return NULL;
}

static void do_ziti_connect(struct conn_req_s *req, future_t *f, uv_loop_t *l) {
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));
    if (zs == NULL) {
        ZITI_LOG(WARN, "socket %lu not found", (unsigned long)req->fd);
        fail_future(f, EBADF);
    } else if (zs->f != NULL) {
        fail_future(f, EALREADY);
    } else {
        zs->f = f;

        int proto = 0;
        socklen_t optlen = sizeof(proto);
        if (getsockopt(req->fd, SOL_SOCKET, SO_TYPE, &proto, &optlen)) {
            ZITI_LOG(WARN, "unknown socket type fd[%d]: %d(%s)", req->fd, errno, strerror(errno));
        }

        if (req->ztx == NULL) {
            MODEL_MAP_FOR(it, ziti_contexts) {
                ztx_wrap_t *wrap = model_map_it_value(it);
                const char *service_name = find_service(wrap, proto, req->host, req->port);

                if (service_name != NULL) {
                    req->ztx = wrap->ztx;
                    req->service = service_name;
                    break;
                }
            }
        }

        const char *proto_str = proto == SOCK_DGRAM ? "udp" : "tcp";
        if (req->ztx != NULL) {
            zs->service = strdup(req->service);
            ziti_conn_init(req->ztx, &zs->conn, zs);
            char app_data[1024];
            size_t len = snprintf(app_data, sizeof(app_data),
                                  "{\"dst_protocol\": \"%s\", \"dst_hostname\": \"%s\", \"dst_port\": \"%u\"}",
                                  proto_str, req->host, req->port);
            ziti_dial_opts opts = {
                    .app_data = app_data,
                    .app_data_sz = len,
                    .identity = req->terminator,
            };
            ziti_dial_with_options(zs->conn, req->service, &opts, on_ziti_connect, NULL);
        } else {
            ZITI_LOG(WARN, "no service for target address[%s:%s:%d]", proto_str, req->host, req->port);
            fail_future(f, ECONNREFUSED);
        }
    }
}

int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port) {
    if (host == NULL) return -EINVAL;
    if (port == 0 || port > UINT16_MAX) return -EINVAL;

    struct conn_req_s req = {
            .fd = socket,
            .host = host,
            .port = port,
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);
    int err = await_future(f);
    set_error(err);
    destroy_future(f);
    return err ? -1 : 0;
}

int Ziti_connect(ziti_socket_t socket, ziti_context ztx, const char *service, const char *terminator) {

    if (ztx == NULL) return EINVAL;
    if (service == NULL) return EINVAL;

    struct conn_req_s req = {
            .fd = socket,
            .ztx = ztx,
            .service = service,
            .terminator = terminator,
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);
    int err = await_future(f);
    set_error(err);
    destroy_future(f);
    return err ? -1 : 0;
}

static bool is_blocking(ziti_socket_t s) {
#if _WIN32
    /*
     * Win32 does not have a method of testing if socket was put into non-blocking state.
     */
    DWORD timeout;
    DWORD fast_check = 1;
    int tolen = sizeof(timeout);
    getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, &tolen);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &fast_check, sizeof(fast_check));
    char b;
    int r = recv(s, &b, 0, 0);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(fast_check));

    if (r == 0)
        return true;
    else if (r == -1) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return false;
        if (err == WSAETIMEDOUT) return true;
    }
    return true;
#else
    int flags = fcntl(s, F_GETFL, 0);
    return (flags & O_NONBLOCK) == 0;
#endif
}

struct sock_info_s {
    ziti_socket_t fd;
    char *peer;
};

static void on_ziti_accept(ziti_connection client, int status) {
    struct backlog_entry_s *pending = ziti_conn_data(client);
    if (status != ZITI_OK) {
        ZITI_LOG(WARN, "ziti_accept failed!");
        // ziti accept failed, so just put the accept future back into accept_q
        TAILQ_INSERT_HEAD(&pending->parent->accept_q, pending->accept_f, _next);

        ziti_close(client, NULL);
        free(pending->caller_id);
        free(pending);
        return;
    }

    ziti_socket_t fd, ziti_fd;
    int rc = make_socketpair(SOCK_STREAM, &fd, &ziti_fd);
    if (rc != 0) {
        fail_future(pending->accept_f, rc);
        ziti_close(client, NULL);
        free(pending->caller_id);
        free(pending);
        return;
    }

    NEWP(zs, ziti_sock_t);
    zs->fd = fd;
    zs->ziti_fd = ziti_fd;
    ziti_conn_set_data(client, zs);
    model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);
    ziti_conn_bridge_fds(client, (uv_os_fd_t) zs->ziti_fd, (uv_os_fd_t) zs->ziti_fd, on_bridge_close, zs);
    NEWP(si, struct sock_info_s);
    si->fd = zs->fd;
    si->peer = pending->caller_id;

    complete_future(pending->accept_f, si);
    free(pending);
}

static void on_ziti_client(ziti_connection server, ziti_connection client, int status, ziti_client_ctx *clt_ctx) {
    ziti_sock_t *server_sock = ziti_conn_data(server);
    ZITI_LOG(DEBUG, "incoming client[%s] for service[%s]", clt_ctx->caller_id, server_sock->service);

    if (status != ZITI_OK) {
        on_bridge_close(server_sock);
        return;
    }

    char notify = 1;

    NEWP(pending, struct backlog_entry_s);
    pending->parent = server_sock;
    pending->conn = client;
    pending->caller_id = strdup(clt_ctx->caller_id);

    if (!TAILQ_EMPTY(&server_sock->accept_q)) {
        future_t *accept_f = TAILQ_FIRST(&server_sock->accept_q);

        ziti_conn_set_data(client, pending);
        // this should not happen but check anyway
        if (ziti_accept(client, on_ziti_accept, NULL) != ZITI_OK) {
            ZITI_LOG(WARN, "ziti_accept() failed unexpectedly");
            ziti_close(client, NULL);
            free(pending->caller_id);
            free(pending);
            return;
        }
        pending->accept_f = accept_f;
        TAILQ_REMOVE(&server_sock->accept_q, accept_f, _next);
        write(server_sock->ziti_fd, &notify, sizeof(notify));
        return;
    }

    if (server_sock->pending < server_sock->max_pending) {
        TAILQ_INSERT_TAIL(&server_sock->backlog, pending, _next);
        server_sock->pending++;
#if _WIN32
            send(server_sock->ziti_fd, &notify, sizeof(notify), 0);
#else
        write(server_sock->ziti_fd, &notify, sizeof(notify));
#endif
    } else {
        ZITI_LOG(DEBUG, "accept backlog is full, client[%s] rejected", clt_ctx->caller_id);
        ziti_close(client, NULL);
    }
}

static void on_ziti_bind(ziti_connection server, int status) {
    ziti_sock_t *zs = ziti_conn_data(server);

    if (status != ZITI_OK) {
        ZITI_LOG(WARN, "failed to bind fd[%d] err[%d/%s]", zs->fd, status, ziti_errorstr(status));
        fail_future(zs->f, status);
    } else {
        ZITI_LOG(DEBUG, "successfully bound fd[%d]", zs->fd);
        complete_future(zs->f, server);
    }
}

static void do_ziti_bind(struct conn_req_s *req, future_t *f, uv_loop_t *l) {
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));

    if (zs == NULL) {
        ZITI_LOG(WARN, "socket %lu not found", (unsigned long)req->fd);
        fail_future(f, EBADF);
    } else if (zs->f != NULL) {
        fail_future(f, EALREADY);
    } else {
        if (req->ztx != NULL) {
            ZITI_LOG(DEBUG, "requesting bind fd[%d] to service[%s]", zs->fd, req->service);
            ziti_listen_opts opts = {
                    .identity = req->terminator,
                    .bind_using_edge_identity = (req->terminator == NULL),
            };
            zs->service = strdup(req->service);
            ziti_conn_init(req->ztx, &zs->conn, zs);
            ziti_listen_with_options(zs->conn, req->service, &opts, on_ziti_bind, on_ziti_client);
            zs->f = f;
        } else {
            ZITI_LOG(WARN, "service[%s] not found", req->service);
            fail_future(f, EINVAL);
        }
    }
}

int Ziti_bind(ziti_socket_t socket, ziti_context ztx, const char *service, const char *terminator) {

    if (ztx == NULL) { return EINVAL; }
    if (service == NULL) { return EINVAL; }

    struct conn_req_s req = {
            .fd = socket,
            .ztx = ztx,
            .service = service,
            .terminator = terminator,
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_bind, &req, true);
    int err = await_future(f);
    set_error(err);
    destroy_future(f);
    return err ? -1 : 0;
}

struct listen_req_s {
    ziti_socket_t fd;
    int backlog;
};

static void do_ziti_listen(void *arg, future_t *f, uv_loop_t *l) {
    struct listen_req_s *req = arg;
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));
    if (zs == NULL) {
        fail_future(f, EBADF);
    } else {
        if (!zs->server) {
            TAILQ_INIT(&zs->accept_q);
            TAILQ_INIT(&zs->backlog);
            zs->server = true;
        }
        zs->max_pending = req->backlog;
        complete_future(f, NULL);
    }
}

int Ziti_listen(ziti_socket_t socket, int backlog) {
    if (backlog <= 0) {
        return EINVAL;
    }

    struct listen_req_s req = {.fd = socket, .backlog = backlog};
    future_t *f = schedule_on_loop(do_ziti_listen, &req, true);

    int err = await_future(f);
    set_error(err);
    destroy_future(f);
    return err ? -1 : 0;
}

static void do_ziti_accept(void *r, future_t *f, uv_loop_t *l) {
    ziti_socket_t server_fd = (ziti_socket_t) (uintptr_t) r;
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &server_fd, sizeof(server_fd));
    if (zs == NULL) {
        fail_future(f, -EINVAL);
        return;
    }

    if (!zs->server) {
        fail_future(f, -EBADF);
        return;
    }

    // no pending connections
    if (TAILQ_EMPTY(&zs->backlog)) {
        if (is_blocking(server_fd)) {
            TAILQ_INSERT_TAIL(&zs->accept_q, f, _next);
        } else {
            fail_future(f, -EWOULDBLOCK);
        }
        return;
    }

    while (!TAILQ_EMPTY(&zs->backlog)) {
        struct backlog_entry_s *pending = TAILQ_FIRST(&zs->backlog);
        ZITI_LOG(DEBUG, "pending connection[%s] for service[%s]", pending->caller_id, zs->service);
        TAILQ_REMOVE(&zs->backlog, pending, _next);

        ziti_connection conn = pending->conn;
        pending->accept_f = f;
        ziti_conn_set_data(conn, pending);
        int rc = ziti_accept(conn, on_ziti_accept, NULL);

        if (rc == ZITI_OK) {
            break;
        }

        ZITI_LOG(DEBUG, "failed to accept: client gone? [%d/%s]", rc, ziti_errorstr(rc));
        ziti_close(conn, NULL);
        free(pending->caller_id);
        free(pending);
    }
}

ziti_socket_t Ziti_accept(ziti_socket_t server, char *caller, int caller_len) {
    future_t *f = schedule_on_loop(do_ziti_accept, (void *) (uintptr_t) server, true);

    ziti_socket_t clt = -1;
    int err = await_future(f);
    if (!err) {
        struct sock_info_s *si = f->result;
        clt = si->fd;
        if (caller != NULL) {
            strncpy(caller, si->peer, caller_len);
        }
        free(si->peer);
        free(si);
        char b;
#if _WIN32
        recv(server, &b, 1, 0);
#else
        read(server, &b, 1);
#endif
    }
    set_error(err);
    destroy_future(f);
    return clt;
}


void Ziti_lib_shutdown(void) {
    future_t *f = schedule_on_loop(do_shutdown, NULL, true);
    uv_thread_join(&lib_thread);
    uv_key_delete(&err_key);
    destroy_future(f);
}

static void looper(void *arg) {
    uv_run(arg, UV_RUN_DEFAULT);
}

future_t *schedule_on_loop(loop_work_cb cb, void *arg, bool wait) {
    queue_elem_t *el = calloc(1, sizeof(queue_elem_t));
    el->cb = cb;
    el->arg = arg;
    if (wait) {
        el->f = new_future();
    }

    uv_mutex_lock(&q_mut);
    LIST_INSERT_HEAD(&loop_q, el, _next);
    uv_mutex_unlock(&q_mut);
    uv_async_send(&q_async);

    return el->f;
}

void process_on_loop(uv_async_t *async) {
    LIST_HEAD(loop_queue, queue_elem_s) q = {0};

    // drain q
    uv_mutex_lock(&q_mut);
    while (!LIST_EMPTY(&loop_q)) {
        queue_elem_t *el = LIST_FIRST(&loop_q);
        LIST_REMOVE(el, _next);
        LIST_INSERT_HEAD(&q, el, _next);
    }
    uv_mutex_unlock(&q_mut);

    while (!LIST_EMPTY(&q)) {
        queue_elem_t *el = LIST_FIRST(&q);
        LIST_REMOVE(el, _next);
        el->cb(el->arg, el->f, async->loop);
        free(el);
    }
}

static void internal_init() {
    init_in4addr_loopback();
    uv_key_create(&err_key);
    uv_mutex_init(&q_mut);
    lib_loop = uv_loop_new();
    uv_async_init(lib_loop, &q_async, process_on_loop);
    uv_thread_create(&lib_thread, looper, lib_loop);
}

void do_shutdown(void *args, future_t *f, uv_loop_t *l) {
    model_map_iter *it = model_map_iterator(&ziti_contexts);
    while (it) {
        ztx_wrap_t *w = model_map_it_value(it);
        it = model_map_it_remove(it);
        ziti_shutdown(w->ztx);
        model_map_clear(&w->intercepts, (void (*)(void *)) free_ziti_intercept_cfg_v1);
    }
    uv_close((uv_handle_t *) &q_async, NULL);
    uv_loop_close(l);
}

static void on_enroll(const ziti_config *cfg, int status, const char *error, void *ctx) {
    future_t *f = ctx;
    if (status != ZITI_OK) {
        fail_future(f, status);
    } else {
        char *cfg_json = ziti_config_to_json(cfg, 0, NULL);
        complete_future(f, cfg_json);
    }
}

static void do_enroll(ziti_enroll_opts *opts, future_t *f, uv_loop_t *loop) {
    ziti_enroll(opts, loop, on_enroll, f);
}

int Ziti_enroll_identity(const char *jwt, const char *key, const char *cert, char **id_json, unsigned long *id_json_len) {
    ziti_enroll_opts opts = {
            .jwt_content = jwt,
            .enroll_key = key,
            .enroll_cert = cert,
    };
    future_t *f = schedule_on_loop((loop_work_cb) do_enroll, &opts, true);
    int rc = await_future(f);
    if (rc == ZITI_OK) {
        *id_json = f->result;
        *id_json_len = strlen(*id_json);
    }
    return rc;
}
