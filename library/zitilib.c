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
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;
#if !defined(__MINGW32__)
#pragma comment(lib, "ws2_32.lib")
#include <afunix.h>
#endif
#else
#include <unistd.h>
#define SOCKET_ERROR -1
#endif

#include <ziti/zitilib.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include "zt_internal.h"
#include "utils.h"

static bool is_blocking(ziti_socket_t s);

ZITI_FUNC
const char *Ziti_lookup(in_addr_t addr);

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
    int rc = uv_mutex_init(&f->lock);
    if (rc != 0) {
        fprintf(stderr, "failed to init lock %d/%s\n", rc, uv_strerror(rc));
    }
    rc = uv_cond_init(&f->cond);
    if (rc != 0) {
        fprintf(stderr, "failed to init cond %d/%s\n", rc, uv_strerror(rc));
    }
    return f;
}

static void destroy_future(future_t *f) {
    uv_mutex_destroy(&f->lock);
    uv_cond_destroy(&f->cond);
    free(f);
}

static int await_future(future_t *f) {
    if (f == NULL) {
        return 0;
    }

    uv_mutex_lock(&f->lock);
    while (!f->completed) {
        uv_cond_wait(&f->cond, &f->lock);
    }
    int err = f->err;
    uv_mutex_unlock(&f->lock);
    return err;
}

static int complete_future(future_t *f, void *result) {
    if (f == NULL) return 0;

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
    if (f == NULL) return 0;

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

static future_t *child_init_future;


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

            if (ziti_service_get_config(s, ZITI_INTERCEPT_CFG_V1, intercept, (parse_service_cfg_f) parse_ziti_intercept_cfg_v1) == ZITI_OK) {
                intercept = model_map_set(&wrap->intercepts, s->name, intercept);
            }

            free_ziti_intercept_cfg_v1(intercept);
            FREE(intercept);
        }

        for (int i = 0; ev->event.service.added && ev->event.service.added[i] != NULL; i++) {
            ziti_service *s = ev->event.service.added[i];
            ziti_intercept_cfg_v1 *intercept = alloc_ziti_intercept_cfg_v1();
            ziti_client_cfg_v1 clt_cfg = {0};

            if (ziti_service_get_config(s, ZITI_INTERCEPT_CFG_V1, intercept, (parse_service_cfg_f) parse_ziti_intercept_cfg_v1) == ZITI_OK) {
                intercept = model_map_set(&wrap->intercepts, s->name, intercept);
            } else if (ziti_service_get_config(s, ZITI_CLIENT_CFG_V1, &clt_cfg, (parse_service_cfg_f) parse_ziti_client_cfg_v1) == ZITI_OK) {
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


    if (wrap) {
        if (wrap->ztx) {
            complete_future(f, wrap->ztx);
            return;
        }

        if (f) {
            TAILQ_INSERT_TAIL(&wrap->futures, f, _next);
        }
        return;
    }

    ZITI_LOG(DEBUG, "loading identity from %s", (char *) arg);
    wrap = calloc(1, sizeof(struct ztx_wrap));
    wrap->opts.app_ctx = wrap;
    wrap->opts.config = strdup(arg);
    wrap->opts.event_cb = on_ctx_event;
    wrap->opts.events = ZitiContextEvent | ZitiServiceEvent;
    wrap->opts.refresh_interval = 60;
    wrap->opts.config_types = configs;
    wrap->services_loaded = new_future();
    TAILQ_INIT(&wrap->futures);
    if (f) {
        TAILQ_INSERT_TAIL(&wrap->futures, f, _next);
    }

    rc = ziti_init_opts(&wrap->opts, l);
    if (rc != ZITI_OK) {
        fail_future(f, rc);
        ZITI_LOG(WARN, "identity file[%s] not found", (const char *) arg);
        free(wrap);
        return;
    }
    model_map_set(&ziti_contexts, arg, wrap);

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
static const char* errno_str(int err) {
    return strerror(errno);
}
/**
 * create bridge socket and connect client socket to it
 * @param clt_sock client socket
 * @param ziti_sock[out] bridge socket
 * @return
 */
static int connect_socket(ziti_socket_t clt_sock, ziti_socket_t *ziti_sock) {
    int rc;
#if _WIN32
    ziti_socket_t
            lsock = SOCKET_ERROR, // listener
            ssock = SOCKET_ERROR; // server side

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

    ioctlsocket(clt_sock, FIONBIO, &nonblocking);

    // this should return an error(WSAEWOULDBLOCK)
    rc = connect(clt_sock, (const struct sockaddr *) &laddr, laddrlen);
    TRY(WSOCK, WSAGetLastError() != WSAEWOULDBLOCK);
    rc = 0;

    fd_set fds = {0};
    FD_SET(lsock, &fds);
    const struct timeval timeout = {
            .tv_sec = 1,
    };
    TRY(WSOCK, select(0, &fds, NULL, NULL, &timeout) != 1);
    TRY(WSOCK, !FD_ISSET(lsock, &fds));
    TRY(WSOCK, (ssock = accept(lsock, NULL, NULL)) == SOCKET_ERROR);

    nonblocking = 0;
    ioctlsocket(clt_sock, FIONBIO, &nonblocking);

    CATCH(WSOCK) {
        rc  = WSAGetLastError();
        if (ssock != SOCKET_ERROR) closesocket(ssock);
    }

    if (lsock != SOCKET_ERROR) closesocket(lsock);

    *ziti_sock = ssock;
#else

#if defined(SOCKET_PAIR_ALT)
    ziti_socket_t
            lsock = SOCKET_ERROR, // listener
            ssock = SOCKET_ERROR; // server side

    PREPF(WSOCK, strerror);

    int clt_flags = fcntl(clt_sock, F_GETFL, NULL);
    TRY(WSOCK, fcntl(clt_sock, F_SETFL, clt_flags | O_NONBLOCK));

    TRY(WSOCK, (lsock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR);

    struct sockaddr_in laddr;
    int laddrlen = sizeof(laddr);
    laddr.sin_port = 0;
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    TRY(WSOCK, bind(lsock, (const struct sockaddr *) &laddr, laddrlen));
    TRY(WSOCK, getsockname(lsock, (struct sockaddr *) &laddr, &laddrlen));
    TRY(WSOCK, listen(lsock, 1));

    // this should return an error(WSAEWOULDBLOCK)
    rc = connect(clt_sock, (const struct sockaddr *) &laddr, laddrlen);
    TRY(WSOCK, errno != EWOULDBLOCK);
    rc = 0;

    fd_set fds = {0};
    FD_SET(lsock, &fds);
    const struct timeval timeout = {
            .tv_sec = 1,
    };
    TRY(WSOCK, select(0, &fds, NULL, NULL, &timeout) != 1);
    TRY(WSOCK, !FD_ISSET(lsock, &fds));
    TRY(WSOCK, (ssock = accept(lsock, NULL, NULL)) == SOCKET_ERROR);

    TRY(WSOCK, fcntl(clt_sock, F_SETFL, clt_flags));

    CATCH(WSOCK) {
        rc  = errno;
        if (ssock != SOCKET_ERROR) close(ssock);
    }

    if (lsock != SOCKET_ERROR) close(lsock);

    *ziti_sock = ssock;
    return rc;
#endif

    ZITI_LOG(VERBOSE, "connecting client socket[%d]", clt_sock);
    int fds[2] = {-1, -1};
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (rc) {
        ZITI_LOG(WARN, "socketpair failed[%d/%s]", errno, strerror(errno));
        return errno;
    }

    rc = dup2(fds[0], clt_sock);
    if (rc == -1) {
        ZITI_LOG(WARN, "dup2 failed[%d/%s]", errno, strerror(errno));
        close(fds[0]);
        close(fds[1]);
        return errno;
    }
    close(fds[0]);

    *ziti_sock = fds[1];
    ZITI_LOG(VERBOSE, "connected client socket[%d] <-> ziti_fd[%d]", clt_sock, *ziti_sock);
#endif
    return 0;
}

// make sure old ziti_sock_t instance does not interfere with
// the new/re-used socket fd
static void check_socket(void *arg, future_t *f, uv_loop_t *l) {
    ziti_socket_t fd = (ziti_socket_t) (uintptr_t) arg;
    ZITI_LOG(VERBOSE, "checking client fd[%d]", fd);
    ziti_sock_t *s = model_map_remove_key(&ziti_sockets, &fd, sizeof(fd));
    if (s) {
        ZITI_LOG(VERBOSE, "stale ziti_sock_t[fd=%d]", fd);
        s->fd = SOCKET_ERROR;
    }
    complete_future(f, NULL);
}

ziti_socket_t Ziti_socket(int type) {
    ziti_socket_t fd = socket(AF_INET, type, 0);
    set_error(fd < 0 ? errno : 0);
    if (fd > 0) {
        future_t *f = schedule_on_loop(check_socket, (void *) (uintptr_t) fd, true);
        await_future(f);
    }
    return fd;
}

static void close_work(void *arg, future_t *f, uv_loop_t *l) {
    ziti_socket_t fd = (ziti_socket_t) (uintptr_t) arg;
    ZITI_LOG(DEBUG, "closing client fd[%d]", fd);
    ziti_sock_t *s = model_map_remove_key(&ziti_sockets, &fd, sizeof(fd));
    close(fd);
    complete_future(f, NULL);
}

void Ziti_close(ziti_socket_t fd) {
    future_t *f = schedule_on_loop(close_work, (void *) (uintptr_t) fd, true);
    await_future(f);
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
    ZITI_LOG(DEBUG, "closed conn for socket(%d)", zs->fd);
    model_map_remove_key(&ziti_sockets, &zs->fd, sizeof(zs->fd));
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
        int rc = connect_socket(zs->fd, &zs->ziti_fd);
        if (rc != 0) {
            ZITI_LOG(ERROR, "failed to connect client socket: %d/%s", rc, strerror(rc));
            fail_future(zs->f, rc);
            return;
        }

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
    ZITI_LOG(DEBUG, "looking up %d:%s:%d", type, host, port);
    const char *service;
    ziti_intercept_cfg_v1 *intercept;

    ziti_protocol proto = 0;
    switch (type) {
        case SOCK_STREAM:
            proto = ziti_protocols.tcp;
            break;
        case SOCK_DGRAM:
            proto = ziti_protocols.udp;
            break;
        case 0: // resolve case: any protocol can be used to assign IP address to host
            break;
        default:
            return NULL;
    }

    int score = -1;
    const char *best = NULL;
    MODEL_MAP_FOREACH(service, intercept, &wrap->intercepts) {
        int match = ziti_intercept_match(intercept, proto, host, port);
        if (match == -1) { continue; }

        if (match == 0) { return service; }

        if (score == -1 || score > match) {
            best = service;
            score = match;
        }
    }
    return best;
}

static void do_ziti_connect(struct conn_req_s *req, future_t *f, uv_loop_t *l) {
    ZITI_LOG(DEBUG, "connecting fd[%d] to %s:%d", req->fd, req->host, req->port);
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));
    if (zs != NULL) {
        ZITI_LOG(WARN, "socket %lu already connecting/connected", (unsigned long) req->fd);
        fail_future(f, EALREADY);
        return;
    }

    int proto = 0;
    socklen_t optlen = sizeof(proto);
    if (getsockopt(req->fd, SOL_SOCKET, SO_TYPE, &proto, &optlen)) {
        ZITI_LOG(WARN, "unknown socket type fd[%d]: %d(%s)", req->fd, errno, strerror(errno));
    }

    in_addr_t ip;
    const char *host = NULL;
    if (uv_inet_pton(AF_INET, req->host, &ip) == 0) { // try reverse lookup
        host = Ziti_lookup(ip);
    }
    if (host == NULL) {
        host = req->host;
    }

    if (req->ztx == NULL) {
        MODEL_MAP_FOR(it, ziti_contexts) {
            ztx_wrap_t *wrap = model_map_it_value(it);
            const char *service_name = find_service(wrap, proto, host, req->port);

            if (service_name != NULL) {
                req->ztx = wrap->ztx;
                req->service = service_name;
                break;
            }
        }
    }

    const char *proto_str = proto == SOCK_DGRAM ? "udp" : "tcp";
    if (req->ztx != NULL) {
        zs = calloc(1, sizeof(*zs));
        zs->fd = req->fd;
        zs->f = f;
        zs->service = strdup(req->service);

        model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);

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
        ZITI_LOG(DEBUG, "connecting fd[%d] to service[%s]", zs->fd, req->service);
        ziti_dial_with_options(zs->conn, req->service, &opts, on_ziti_connect, NULL);
    } else {
        ZITI_LOG(WARN, "no service for target address[%s:%s:%d]", proto_str, req->host, req->port);
        fail_future(f, ECONNREFUSED);
    }
}

int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port) {
    if (host == NULL) { return EINVAL; }
    if (port == 0 || port > UINT16_MAX) { return EINVAL; }

    await_future(child_init_future);

    const char *id;
    ztx_wrap_t *wrap;
    MODEL_MAP_FOREACH(id, wrap, &ziti_contexts) {
        await_future(wrap->services_loaded);
    }

    struct conn_req_s req = {
            .fd = socket,
            .host = host,
            .port = port,
    };


    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);

    int err = 0;
    if (f) {
        err = await_future(f);
        set_error(err);
        destroy_future(f);
    }
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
    fd = Ziti_socket(SOCK_STREAM);
    int rc = connect_socket(fd, &ziti_fd);
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

    if (status != ZITI_OK) {
        on_bridge_close(server_sock);
        return;
    }
    ZITI_LOG(DEBUG, "incoming client[%s] for service[%s] status[%s]", clt_ctx->caller_id, server_sock->service, ziti_errorstr(status));

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
        int r = write(server_sock->ziti_fd, &notify, sizeof(notify));
        ZITI_LOG(TRACE, "wrote result = %d", r);
#endif
    } else {
        ZITI_LOG(DEBUG, "accept backlog is full, client[%s] rejected", clt_ctx->caller_id);
        ziti_close(client, NULL);
    }
}

static void on_ziti_bind(ziti_connection server, int status) {
    ziti_sock_t *zs = ziti_conn_data(server);

    if (status != ZITI_OK) {
        ZITI_LOG(WARN, "failed to bind fd[%d] to service[%s] err[%d/%s]", zs->fd, zs->service, status, ziti_errorstr(status));
        fail_future(zs->f, status);
        free(zs->service);
        free(zs);
    } else {
        connect_socket(zs->fd, &zs->ziti_fd);
        model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);

        ZITI_LOG(DEBUG, "successfully bound fd[%d] to service[%s]", zs->fd, zs->service);
        complete_future(zs->f, server);
    }
}

static void do_ziti_bind(struct conn_req_s *req, future_t *f, uv_loop_t *l) {
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));
    if (zs) {
        fail_future(f, EALREADY);
        return;
    }

    if (req->ztx != NULL) {
        zs = calloc(1, sizeof(*zs));
        zs->fd = req->fd;
        zs->service = strdup(req->service);
        zs->f = f;

        ZITI_LOG(DEBUG, "requesting bind fd[%d] to service[%s@%s]", zs->fd, req->terminator ? req->terminator : "", req->service);
        ziti_listen_opts opts = {
                .identity = req->terminator,
        };
        ziti_conn_init(req->ztx, &zs->conn, zs);
        ziti_listen_with_options(zs->conn, req->service, &opts, on_ziti_bind, on_ziti_client);
    } else {
        ZITI_LOG(WARN, "service[%s] not found", req->service);
        fail_future(f, EINVAL);
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
        ZITI_LOG(DEBUG, "no pending connections");
        if (is_blocking(server_fd)) {
            TAILQ_INSERT_TAIL(&zs->accept_q, f, _next);
        } else {
            fail_future(f, EWOULDBLOCK);
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
    await_future(f);
    uv_thread_join(&lib_thread);
    uv_once_t child_once = UV_ONCE_INIT;
    memcpy(&init, &child_once, sizeof(child_once));
    uv_key_delete(&err_key);
    destroy_future(f);
}

static void looper(void *arg) {
    uv_loop_t *l = arg;
    ZITI_LOG(DEBUG, "loop is starting");
    uv_run(l, UV_RUN_DEFAULT);
    ZITI_LOG(DEBUG, "loop is done");
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

static void child_load_contexts(void *load_list, future_t *f, uv_loop_t *l) {
    model_list *load_ids = load_list;

    void *id;
    MODEL_LIST_FOREACH(id, *load_ids) {
        ZITI_LOG(INFO, "loading %s", (const char *) id);
        load_ziti_ctx(id, NULL, l);
    }

    complete_future(f, NULL);
}

static void child_init() {
    lib_loop = uv_loop_new();
    memset(&loop_q, 0, sizeof(loop_q));
    ziti_log_init(lib_loop, -1, NULL);
    uv_async_init(lib_loop, &q_async, process_on_loop);

    model_map_iter it = model_map_iterator(&ziti_contexts);
    model_list *idents = calloc(1, sizeof(*idents));
    while (it) {
        const char *ident = model_map_it_key(it);
        model_list_append(idents, strdup(ident));
        it = model_map_it_remove(it);
    }

    child_init_future = schedule_on_loop(child_load_contexts, idents, true);
    uv_thread_create(&lib_thread, looper, lib_loop);
}


static void internal_init() {
#if defined(PTHREAD_ONCE_INIT)
    pthread_atfork(NULL, NULL, child_init);
#endif
    init_in4addr_loopback();
    uv_key_create(&err_key);
    uv_mutex_init(&q_mut);
    lib_loop = uv_loop_new();
    ziti_log_init(lib_loop, -1, NULL);
    uv_async_init(lib_loop, &q_async, process_on_loop);
    uv_thread_create(&lib_thread, looper, lib_loop);
}

void do_shutdown(void *args, future_t *f, uv_loop_t *l) {
    model_map_iter *it = model_map_iterator(&ziti_contexts);
    while (it) {
        ztx_wrap_t *w = model_map_it_value(it);
        it = model_map_it_remove(it);
        if (w->ztx) {
            ziti_shutdown(w->ztx);
        }
        model_map_clear(&w->intercepts, (void (*)(void *)) free_ziti_intercept_cfg_v1_ptr);
    }
    complete_future(f, NULL);
    uv_close((uv_handle_t *) &q_async, NULL);

#if _WIN32
    uv_stop(q_async.loop);
#endif
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

static model_map host_to_ip;
static model_map ip_to_host;

static in_addr_t addr_counter = 0x64400000; // 100.64.0.0
static void resolve_cb(void *r, future_t *f) {
    struct conn_req_s *req = r;

    ZITI_LOG(DEBUG, "resolving %s", req->host);
    const char *service_name;
    MODEL_MAP_FOR(it, ziti_contexts) {
        ztx_wrap_t *wrap = model_map_it_value(it);
        service_name = find_service(wrap, 0, req->host, req->port);
        if (service_name) {
            ZITI_LOG(DEBUG, "%s:%d => %s", req->host, req->port, service_name);
            break;
        }
    }

    if (service_name == NULL) {
        fail_future(f, EAI_NONAME);
        return;
    }

    in_addr_t ip = (in_addr_t)(intptr_t)model_map_get(&host_to_ip, req->host);
    if (ip == 0) {
        ip = htonl(++addr_counter);
        ZITI_LOG(DEBUG, "assigned %s => %x", req->host, ip);
        model_map_set(&host_to_ip, req->host, (void *) (uintptr_t) ip);
        model_map_set_key(&ip_to_host, &ip, sizeof(ip), strdup(req->host));
    }

    complete_future(f, (void *) (uintptr_t) ip);
}

ZITI_FUNC
void Ziti_freeaddrinfo(struct addrinfo *addrlist) {
    uv_freeaddrinfo(addrlist);
}

ZITI_FUNC
int Ziti_resolve(const char *host, const char *port, const struct addrinfo *hints, struct addrinfo **addrlist) {
    in_port_t portnum = port ? (in_port_t) strtol(port, NULL, 10) : 0;
    ZITI_LOG(DEBUG, "host[%s] port[%s]", host, port);
    struct addrinfo *res = calloc(1, sizeof(struct addrinfo));
    if (hints) {
        res->ai_socktype = hints->ai_socktype;
        switch (hints->ai_socktype) {
            case SOCK_STREAM:
                res->ai_protocol = IPPROTO_TCP;
                break;
            case SOCK_DGRAM:
                res->ai_protocol = IPPROTO_UDP;
                break;
            case 0: // any type
                res->ai_protocol = 0;
                break;
            default: // no other protocols are supported
                return -1;
        }
    }

    struct sockaddr_in *addr4 = calloc(1, sizeof(struct sockaddr_in6));
    int rc = 0;
    if ((rc = uv_ip4_addr(host, portnum, addr4)) == 0) {
        ZITI_LOG(DEBUG, "host[%s] port[%s] rc = %d", host, port, rc);

        res->ai_family = AF_INET;
        res->ai_addr = (struct sockaddr *) addr4;
        res->ai_addrlen = sizeof(struct sockaddr_in);

        *addrlist = res;
        return 0;
    } else if (uv_ip6_addr(host, portnum, (struct sockaddr_in6 *) addr4) == 0) {
        ZITI_LOG(INFO, "host[%s] port[%s] rc = %d", host, port, rc);

        res->ai_family = AF_INET6;
        res->ai_addr = (struct sockaddr *) addr4;
        res->ai_addrlen = sizeof(struct sockaddr_in6);
        *addrlist = res;
        return 0;
    }

    // refuse resolving controller/router addresses here
    // this way Ziti context can operate even if resolve was high-jacked (e.g. zitify)
    MODEL_MAP_FOR(it, ziti_contexts) {
        ztx_wrap_t *wrap = model_map_it_value(it);
        const char *ctrl = wrap->ztx ? ziti_get_controller(wrap->ztx) : wrap->opts.controller;
        struct http_parser_url url;
        http_parser_url_init(&url);
        http_parser_parse_url(ctrl, strlen(ctrl), 0, &url);

        if (strncmp(host, ctrl + url.field_data[UF_HOST].off, url.field_data[UF_HOST].len) == 0) {
            return -1;
        }

        if (wrap->ztx) {
            MODEL_MAP_FOR(chit, wrap->ztx->channels) {
                ziti_channel_t *ch = model_map_it_value(chit);
                if (strcmp(ch->host, host) == 0) {
                    return -1;
                }
            }
        }
    }

    MODEL_MAP_FOR(it, ziti_contexts) {
        ztx_wrap_t *ztx = model_map_it_value(it);
        await_future(ztx->services_loaded);
    }

    struct conn_req_s req = {
            .host = host,
            .port = portnum,
    };

    future_t *f = schedule_on_loop((loop_work_cb) resolve_cb, &req, true);
    int err = await_future(f);
    if (err == 0) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(portnum);
        addr4->sin_addr.s_addr = (in_addr_t)(uintptr_t)f->result;

        res->ai_family = AF_INET;
        res->ai_addr = (struct sockaddr *) addr4;
        res->ai_socktype = hints->ai_socktype;

        res->ai_addrlen = sizeof(*addr4);
        *addrlist = res;
        return 0;
    } else {
        set_error(err);
        return -1;
    }
}

ZITI_FUNC
const char *Ziti_lookup(in_addr_t addr) {
    const char *hostname = model_map_get_key(&ip_to_host, &addr, sizeof(addr));
    return hostname;
}

ZITI_FUNC
void Ziti_free(void *o) {
    if (o) {
        free(o);
    }
}
