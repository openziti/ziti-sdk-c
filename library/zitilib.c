// Copyright (c) 2022-2023.  NetFoundry Inc.
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


#include <tlsuv/queue.h>

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
#define SOCKET_ERROR (-1)
#endif

#include <ziti/zitilib.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include "zt_internal.h"
#include "util/future.h"

static bool is_blocking(ziti_socket_t s);

ZITI_FUNC
const char *Ziti_lookup(in_addr_t addr);

static const char *configs[] = {
        ZITI_INTERCEPT_CFG_V1,
        ZITI_CLIENT_CFG_V1,
        NULL,
};


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
    // list[future_t]
    model_list futures;

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
    int max_pending;
    model_list backlog;
    model_list accept_q;

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
    future_t *f;
    if (ev->type == ZitiContextEvent) {
        int err = ev->ctx.ctrl_status;
        if (err == ZITI_OK) {
            wrap->ztx = ztx;
            model_list_iter it = model_list_iterator(&wrap->futures);
            while (it) {
                f = model_list_it_element(it);
                it = model_list_it_remove(it);
                complete_future(f, ztx);
            }
        } else if (err == ZITI_PARTIALLY_AUTHENTICATED) {
            return;
        } else {
            model_list_iter it = model_list_iterator(&wrap->futures);
            while (it) {
                f = model_list_it_element(it);
                it = model_list_it_remove(it);
                fail_future(f, err);
            }
            if (err == ZITI_DISABLED) {
                destroy_future(wrap->services_loaded);
                free(wrap);
            }
        }
    } else if (ev->type == ZitiServiceEvent) {

        for (int i = 0; ev->service.removed && ev->service.removed[i] != NULL; i++) {
            ziti_intercept_cfg_v1 *intercept = model_map_remove(&wrap->intercepts, ev->service.removed[i]->name);
            free_ziti_intercept_cfg_v1(intercept);
            FREE(intercept);
        }

        for (int i = 0; ev->service.changed && ev->service.changed[i] != NULL; i++) {
            ziti_service *s = ev->service.changed[i];
            ziti_intercept_cfg_v1 *intercept = alloc_ziti_intercept_cfg_v1();

            if (ziti_service_get_config(s, ZITI_INTERCEPT_CFG_V1, intercept, (parse_service_cfg_f) parse_ziti_intercept_cfg_v1) == ZITI_OK) {
                intercept = model_map_set(&wrap->intercepts, s->name, intercept);
            }

            free_ziti_intercept_cfg_v1(intercept);
            FREE(intercept);
        }

        for (int i = 0; ev->service.added && ev->service.added[i] != NULL; i++) {
            ziti_service *s = ev->service.added[i];
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

        complete_future(wrap->services_loaded, NULL);
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
            model_list_append(&wrap->futures, f);
        }
        return;
    }

    ZITI_LOG(DEBUG, "loading identity from %s", (char *) arg);
    ziti_config cfg = {0};
    ziti_context ztx = NULL;

    rc = ziti_load_config(&cfg, (const char*)arg);
    if (rc != ZITI_OK) goto error;

    rc = ziti_context_init(&ztx, &cfg);
    if (rc != ZITI_OK) goto error;

    wrap = calloc(1, sizeof(struct ztx_wrap));
    wrap->ztx = ztx;
    rc = ziti_context_set_options(ztx, &(ziti_options){
            .app_ctx = wrap,
            .event_cb = on_ctx_event,
            .events = ZitiContextEvent | ZitiServiceEvent,
            .refresh_interval = 60,
            .config_types = configs,
    });
    if (rc != ZITI_OK) goto error;

    wrap->services_loaded = new_future();
    if (f) {
        model_list_append(&wrap->futures, f);
    }
    rc = ziti_context_run(ztx, l);
    if (rc != ZITI_OK) goto error;

    model_map_set(&ziti_contexts, arg, wrap);

error:

    free_ziti_config(&cfg);

    if (rc != ZITI_OK) {
        fail_future(f, rc);
        ZITI_LOG(WARN, "fail to load identity file[%s]: %d/%s", (const char *) arg, rc, ziti_errorstr(rc));
        free(wrap);
        return;
    }

}

ziti_context Ziti_load_context(const char *identity) {
    future_t *f = schedule_on_loop(load_ziti_ctx, (void *) identity, true);
    ziti_context ztx;
    int err = await_future(f, (void **) &ztx);
    set_error(err);
    if (err == 0) {
        ztx_wrap_t *wrap = ziti_app_ctx(ztx);
        await_future(wrap->services_loaded, NULL);
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
#if defined(SO_NOSIGPIPE)
    int nosig = 1;
    setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, (void *)&nosig, sizeof(int));
#endif

    *ziti_sock = fds[1];
    ZITI_LOG(VERBOSE, "connected client socket[%d] <-> ziti_fd[%d]", clt_sock, *ziti_sock);
#endif
    return 0;
}

// make sure old ziti_sock_t instance does not interfere with
// the new/reused socket fd
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
        await_future(f, NULL);
        destroy_future(f);
    }
    return fd;
}

static void close_work(void *arg, future_t *f, uv_loop_t *l) {
    ziti_socket_t fd = (ziti_socket_t) (uintptr_t) arg;
    ZITI_LOG(DEBUG, "closing client fd[%d]", fd);
    ziti_sock_t *s = model_map_remove_key(&ziti_sockets, &fd, sizeof(fd));
#if _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    complete_future(f, NULL);
}

int Ziti_close(ziti_socket_t fd) {
    ziti_sock_t *s = model_map_get_key(&ziti_sockets, &fd, sizeof(fd));
    if (s) {
        ZITI_LOG(DEBUG, "closing ziti socket[%d]", fd);
        future_t *f = schedule_on_loop(close_work, (void *) (uintptr_t) fd, true);
        await_future(f, NULL);
        destroy_future(f);
        return 0;
    }
    return -1;
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

        ZITI_LOG(DEBUG, "bridge connected to ziti fd[%d]->ziti_fd[%d]->conn[%d]->service[%s]",
                 zs->fd, zs->ziti_fd, zs->conn->conn_id, zs->service);
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

    // check for service matching host
    ziti_service *s = model_map_get(&wrap->ztx->services, host);
    if (s != NULL) {
        ZITI_LOG(DEBUG, "hostname matches service name %s", host);
        service = s->name;
        return service;
    }

    MODEL_MAP_FOREACH(service, s, &wrap->ztx->services) {
        if (strcasecmp(service, host) == 0) {
            ZITI_LOG(DEBUG, "hostname matches service name %s", host);
            return service;
        }
    }

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

const char *fmt_identity(const ziti_intercept_cfg_v1 *intercept, const char* proto, const char *host, int port) {
    if (intercept == NULL) return NULL;

    tag *id_tag = model_map_get(&intercept->dial_options, "identity");
    if (id_tag == NULL || id_tag->type != tag_string) {
        return NULL;
    }

    static char identity[1024];
    const char *p = id_tag->string_value;
    char *o = identity;
    while(*p != 0) {
        if (*p == '$') {
            p++;
            if (strncmp(p, DST_PROTOCOL, strlen(DST_PROTOCOL)) == 0) {
                o += snprintf(o, sizeof(identity) - (o - identity), "%s", proto);
                p += strlen(DST_PROTOCOL);
            } else if (strncmp(p, DST_HOSTNAME, strlen(DST_HOSTNAME)) == 0) {
                o += snprintf(o, sizeof(identity) - (o - identity), "%s", host);
                p += strlen(DST_HOSTNAME);
            } else if (strncmp(p, DST_PORT, strlen(DST_PORT)) == 0) {
                o += snprintf(o, sizeof(identity) - (o - identity), "%d", port);
                p += strlen(DST_PORT);
            } else {
                *o++ = '$';
            }
        } else {
            *o++ = *p++;
        }

        if (o >= identity + sizeof(identity))
            break;
    }
    return identity;
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

    ziti_intercept_cfg_v1 *intercept = NULL;
    if (req->ztx == NULL) {
        MODEL_MAP_FOR(it, ziti_contexts) {
            ztx_wrap_t *wrap = model_map_it_value(it);
            const char *service_name = find_service(wrap, proto, host, req->port);

            if (service_name != NULL) {
                req->ztx = wrap->ztx;
                req->service = service_name;
                intercept = model_map_get(&wrap->intercepts, service_name);
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
                              "{\"" DST_PROTOCOL "\": \"%s\","
                               "\"" DST_HOSTNAME "\": \"%s\","
                               "\"" DST_PORT     "\": \"%u\"}",
                              proto_str, host, req->port);

        ziti_dial_opts opts = {
                .app_data = app_data,
                .app_data_sz = len,
                .identity = (char*)(req->terminator ?
                                    req->terminator :
                                    fmt_identity(intercept, proto_str, host, req->port)),
        };
        ZITI_LOG(DEBUG, "connecting fd[%d] to service[%s]", zs->fd, req->service);
        ZITI_LOG(VERBOSE, "appdata[%.*s]", (int)opts.app_data_sz, (char*)opts.app_data);
        ZITI_LOG(VERBOSE, "identity[%s]", opts.identity);
        ziti_dial_with_options(zs->conn, req->service, &opts, on_ziti_connect, NULL);
    } else {
        ZITI_LOG(WARN, "no service for target address[%s:%s:%d]", proto_str, req->host, req->port);
        fail_future(f, ECONNREFUSED);
    }
}

int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port) {
    if (host == NULL) { return EINVAL; }
    if (port == 0 || port > UINT16_MAX) { return EINVAL; }

    await_future(child_init_future, NULL);

    const char *id;
    ztx_wrap_t *wrap;
    MODEL_MAP_FOREACH(id, wrap, &ziti_contexts) {
        await_future(wrap->services_loaded, NULL);
    }

    struct conn_req_s req = {
            .fd = socket,
            .host = host,
            .port = port,
    };


    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);

    int err = 0;
    if (f) {
        err = await_future(f, NULL);
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
            .terminator = terminator ? strdup(terminator) : NULL,
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);
    int err = await_future(f, NULL);
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
    int rc = getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, &tolen);
    rc = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &fast_check, sizeof(fast_check));
    char b;
    int r = recv(s, &b, 0, MSG_OOB);
    int err = WSAGetLastError();
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(fast_check));

    if (r == 0)
        return true;
    else if (r == -1) {
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
        model_list_push(&pending->parent->accept_q, pending->accept_f);

        ziti_close(client, NULL);
        free(pending->caller_id);
        free(pending);
        return;
    }

    ziti_socket_t fd, ziti_fd;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    int rc = connect_socket(fd, &ziti_fd);
    if (rc != 0) {
        ZITI_LOG(WARN, "failed to connect client socket[%d]: %d", fd, rc);
        fail_future(pending->accept_f, rc);
        ziti_close(client, NULL);
        free(pending->caller_id);
        free(pending);
        return;
    }

    ZITI_LOG(INFO, "bridging socket for fd[%d]", fd);

    NEWP(zs, ziti_sock_t);
    zs->fd = fd;
    zs->ziti_fd = ziti_fd;
    ziti_conn_set_data(client, zs);
    model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);
    ziti_conn_bridge_fds(client, (uv_os_fd_t) zs->ziti_fd, (uv_os_fd_t) zs->ziti_fd, on_bridge_close, zs);
    NEWP(si, struct sock_info_s);
    si->fd = zs->fd;
    si->peer = pending->caller_id;

    ZITI_LOG(DEBUG, "completing accept future[%p] with fd[%d]", pending->accept_f, fd);
    complete_future(pending->accept_f, si);
    free(pending);
}

static void on_ziti_client(ziti_connection server, ziti_connection client, int status, const ziti_client_ctx *clt_ctx) {
    ziti_sock_t *server_sock = ziti_conn_data(server);

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "closing server fd[%d]: failed to accept client [%d/%s]", server_sock->fd, status, ziti_errorstr(status));
        on_bridge_close(server_sock);
        return;
    }
    ZITI_LOG(DEBUG, "incoming client[%s] for service[%s]/fd[%d]", clt_ctx->caller_id, server_sock->service, server_sock->fd);

    char notify = 1;

    NEWP(pending, struct backlog_entry_s);
    pending->parent = server_sock;
    pending->conn = client;
    pending->caller_id = strdup(clt_ctx->caller_id);

    future_t *accept_f = model_list_pop(&server_sock->accept_q);
    if (accept_f) {
        ZITI_LOG(DEBUG, "found waiting accept for fd[%d]", server_sock->fd);

        pending->accept_f = accept_f;

        ziti_conn_set_data(client, pending);
        // this should not happen but check anyway
        if (ziti_accept(client, on_ziti_accept, NULL) != ZITI_OK) {
            ZITI_LOG(WARN, "ziti_accept() failed unexpectedly");
            ziti_close(client, NULL);
            free(pending->caller_id);
            free(pending);
            model_list_push(&server_sock->accept_q, accept_f);
            return;
        }
        send(server_sock->ziti_fd, &notify, sizeof(notify), 0);
        return;
    }

    if (model_list_size(&server_sock->backlog) < server_sock->max_pending) {
        ZITI_LOG(DEBUG, "server[%d] no active accept: putting connection in backlog and sending notify", server_sock->fd);
        model_list_append(&server_sock->backlog, pending);
        send(server_sock->ziti_fd, &notify, sizeof(notify), 0);
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
    int err = await_future(f, NULL);
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

    int err = await_future(f, NULL);
    set_error(err);
    destroy_future(f);
    return err ? -1 : 0;
}

static void do_ziti_accept(void *r, future_t *f, uv_loop_t *l) {
    ziti_socket_t server_fd = (ziti_socket_t) (uintptr_t) r;
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &server_fd, sizeof(server_fd));
    if (zs == NULL) {
        ZITI_LOG(WARN, "fd[%d] is not a ziti socket", server_fd);
        fail_future(f, EINVAL);
        return;
    }

    if (!zs->server) {
        ZITI_LOG(WARN, "fd[%d] cannot so accept on non-server socket", server_fd);
        fail_future(f, EBADF);
        return;
    }

    while (model_list_size(&zs->backlog) > 0) {
        struct backlog_entry_s *pending = model_list_pop(&zs->backlog);
        ZITI_LOG(DEBUG, "server[%d]: pending connection[%s] for service[%s]", zs->fd, pending->caller_id, zs->service);

        ziti_connection conn = pending->conn;
        pending->accept_f = f;
        ziti_conn_set_data(conn, pending);
        int rc = ziti_accept(conn, on_ziti_accept, NULL);

        if (rc == ZITI_OK) {
            return;
        }

        ZITI_LOG(DEBUG, "failed to accept: client conn[%d] gone? [%d/%s]", conn->conn_id, rc, ziti_errorstr(rc));
        ziti_close(conn, NULL);
        free(pending->caller_id);
        free(pending);
    }

    // no pending connections
    if (model_list_size(&zs->backlog) == 0) {
        bool blocking = is_blocking(server_fd);
        ZITI_LOG(DEBUG, "fd[%d] is_blocking[%d]", server_fd, blocking);

        ZITI_LOG(DEBUG, "no pending connections for server fd[%d]", server_fd);
        if (blocking) {
            model_list_append(&zs->accept_q, f);
        } else {
            fail_future(f, EWOULDBLOCK);
        }
        return;
    }

}

ziti_socket_t Ziti_accept(ziti_socket_t server, char *caller, int caller_len) {
    future_t *f = schedule_on_loop(do_ziti_accept, (void *) (uintptr_t) server, true);
    ZITI_LOG(DEBUG, "fd[%d] waiting for future[%p]", server, f);
    ziti_socket_t clt = -1;
    struct sock_info_s *si;
    int err = await_future(f, (void **) &si);
    ZITI_LOG(DEBUG, "fd[%d] future[%p] completed err = %d", server, f, err);

    if (!err) {
        clt = si->fd;
        if (caller != NULL) {
            strncpy(caller, si->peer, caller_len);
        }
        ZITI_LOG(DEBUG, "fd[%d] future[%p] completed with caller %.*s", server, f, caller_len, caller);

        free(si->peer);
        free(si);
        char b;

        recv(server, &b, 1, 0);
    }
    set_error(err);
    destroy_future(f);
    ZITI_LOG(DEBUG, "fd[%d] future[%p] returning clt[%d]", server, f, clt);

    return clt;
}


void Ziti_lib_shutdown(void) {
    future_t *f = schedule_on_loop(do_shutdown, NULL, true);
    await_future(f, NULL);
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
//    pthread_atfork(NULL, NULL, child_init);
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
            .token = jwt,
            .key = key,
            .cert = cert,
    };
    future_t *f = schedule_on_loop((loop_work_cb) do_enroll, &opts, true);
    void *result;
    int rc = await_future(f, &result);
    if (rc == ZITI_OK) {
        *id_json = result;
        *id_json_len = strlen(*id_json);
    }
    destroy_future(f);
    return rc;
}

static model_map host_to_ip;
static model_map ip_to_host;

static in_addr_t addr_counter = 0x64400000; // 100.64.0.0
static void resolve_cb(void *r, future_t *f) {
    struct conn_req_s *req = r;

    ZITI_LOG(DEBUG, "resolving %s", req->host);
    in_addr_t ip = (in_addr_t)(intptr_t)model_map_get(&host_to_ip, req->host);
    if (ip == 0) {
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

static bool is_internal(const char *host) {
    // refuse resolving controller/router addresses here
    // this way Ziti context can operate even if resolve was high-jacked (e.g. zitify)
    MODEL_MAP_FOR(it, ziti_contexts) {
        ztx_wrap_t *wrap = model_map_it_value(it);
        if (wrap->ztx == NULL) continue;

        const char *ctrl = ziti_get_controller(wrap->ztx);
        struct tlsuv_url_s url;
        tlsuv_parse_url(&url, ctrl);

        if (strncmp(host, url.hostname, url.hostname_len) == 0) {
            return true;
        }

        if (wrap->ztx) {
            MODEL_MAP_FOR(chit, wrap->ztx->channels) {
                ziti_channel_t *ch = model_map_it_value(chit);
                if (strcmp(ch->host, host) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

ZITI_FUNC
int Ziti_resolve(const char *host, const char *port, const struct addrinfo *hints, struct addrinfo **addrlist) {
    if (host == NULL) {
        return EAI_NONAME;
    }

    int socktype = 0;
    int proto = 0;
    if (hints) {
        socktype = hints->ai_socktype;
        switch (hints->ai_socktype) {
            case SOCK_STREAM:proto = IPPROTO_TCP;break;
            case SOCK_DGRAM:proto = IPPROTO_UDP;break;
            case 0:proto = 0;break;// any type
            default: // no other protocols are supported
                return -1;
        }
    }

    // refuse resolving controller/router addresses here
    // this way Ziti context can operate even if resolve was high-jacked (e.g. zitify)
    if (is_internal(host)) {
        return -1;
    }

    in_port_t portnum = port ? (in_port_t) strtol(port, NULL, 10) : 0;
    ZITI_LOG(DEBUG, "host[%s] port[%s]", host, port);
    struct addrinfo *res = calloc(1, sizeof(struct addrinfo));
    res->ai_socktype = socktype;
    res->ai_protocol = proto;

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

    MODEL_MAP_FOR(it, ziti_contexts) {
        ztx_wrap_t *ztx = model_map_it_value(it);
        await_future(ztx->services_loaded, NULL);
    }

    struct conn_req_s req = {
            .host = host,
            .port = portnum,
    };

    future_t *f = schedule_on_loop((loop_work_cb) resolve_cb, &req, true);
    uintptr_t result;
    int err = await_future(f, (void **) &result);
    set_error(err);

    if (err == 0) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(portnum);
        addr4->sin_addr.s_addr = (in_addr_t)result;

        res->ai_family = AF_INET;
        res->ai_addr = (struct sockaddr *) addr4;
        res->ai_socktype = hints->ai_socktype;

        res->ai_addrlen = sizeof(*addr4);
        *addrlist = res;
    } else {
        free(res);
        free(addr4);
    }
    destroy_future(f);

    return err == 0 ? 0 : -1;
}

int Ziti_check_socket(ziti_socket_t fd) {
    ziti_sock_t *sock = model_map_get_key(&ziti_sockets, &fd, sizeof(fd));
    if (sock == NULL) return 0;
    if (sock->server) return 2;
    return 1;
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
