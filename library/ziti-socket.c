// Copyright (c) 2022.  NetFoundry, Inc.
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

#include <ziti/socket.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include "utils.h"

typedef struct future_s {
    uv_mutex_t lock;
    uv_cond_t cond;
    bool completed;
    void *result;
    int err;

    LIST_ENTRY(future_s) _next;
} future_t;

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

typedef void (*loop_work_cb)(const void *arg, future_t *f, uv_loop_t *l);

typedef struct queue_elem_s {
    loop_work_cb cb;
    const void *arg;
    future_t *f;
    LIST_ENTRY(queue_elem_s) _next;
} queue_elem_t;

static void internal_init();

static future_t *schedule_on_loop(loop_work_cb cb, const void *arg, bool wait);

static void do_shutdown(const void *args, future_t *f, uv_loop_t *l);

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

static struct sockaddr_un ziti_sock_name;
static ziti_socket_t ziti_sock_server;
#endif

typedef struct ztx_wrap {
    ziti_options opts;
    ziti_context ztx;
    LIST_HEAD(futures, future_s) futures;

    future_t *services_loaded;
    model_map intercepts;
} ztx_wrap_t;

typedef struct ziti_sock_s {
    ziti_socket_t fd;
    ziti_socket_t ziti_fd;
    future_t *f;
    ziti_context ztx;
    ziti_connection conn;
} ziti_sock_t;

static model_map ziti_contexts;

static model_map ziti_sockets;

void Ziti_lib_init(void) {
    uv_once(&init, internal_init);
}

int Ziti_last_error() {
    void *p = uv_key_get(&err_key);
    return (int)p;
}

static void set_error(int err) {
    uv_key_set(&err_key, (void*)err);
}

static void on_ctx_event(ziti_context ztx, const ziti_event_t *ev) {
    ztx_wrap_t *wrap = ziti_app_ctx(ztx);
    if (ev->type == ZitiContextEvent) {
        int err = ev->event.ctx.ctrl_status;
        if (err == ZITI_OK) {
            wrap->ztx = ztx;
            future_t *f;
            while (!LIST_EMPTY(&wrap->futures)) {
                f = LIST_FIRST(&wrap->futures);
                LIST_REMOVE(f, _next);
                complete_future(f, ztx);
            }
        } else if (err == ZITI_PARTIALLY_AUTHENTICATED) {
            return;
        } else {
            future_t *f;
            while (!LIST_EMPTY(&wrap->futures)) {
                f = LIST_FIRST(&wrap->futures);
                LIST_REMOVE(f, _next);
                fail_future(f, err);
            }
            if (err == ZITI_DISABLED) {
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

            if (ziti_service_get_config(s, ZITI_INTERCEPT_CFG_V1, intercept, parse_ziti_intercept_cfg_v1) == ZITI_OK) {
                intercept = model_map_set(&wrap->intercepts, s->name, intercept);
            }

            free_ziti_intercept_cfg_v1(intercept);
            FREE(intercept);
        }

        if (!wrap->services_loaded->completed) {
            complete_future(wrap->services_loaded, NULL);
        }
    }
}

static const char *configs[] = {
        ZITI_INTERCEPT_CFG_V1, NULL
};

static void load_ziti_ctx(const void *arg, future_t *f, uv_loop_t *l) {

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

        model_map_set(&ziti_contexts, arg, wrap);
        LIST_INSERT_HEAD(&wrap->futures, f, _next);

        ziti_init_opts(&wrap->opts, l);
    } else if (wrap->ztx) {
        complete_future(f, wrap->ztx);
    } else {
        LIST_INSERT_HEAD(&wrap->futures, f, _next);
    }
}

ziti_context Ziti_load_context(const char *identity) {
    future_t *f = schedule_on_loop(load_ziti_ctx, identity, true);
    int err = await_future(f);
    set_error(err);
    ziti_context ztx = (ziti_context) f->result;
    ztx_wrap_t *wrap = ziti_app_ctx(ztx);
    await_future(wrap->services_loaded);
    destroy_future(f);
    return ztx;
}

static void save_ziti_socket(const void *arg, future_t *f, uv_loop_t *l) {
    ziti_sock_t *zs = arg;
    model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);
    complete_future(f, (void *) zs);
}

#if _WIN32
static void connect_ziti_socket_win32(const void *arg, future_t *f, uv_loop_t *l) {
    ziti_sock_t *zs = arg;

    zs->ziti_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    int rc = connect(zs->ziti_fd, (const struct sockaddr *) &ziti_sock_name, sizeof(ziti_sock_name));
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        fail_future(f, err);
    } else {
        complete_future(f, NULL);
    }
}
#endif

ziti_socket_t Ziti_socket(int type) {
    NEWP(zs, ziti_sock_t);
    int rc = 0;
#if _WIN32
    future_t *conn_f = schedule_on_loop(connect_ziti_socket_win32, zs, true);
    zs->fd = accept(ziti_sock_server, NULL, 0);
    rc = await_future(conn_f);
    destroy_future(conn_f);
#else
    int fds[2] = {-1, -1};
    rc = socketpair(AF_UNIX, type, 0, fds);
    zs->fd = fds[0];
    zs->ziti_fd = fds[1];
#endif

    if (rc != 0) {
        free(zs);
        return rc;
    }

    future_t *f = schedule_on_loop(save_ziti_socket, zs, true);
    rc = await_future(f);
    set_error(rc);
    destroy_future(f);
    return rc == 0 ? zs->fd : rc;
}

struct dial_req_s {
    ziti_socket_t fd;

    ziti_context ztx;
    const char *service;

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
    free(zs);
}

static void on_ziti_connect(ziti_connection conn, int status) {
    ziti_sock_t *zs = ziti_conn_data(conn);
    if (status == ZITI_OK) {
        ZITI_LOG(INFO, "bridge connected to ziti service");
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

static void do_ziti_connect(struct dial_req_s *req, future_t *f, uv_loop_t *l) {
    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));
    if (zs == NULL) {
        ZITI_LOG(WARN, "socket %lu not found", (unsigned long)req->fd);
        fail_future(f, -EBADF);
    } else if (zs->f != NULL) {
        fail_future(f, -EALREADY);
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
            ziti_conn_init(req->ztx, &zs->conn, zs);
            char app_data[1024];
            size_t len = snprintf(app_data, sizeof(app_data),
                                  "{\"dst_protocol\": \"%s\", \"dst_hostname\": \"%s\", \"dst_port\": \"%u\"}",
                                  proto_str, req->host, req->port);
            ziti_dial_opts opts = {
                    .app_data = app_data,
                    .app_data_sz = len,
            };
            ziti_dial_with_options(zs->conn, req->service, &opts, on_ziti_connect, NULL);
        } else {
            ZITI_LOG(WARN, "no service for target address[%s:%s:%d]", proto_str, req->host, req->port);
            fail_future(f, -ECONNREFUSED);
        }
    }
}

int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port) {
    if (host == NULL) return -EINVAL;
    if (port == 0 || port > UINT16_MAX) return -EINVAL;

    struct dial_req_s req = {
            .fd = socket,
            .host = host,
            .port = port,
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);
    int err = await_future(f);
    destroy_future(f);
    return err;
}

int Ziti_connect(ziti_socket_t socket, ziti_context ztx, const char *service) {

    if (ztx == NULL) return -EINVAL;
    if (service == NULL) return -EINVAL;

    struct dial_req_s req = {
            .fd = socket,
            .ztx = ztx,
            .service = service
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_connect, &req, true);
    int err = await_future(f);
    destroy_future(f);
    return err;
}

void Ziti_lib_shutdown(void) {
    schedule_on_loop(do_shutdown, NULL, true);
    uv_thread_join(&lib_thread);
    uv_key_delete(&err_key);
#if _WIN32
    closesocket(ziti_sock_server);
    if (!DeleteFile(ziti_sock_name.sun_path)) {
        fprintf(stderr, "failed to delete file: %lu\n", GetLastError());
    }
#endif
}

static void looper(void *arg) {
    uv_run(arg, UV_RUN_DEFAULT);
}

future_t *schedule_on_loop(loop_work_cb cb, const void *arg, bool wait) {
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
#if _WIN32
    WORD ver = MAKEWORD(2,2);
    WSADATA data;
    DWORD err;
    err = WSAStartup(ver, &data);

    ziti_sock_server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ziti_sock_server == INVALID_SOCKET) {
        fprintf(stderr, "invalid socket: %d", WSAGetLastError());
    }

    ziti_sock_name.sun_family = AF_UNIX;
    char temp[sizeof(ziti_sock_name.sun_path)];
    GetTempPath(sizeof(temp), temp);
    snprintf(ziti_sock_name.sun_path, sizeof(ziti_sock_name.sun_path), "%sziti-socket.%d", temp, uv_os_getpid());

    err = bind(ziti_sock_server, (const struct sockaddr *) &ziti_sock_name, sizeof(ziti_sock_name));
    if (err != 0) {
        fprintf(stderr, "failed to bind: %ld %d", err, WSAGetLastError());
    }
    err = listen(ziti_sock_server, 10);
    if (err != 0) {
        fprintf(stderr, "failed to listen: %ld %d", err, WSAGetLastError());
    }
#endif
    uv_key_create(&err_key);
    uv_mutex_init(&q_mut);
    lib_loop = uv_loop_new();
    uv_async_init(lib_loop, &q_async, process_on_loop);
    uv_thread_create(&lib_thread, looper, lib_loop);
}

void do_shutdown(const void *args, future_t *f, uv_loop_t *l) {
    model_map_iter *it = model_map_iterator(&ziti_contexts);
    while (it) {
        ztx_wrap_t *w = model_map_it_value(it);
        it = model_map_it_remove(it);
        ziti_shutdown(w->ztx);
        model_map_clear(&w->intercepts, free_ziti_intercept_cfg_v1);
    }
    uv_close(&q_async, NULL);
    uv_loop_close(l);
}
