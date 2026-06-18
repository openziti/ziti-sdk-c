// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
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

#include "zl.h"

#include <ziti/ziti_log.h>

#include "connect.h"
#include "utils.h"

struct backlog_entry_s {
    struct ziti_sock_s *parent;
    ziti_connection conn;
    cstr caller_id;
    future_t *accept_f;
    TAILQ_ENTRY(backlog_entry_s) _next;
};

struct sock_info_s {
    ziti_socket_t fd;
    cstr peer;
};

struct bind_req_s {
    ziti_socket_t fd;

    ziti_handle_t ziti_handle;
    cstr service;
    cstr terminator;
};


static void do_ziti_accept(void *r, future_t *f, uv_loop_t *l);
static void do_ziti_bind(struct bind_req_s *req, future_t *f, uv_loop_t *l);
static void bind_req_drop(struct bind_req_s *req);
static void on_bridge_close(void *ctx);

int Ziti_bind(ziti_socket_t socket, ziti_handle_t zh, const char *service, const char *terminator) {
    if (!zl_check_daemon()) {
        set_errno(err(EINVAL));
        return -1;
    }
    if (zh == ZITI_INVALID_HANDLE) {
        set_errno(err(EINVAL));
        return -1;
    }
    if (service == NULL) {
        set_errno(err(EINVAL));
        return -1;
    }

    struct bind_req_s req = {
        .fd = socket,
        .ziti_handle = zh,
        .service = cstr_from(service),
        .terminator = terminator ? cstr_from(terminator) : cstr_init(),
    };

    future_t *f = schedule_on_loop((loop_work_cb) do_ziti_bind, &req, true);
    int err = await_future(f, NULL);
    destroy_future(f);
    bind_req_drop(&req);
    if (err != 0) {
        set_errno(err);
    }
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
        complete_future(f, NULL, 0);
    }
}

int Ziti_listen(ziti_socket_t socket, int backlog) {
    if (!zl_check_daemon()) {
        zl_set_error(ZITI_INVALID_STATE);
        return -1;
    }

    if (backlog <= 0) {
        set_errno(err(EINVAL));
        return -1;
    }

    struct listen_req_s req = {.fd = socket, .backlog = backlog};
    future_t *f = schedule_on_loop(do_ziti_listen, &req, true);

    int err = await_future(f, NULL);
    destroy_future(f);
    if (err != 0) {
        set_errno(err);
    }
    return err ? -1 : 0;
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
            snprintf(caller, caller_len, "%s", cstr_str(&si->peer));
        }
        ZITI_LOG(DEBUG, "fd[%d] future[%p] completed with caller %.*s", server, f, caller_len, caller);

        cstr_drop(&si->peer);
        free(si);
        char b;

        recv(server, &b, 1, 0);
    }
    destroy_future(f);
    ZITI_LOG(DEBUG, "fd[%d] future[%p] returning clt[%d]", server, f, clt);

    zl_set_error(err);
    if (err != 0) {
        set_errno(err);
    }
    return clt;
}

static void on_ziti_accept(ziti_connection client, int status) {
    struct backlog_entry_s *pending = ziti_conn_data(client);
    if (status != ZITI_OK) {
        ZITI_LOG(WARN, "ziti_accept failed!");
        // ziti accept failed, so just put the accept future back into accept_q
        model_list_push(&pending->parent->accept_q, pending->accept_f);

        ziti_close(client, NULL);
        cstr_drop(&pending->caller_id);
        free(pending);
        return;
    }

    ziti_socket_t fd, ziti_fd;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    int rc = connect_socket(AF_INET, fd, &ziti_fd);
    if (rc != 0) {
        ZITI_LOG(WARN, "failed to connect client socket[%d]: %d", fd, rc);
        fail_future(pending->accept_f, rc);
        ziti_close(client, NULL);
        cstr_drop(&pending->caller_id);
        free(pending);
        return;
    }

    ZITI_LOG(INFO, "bridging socket for fd[%d]", fd);

    NEWP(zs, ziti_sock_t);
    zs->fd = fd;
    zs->ziti_fd = ziti_fd;
    ziti_conn_set_data(client, zs);
    model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);
    ziti_conn_bridge_fds(client, zs->ziti_fd, zs->ziti_fd, on_bridge_close, zs);
    NEWP(si, struct sock_info_s);
    si->fd = zs->fd;
    si->peer = pending->caller_id;

    ZITI_LOG(DEBUG, "completing accept future[%p] with fd[%d]", pending->accept_f, fd);
    complete_future(pending->accept_f, si, 0);
    free(pending);
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
        ZITI_LOG(DEBUG, "server[%d]: pending connection[%s] for service[%s]",
                 zs->fd, cstr_str(&pending->caller_id), cstr_str(&zs->service));

        ziti_connection conn = pending->conn;
        pending->accept_f = f;
        ziti_conn_set_data(conn, pending);
        int rc = ziti_accept(conn, on_ziti_accept, NULL);

        if (rc == ZITI_OK) {
            return;
        }

        ZITI_LOG(DEBUG, "failed to accept: client conn[%d] gone? [%d/%s]", conn->conn_id, rc, ziti_errorstr(rc));
        ziti_close(conn, NULL);
        cstr_drop(&pending->caller_id);
        free(pending);
    }

    // no pending connections
    if (model_list_size(&zs->backlog) == 0) {
        bool blocking = zl_is_blocking(server_fd);
        ZITI_LOG(DEBUG, "fd[%d] zl_is_blocking[%d]", server_fd, blocking);

        ZITI_LOG(DEBUG, "no pending connections for server fd[%d]", server_fd);
        if (blocking) {
            model_list_append(&zs->accept_q, f);
        } else {
            fail_future(f, EWOULDBLOCK);
        }
        return;
    }

}

static void on_ziti_client(ziti_connection server, ziti_connection client, int status, const ziti_client_ctx *clt_ctx) {
    ziti_sock_t *server_sock = ziti_conn_data(server);

    if (status != ZITI_OK) {
        ZITI_LOG(ERROR, "closing server fd[%d]: failed to accept client [%d/%s]", server_sock->fd, status, ziti_errorstr(status));
        on_bridge_close(server_sock);
        return;
    }


    NEWP(pending, struct backlog_entry_s);
    pending->parent = server_sock;
    pending->conn = client;
    pending->caller_id = clt_ctx && clt_ctx->caller_id ? cstr_from(clt_ctx->caller_id) : cstr_init();
    ZITI_LOG(DEBUG, "incoming client[%s] for service[%s]/fd[%d]", cstr_str(&pending->caller_id),
             cstr_str(&server_sock->service), server_sock->fd);

    char notify = 1;
    future_t *accept_f = model_list_pop(&server_sock->accept_q);
    if (accept_f) {
        ZITI_LOG(DEBUG, "found waiting accept for fd[%d]", server_sock->fd);

        pending->accept_f = accept_f;

        ziti_conn_set_data(client, pending);
        // this should not happen but check anyway
        if (ziti_accept(client, on_ziti_accept, NULL) != ZITI_OK) {
            ZITI_LOG(WARN, "ziti_accept() failed unexpectedly");
            ziti_close(client, NULL);
            cstr_drop(&pending->caller_id);
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
        ZITI_LOG(WARN, "failed to bind fd[%d] to service[%s] err[%d/%s]", zs->fd, cstr_str(&zs->service), status, ziti_errorstr(status));
        fail_future(zs->f, status);
        cstr_drop(&zs->service);
        free(zs);
    } else {
        connect_socket(AF_INET, zs->fd, &zs->ziti_fd);
        model_map_set_key(&ziti_sockets, &zs->fd, sizeof(zs->fd), zs);

        ZITI_LOG(DEBUG, "successfully bound fd[%d] to service[%s]", zs->fd, cstr_str(&zs->service));
        complete_future(zs->f, server, 0);
    }
}

static void do_ziti_bind(struct bind_req_s *req, future_t *f, uv_loop_t *l) {
    ztx_wrap_t *wrap = zl_find_wrap(req->ziti_handle);
    if (wrap == NULL) {
        ZITI_LOG(WARN, "ziti handle[%d] not found", req->ziti_handle);
        fail_future(f, EINVAL);
        return;
    }

    ziti_sock_t *zs = model_map_get_key(&ziti_sockets, &req->fd, sizeof(req->fd));
    if (zs) {
        fail_future(f, EALREADY);
        return;
    }

    zs = calloc(1, sizeof(*zs));
    zs->fd = req->fd;
    cstr_copy(&zs->service, req->service);
    zs->f = f;

    ZITI_LOG(DEBUG, "requesting bind fd[%d] to service[%s@%s]", zs->fd, cstr_str(&req->terminator), cstr_str(&req->service));
    ziti_listen_opts opts = {
        .identity = cstr_is_empty(&req->terminator) ? NULL : (char*)cstr_str(&req->terminator),
    };
    ziti_conn_init(wrap->ztx, &zs->conn, zs);
    ziti_listen_with_options(zs->conn, cstr_str(&req->service), &opts, on_ziti_bind, on_ziti_client);
}

static void bind_req_drop(struct bind_req_s *req) {
    cstr_drop(&req->service);
    cstr_drop(&req->terminator);
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




