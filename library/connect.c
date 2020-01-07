/*
Copyright 2019-2020 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdlib.h>
#include <assert.h>

#include "zt_internal.h"
#include "utils.h"
#include "endian_internal.h"

struct nf_conn_req {
    struct nf_conn *conn;
    char *service_id;
    ziti_channel_t *channel;
    nf_conn_cb cb;

    uv_timer_t *t;
};

int ziti_channel_start_connection(struct nf_conn_req *req);

static void free_handle(uv_handle_t *h) {
    free(h);
}

void on_write_completed(struct nf_conn *conn, struct nf_write_req *req, int status) {
    if (req->conn == NULL) {
        ZITI_LOG(DEBUG, "write completed for timed out or closed connection");
        free(req);
        return;
    }
    conn->write_reqs--;

    if (status < 0) {
        conn->state = Closed;
        SLIST_REMOVE(&conn->channel->connections, conn, nf_conn, next);
    }

    if (req->timeout != NULL) {
        uv_timer_stop(req->timeout);
        uv_close((uv_handle_t *) req->timeout, free_handle);
    }

    if (req->cb != NULL) {
        if (status == 0) {
            status = req->len;
        }
        req->cb(conn, status, req->ctx);
    }

    if (conn->state == Closed && conn->write_reqs == 0) {
        free(conn);
    }
    free(req);
}

static int send_message(struct nf_conn *conn, uint32_t content, uint8_t *body, uint32_t body_len, struct nf_write_req *wr) {
    ziti_channel_t *ch = conn->channel;
    int32_t conn_id = htole32(conn->conn_id);
    int32_t msg_seq = htole32(conn->edge_msg_seq++);
    hdr_t headers[] = {
            {
                    .header_id = ConnIdHeader,
                    .length = sizeof(conn_id),
                    .value = (uint8_t *) &conn_id
            },
            {
                    .header_id = SeqHeader,
                    .length = sizeof(msg_seq),
                    .value = (uint8_t *) &msg_seq
            }
    };
    return ziti_channel_send(ch, content, headers, 2, body, body_len, wr);
}

static void on_channel_connected(ziti_channel_t *ch, void *ctx, int status) {

    struct nf_conn_req * req = ctx;
    if (status < 0) {
        ZITI_LOG(ERROR, "ch[%d] failed to connect status[%d](%s)", ch->id, status, uv_strerror(status));
        req->cb(req->conn, ZITI_GATEWAY_UNAVAILABLE);
    }
    else if (req->conn->channel == NULL) { // first channel to connect
        ZITI_LOG(TRACE, "channel connected status[%d]", status);

        req->conn->edge_msg_seq = 1;

        req->channel = ch;
        req->conn->channel = ch;
        ziti_channel_start_connection(req);
    }
    else {
        ZITI_LOG(TRACE, "conn[%d] is already using another channel", req->conn->conn_id);
    }

}

static void connect_timeout(uv_timer_t *timer) {
    struct nf_conn_req *req = timer->data;
    struct nf_conn *conn = req->conn;

    if (conn->state == Connecting) {
        ZITI_LOG(WARN, "ziti connection timed out");
        conn->state = Closed;
        req->cb(conn, ZITI_TIMEOUT);
    }

    uv_timer_stop(timer);
    uv_close((uv_handle_t *) timer, free_handle);
    req->t = NULL;
}

static int ziti_connect(struct nf_ctx *ctx, const ziti_net_session *session, struct nf_conn_req *req) {
    struct nf_conn *conn = req->conn;
    conn->token = session->token;

    ziti_edge_router **er;
    for (er = session->edge_routers; *er != NULL; er++) {
        ZITI_LOG(TRACE, "connecting to %s(%s) for session[%s]", (*er)->name, (*er)->url_tls, conn->token);
        ziti_channel_connect(ctx, (*er)->url_tls, on_channel_connected, req);
    }

    return 0;
}

void ziti_connect_async(uv_async_t *ar) {
    struct nf_conn_req *req = ar->data;
    struct nf_ctx *ctx = req->conn->nf_ctx;
    uv_loop_t *loop = ar->loop;

    uv_close((uv_handle_t *) ar, free_handle);

    // find service
    const ziti_net_session *net_session = NULL;
    const char *service_id = NULL;
    ziti_service *s;
    SLIST_FOREACH (s, &ctx->services, _next) {
        if (strcmp(req->service_id, s->name) == 0) {
            service_id = s->id;
            break;
        }
    }

    if (service_id == NULL) {
        req->cb(req->conn, ZITI_SERVICE_UNAVALABLE);
        return;
    }

    ziti_net_session *it;
    SLIST_FOREACH(it, &ctx->net_sessions, _next) {
        if (strcmp(service_id, it->service_id) == 0) {
            net_session = it;
            break;
        }
    }

    //at this point the service_id allocated in ziti_dial is no longer needed - free it
    free(req->service_id);
    req->service_id = NULL;

    if (net_session == NULL) {
        req->cb(req->conn, ZITI_SERVICE_UNAVALABLE);
    }
    else {
        req->t = malloc(sizeof(uv_timer_t));
        uv_timer_init(loop, req->t);
        req->t->data = req;
        uv_timer_start(req->t, connect_timeout, req->conn->timeout, 0);

        ziti_connect(ctx, net_session, req);
    }
}

int ziti_dial(nf_connection conn, const char *service, nf_conn_cb conn_cb, nf_data_cb data_cb) {
    NEWP(req, struct nf_conn_req);

    //duplicate the service name in case the callee reclaims the memory
    //this string is free'd in ziti_connect_async
    req->service_id = strdup(service);
    req->conn = conn;
    req->cb = conn_cb;

    conn->data_cb = data_cb;
    conn->state = Connecting;

    NEWP(async_cr, uv_async_t);
    uv_async_init(conn->nf_ctx->loop, async_cr, ziti_connect_async);

    async_cr->data = req;

    return uv_async_send(async_cr);
}

static void ziti_write_timeout(uv_timer_t *t) {
    struct nf_write_req *req = t->data;
    struct nf_conn *conn = req->conn;
    struct ziti_channel *ch = conn->channel;

    conn->write_reqs--;
    req->timeout = NULL;
    req->conn = NULL;

    if (conn->state != Closed) {
        conn->state = Closed;
        req->cb(conn, ZITI_TIMEOUT, req->ctx);
        SLIST_REMOVE(&ch->connections, conn, nf_conn, next);
    }

    if (conn->write_reqs == 0) {
        free(conn);
    }

    uv_close((uv_handle_t *) t, free_handle);
}

static void ziti_write_async(uv_async_t *ar) {
    struct nf_write_req *req = ar->data;
    struct nf_conn *conn = req->conn;

    conn->write_reqs++;

    if (req->cb) {
        req->timeout = calloc(1, sizeof(uv_timer_t));
        uv_timer_init(ar->loop, req->timeout);
        req->timeout->data = req;
        uv_timer_start(req->timeout, ziti_write_timeout, conn->timeout, 0);
    }

    send_message(conn, ContentTypeData, req->buf, req->len, req);

    uv_close((uv_handle_t *) ar, free_handle);
}

int ziti_write(struct nf_write_req *req) {
    NEWP(ar, uv_async_t);
    uv_async_init(req->conn->nf_ctx->loop, ar, ziti_write_async);
    ar->data = req;
    return uv_async_send(ar);
}

static void ziti_disconnect_async(uv_async_t *ar) {
    struct nf_conn *conn = ar->data;

    uv_close((uv_handle_t *) ar, free_handle);

    if (conn->state == Connected) {
        NEWP(wr, struct nf_write_req);
        send_message(conn, ContentTypeStateClosed, NULL, 0, wr);
    }
}

int ziti_disconnect(struct nf_conn *conn) {
    NEWP(ar, uv_async_t);
    uv_async_init(conn->channel->ctx->loop, ar, ziti_disconnect_async);
    ar->data = conn;
    return uv_async_send(ar);
}

void connect_reply_cb(void *ctx, message *msg) {
    struct nf_conn_req* req = ctx;
    struct nf_conn *conn = req->conn;

    if (req->t != NULL) {
        uv_timer_stop(req->t);
        uv_close((uv_handle_t *) req->t, free_handle);
        req->t = NULL;
    }

    switch (msg->header.content) {
        case ContentTypeStateClosed:
            ZITI_LOG(ERROR, "edge conn_id[%d]: failed to %s, reason=%*s",
                     conn->conn_id, conn->state == Binding ? "bind" : "connect",
                     msg->header.body_len, msg->body);
            conn->state = Closed;
            req->cb(conn, ZITI_EOF);
            SLIST_REMOVE(&req->channel->connections, conn, nf_conn, next);
            break;

        case ContentTypeStateConnected:
            if (conn->state == Connecting) {
                ZITI_LOG(TRACE, "edge conn_id[%d]: connected.", conn->conn_id);
                conn->state = Connected;
                req->cb(conn, ZITI_OK);
            }
            else if (conn->state == Binding) {
                ZITI_LOG(TRACE, "edge conn_id[%d]: bound.", conn->conn_id);
                conn->state = Bound;
                req->cb(conn, ZITI_OK);
            }
            else if (conn->state == Accepting) {
                ZITI_LOG(TRACE, "edge conn_id[%d]: accepted.", conn->conn_id);
                conn->state = Connected;
                req->cb(conn, ZITI_OK);
            }
            else if (conn->state == Closed) {
                ZITI_LOG(WARN, "received connect reply for closed/timedout connection[%d]", conn->conn_id);
                ziti_disconnect(conn);
                SLIST_REMOVE(&conn->channel->connections, conn, nf_conn, next);
            }
            break;

        default:
            ZITI_LOG(WARN, "unexpected content_type[%d] conn_id[%d]", msg->header.content, conn->conn_id);
            ziti_disconnect(conn);
            SLIST_REMOVE(&conn->channel->connections, conn, nf_conn, next);
    }
    free(ctx);
}

int ziti_channel_start_connection(struct nf_conn_req *req) {
    ziti_channel_t *ch = req->channel;

    req->conn->channel = ch;
    req->conn->conn_id = ch->conn_seq++;

    ZITI_LOG(TRACE, "ch[%d] => Edge Connect request token[%s] conn_id[%d]", ch->id, req->conn->token,
             req->conn->conn_id);

    uint32_t content_type;
    switch (req->conn->state) {
        case Binding:
            content_type = ContentTypeBind;
            break;
        case Connecting:
            content_type = ContentTypeConnect;
            break;
        case Closed:
            ZITI_LOG(WARN, "channel did not connect in time for connection[%d]. ", req->conn->conn_id);
            return ZITI_OK;
        default:
            ZITI_LOG(ERROR, "connection[%d] is in unexpected state[%d]", req->conn->conn_id, req->conn->state);
            return ZITI_WTF;
    }

    SLIST_INSERT_HEAD(&ch->connections, req->conn, next);

    int32_t conn_id = htole32(req->conn->conn_id);
    int32_t msg_seq = htole32(0);
    hdr_t headers[] = {
            {
                    .header_id = ConnIdHeader,
                    .length = sizeof(conn_id),
                    .value = (uint8_t *) &conn_id
            },
            {
                    .header_id = SeqHeader,
                    .length = sizeof(msg_seq),
                    .value = (uint8_t *) &msg_seq
            }
    };
    ziti_channel_send_for_reply(ch, content_type, headers, 2, req->conn->token, strlen(req->conn->token),
                                connect_reply_cb, req);

    return ZITI_OK;
}

int ziti_bind(nf_connection conn, const char *service, nf_listen_cb listen_cb, nf_client_cb on_clt_cb) {
    NEWP(req, struct nf_conn_req);

    //duplicate the service name in case the callee reclaims the memory
    //this string is free'd in ziti_connect_async
    req->service_id = strdup(service);
    req->conn = conn;
    req->cb = listen_cb;

    conn->client_cb = on_clt_cb;
    conn->state = Binding;

    NEWP(async_cr, uv_async_t);
    uv_async_init(conn->nf_ctx->loop, async_cr, ziti_connect_async);
    async_cr->data = req;
    return uv_async_send(async_cr);

}

int ziti_accept(nf_connection conn, nf_conn_cb cb, nf_data_cb data_cb) {

    ziti_channel_t *ch = conn->parent->channel;

    conn->channel = ch;
    conn->conn_id = ch->conn_seq++;
    conn->data_cb = data_cb;

    SLIST_INSERT_HEAD(&ch->connections, conn, next);

    ZITI_LOG(TRACE, "ch[%d] => Edge Accept conn_id[%d] parent_conn_id[%d]", ch->id, conn->conn_id,
             conn->parent->conn_id);

    uint32_t content_type = ContentTypeDialSuccess;

    int32_t conn_id = htole32(conn->parent->conn_id);
    int32_t msg_seq = htole32(0);
    int32_t reply_id = htole32(conn->dial_req_seq);
    int32_t clt_conn_id = htole32(conn->conn_id);
    hdr_t headers[] = {
            {
                    .header_id = ConnIdHeader,
                    .length = sizeof(conn_id),
                    .value = (uint8_t *) &conn_id
            },
            {
                    .header_id = SeqHeader,
                    .length = sizeof(msg_seq),
                    .value = (uint8_t *) &msg_seq
            },
            {
                    .header_id = ReplyForHeader,
                    .length = sizeof(reply_id),
                    .value = (uint8_t *) &reply_id
            },
    };
    NEWP(req, struct nf_conn_req);
    req->channel = conn->channel;
    req->conn = conn;
    req->cb = cb;
    ziti_channel_send_for_reply(ch, content_type, headers, 3, (const uint8_t *) &clt_conn_id, sizeof(clt_conn_id),
                                connect_reply_cb, req);

    return ZITI_OK;
}
