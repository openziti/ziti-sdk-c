/*
Copyright 2019-2020 NetFoundry, Inc.

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

#include "zt_internal.h"
#include "utils.h"
#include "endian_internal.h"

static const char *TYPE_BIND = "Bind";
static const char *TYPE_DIAL = "Dial";

#define crypto(func) crypto_secretstream_xchacha20poly1305_##func

struct nf_conn_req {
    struct nf_conn *conn;
    char *service_name;
    const char *session_type;
    ziti_service *service;
    ziti_channel_t *channel;
    nf_conn_cb cb;

    uv_timer_t *conn_timeout;

    LIST_ENTRY(nf_conn_req) _next;
    int ref_count;
};

static void ziti_connect_async(uv_async_t *ar);
int ziti_channel_start_connection(struct nf_conn_req *req);

static void free_handle(uv_handle_t *h) {
    free(h);
}

static void free_conn_req(struct nf_conn_req *r) {
    FREE(r->service_name);
    if (r->conn_timeout) {
        uv_close((uv_handle_t *) r->conn_timeout, free_handle);
    }
    free(r);
};

void on_write_completed(struct nf_conn *conn, struct nf_write_req *req, int status) {
    if (req->conn == NULL) {
        ZITI_LOG(DEBUG, "write completed for timed out or closed connection");
        free(req);
        return;
    }
    conn->write_reqs--;

    if (req->timeout != NULL) {
        uv_timer_stop(req->timeout);
        uv_close((uv_handle_t *) req->timeout, free_handle);
    }

    if (req->cb != NULL) {
        if (status == 0) {
            status = req->len;
        }

        if (status < 0) {
            conn->state = Closed;
        }

        req->cb(conn, status, req->ctx);
    }

    if (conn->state == Closed && conn->write_reqs == 0) {
        LIST_REMOVE(conn, next);
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
    conn->write_reqs++;
    return ziti_channel_send(ch, content, headers, 2, body, body_len, wr);
}

static void on_channel_connected(ziti_channel_t *ch, void *ctx, int status) {
    nf_context nf = ch->ctx;

    struct nf_conn_req *req;

    LIST_FOREACH(req, &nf->connect_requests, _next) {
        if (req == ctx)
            break;
    }
    if (req == NULL) {
        ZITI_LOG(DEBUG, "req was removed");
        return;
    }

    if (status < 0) {
        ZITI_LOG(ERROR, "ch[%d] failed to connect status[%d](%s)", ch->id, status, uv_strerror(status));
        req->cb(req->conn, ZITI_GATEWAY_UNAVAILABLE);
    }
    else if (req->conn->channel == NULL) { // first channel to connect
        ZITI_LOG(TRACE, "channel connected status[%d]", status);

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

        LIST_REMOVE(req, _next);
    } else {
        ZITI_LOG(ERROR, "timeout for connection[%d] in unexpected state[%d]", conn->conn_id, conn->state);
    }

    uv_timer_stop(timer);
    free_conn_req(req);
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

static void connect_get_service_cb(ziti_service* s, ziti_error *err, void *ctx) {
    uv_async_t *ar = ctx;
    struct nf_conn_req *req = ar->data;
    struct nf_ctx *nf_ctx = req->conn->nf_ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to load service (%s): %s(%s)", req->service_name, err->code, err->message);
    }
    if (s == NULL) {
        req->cb(req->conn, ZITI_SERVICE_UNAVAILABLE);
        free_conn_req(req);
    } else {
        ZITI_LOG(INFO, "got service[%s] id[%s]", s->name, s->id);
        for (int i = 0; s->permissions[i] != NULL; i++) {
            if (strcmp(s->permissions[i], "Dial") == 0) {
                 s->perm_flags |= ZITI_CAN_DIAL;
            }
            if (strcmp(s->permissions[i], "Bind") == 0) {
                s->perm_flags |= ZITI_CAN_BIND;
            }
        }
        LIST_INSERT_HEAD(&nf_ctx->services, s, _next);
        req->service = s;
        ziti_connect_async(ar);
    }

    free_ziti_error(err);
}

static void connect_get_net_session_cb(ziti_net_session * s, ziti_error *err, void *ctx) {
    uv_async_t *ar = ctx;
    struct nf_conn_req *req = ar->data;
    struct nf_ctx *nf_ctx = req->conn->nf_ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to load service[%s]: %s(%s)", req->service_name, err->code, err->message);
    }
    if (s == NULL) {
        req->cb(req->conn, ZITI_SERVICE_UNAVAILABLE);
        free_conn_req(req);
    } else {
        ZITI_LOG(INFO, "got session[%s] for service[%s]", s->id, req->service->name);
        s->service_id = strdup(req->service->id);
        LIST_INSERT_HEAD(&nf_ctx->net_sessions, s, _next);
        ziti_connect_async(ar);
    }

    free_ziti_error(err);
}

static void ziti_connect_async(uv_async_t *ar) {
    struct nf_conn_req *req = ar->data;
    struct nf_ctx *ctx = req->conn->nf_ctx;
    uv_loop_t *loop = ar->loop;

    const ziti_net_session *net_session = NULL;
    const char *service_id = NULL;

    // find service
    if (req->service == NULL) {
        ziti_service *s;
        LIST_FOREACH (s, &ctx->services, _next) {
            if (strcmp(req->service_name, s->name) == 0) {
                service_id = s->id;
                req->service = s;
                break;
            }
        }

        if (service_id == NULL) {
            ZITI_LOG(DEBUG, "service[%s] not loaded yet, requesting it", req->service_name);
            ziti_ctrl_get_service(&ctx->controller, req->service_name, connect_get_service_cb, ar);
            return;
        }
    }

    ziti_net_session *it = NULL;
    LIST_FOREACH(it, &ctx->net_sessions, _next) {
        if (strcmp(req->service->id, it->service_id) == 0 && strcmp(req->session_type, it->session_type) == 0 ) {
            net_session = it;
            break;
        }
    }

    if (net_session == NULL) {
        ZITI_LOG(DEBUG, "requesting session for service[%s]", req->service_name);
        ziti_ctrl_get_net_session(&ctx->controller, req->service, req->session_type, connect_get_net_session_cb, ar);
        return;
    }
    else {
        req->conn_timeout = malloc(sizeof(uv_timer_t));
        uv_timer_init(loop, req->conn_timeout);
        req->conn_timeout->data = req;
        uv_timer_start(req->conn_timeout, connect_timeout, req->conn->timeout, 0);

        ZITI_LOG(DEBUG, "starting connection for service[%s] with session[%s]", req->service_name, net_session->id);
        ziti_connect(ctx, net_session, req);
    }

    uv_close((uv_handle_t *) ar, free_handle);
}

int ziti_dial(nf_connection conn, const char *service, nf_conn_cb conn_cb, nf_data_cb data_cb) {

    nf_context nf = conn->nf_ctx;

    PREPF(ziti, ziti_errorstr);
    if (conn->state != Initial) {
        TRY(ziti, ZITI_INVALID_STATE);
    }


    NEWP(req, struct nf_conn_req);

    req->service_name = strdup(service);
    req->session_type = TYPE_DIAL;
    req->conn = conn;
    req->cb = conn_cb;

    conn->data_cb = data_cb;
    conn->state = Connecting;

    LIST_INSERT_HEAD(&nf->connect_requests, req, _next);

    CATCH(ziti) {
        return ERR(ziti);
    }

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
        LIST_REMOVE(conn, next);
    }

    if (conn->write_reqs == 0) {
        free(conn);
    }

    uv_close((uv_handle_t *) t, free_handle);
}

static void ziti_write_async(uv_async_t *ar) {
    struct nf_write_req *req = ar->data;
    struct nf_conn *conn = req->conn;

    if (req->cb) {
        req->timeout = calloc(1, sizeof(uv_timer_t));
        uv_timer_init(ar->loop, req->timeout);
        req->timeout->data = req;
        uv_timer_start(req->timeout, ziti_write_timeout, conn->timeout, 0);
    }

    if (conn->encrypted) {
        uint32_t crypto_len = req->len + crypto_secretstream_xchacha20poly1305_abytes();
        unsigned char *cipher_text = malloc(crypto_len);
        crypto_secretstream_xchacha20poly1305_push(&conn->crypt_o, cipher_text, NULL, req->buf, req->len, NULL, 0, 0);
        send_message(conn, ContentTypeData, cipher_text, crypto_len, req);
        free(cipher_text);
    } else {
        send_message(conn, ContentTypeData, req->buf, req->len, req);
    }

    uv_close((uv_handle_t *) ar, free_handle);
}

int ziti_write(struct nf_write_req *req) {
    NEWP(ar, uv_async_t);
    uv_async_init(req->conn->nf_ctx->loop, ar, ziti_write_async);
    ar->data = req;
    return uv_async_send(ar);
}

static void ziti_disconnect_cb(nf_connection conn, ssize_t status, void *ctx) {
    conn->state = Closed;
}

static void ziti_disconnect_async(uv_async_t *ar) {
    struct nf_conn *conn = ar->data;

    uv_close((uv_handle_t *) ar, free_handle);

    if (conn->state == Connected) {
        NEWP(wr, struct nf_write_req);
        wr->conn = conn;
        wr->cb = ziti_disconnect_cb;
        send_message(conn, ContentTypeStateClosed, NULL, 0, wr);
    }
}

int ziti_disconnect(struct nf_conn *conn) {
    NEWP(ar, uv_async_t);
    uv_async_init(conn->channel->ctx->loop, ar, ziti_disconnect_async);
    ar->data = conn;
    return uv_async_send(ar);
}

static void crypto_wr_cb(nf_connection conn, ssize_t status, void* ctx) {
    if (status < 0) {
        ZITI_LOG(ERROR, "crypto header write failed with status[%zd]", status);
        conn->data_cb(conn, NULL, status);
        LIST_REMOVE(conn, next);
    }
}

static int establish_crypto (nf_connection conn, message *msg) {

    size_t peer_key_len;
    uint8_t *peer_key;
    bool peer_key_sent = message_get_bytes_header(msg, PublicKeyHeader, &peer_key, &peer_key_len);
    if (!peer_key_sent) {
        ZITI_LOG(DEBUG, "did not recieve peer key. connection[%d] will not be encrypted", conn->conn_id);
        conn->encrypted = false;
        return ZITI_OK;
    }

    conn->encrypted = true;
    uint8_t tx[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    conn->rx = calloc(1, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    int rc;
    if (conn->state == Connecting) {
        rc = crypto_kx_client_session_keys(conn->rx, tx, conn->pk, conn->sk, peer_key);
    } else if (conn->state == Accepting) {
        rc = crypto_kx_server_session_keys(conn->rx, tx, conn->parent->pk, conn->parent->sk, peer_key);
    } else {
        ZITI_LOG(ERROR, "cannot establish crypto in %d state", conn->state);
        return ZITI_INVALID_STATE;
    }
    if (rc != 0) {
        return ZITI_CRYPTO_FAIL;
    }

    NEWP(wr, struct nf_write_req);
    wr->conn = conn;
    uint8_t *header = calloc(1, crypto_secretstream_xchacha20poly1305_headerbytes());
    wr->buf = header;
    wr->cb = crypto_wr_cb;

    crypto_secretstream_xchacha20poly1305_init_push(&conn->crypt_o, header, tx);
    send_message(conn, ContentTypeData, header, crypto_secretstream_xchacha20poly1305_headerbytes(), wr);
    free(header);
    return ZITI_OK;
}

void conn_inbound_data_msg(nf_connection conn, message *msg) {
    int rc = 0;
    if (conn->encrypted) {
        uint8_t *plain_text = NULL;
        PREP(crypto);
        // first message is expected to be peer crypto header
        if (conn->rx != NULL) {
            TRY(crypto, msg->header.body_len != crypto_secretstream_xchacha20poly1305_HEADERBYTES);
            TRY(crypto, crypto_secretstream_xchacha20poly1305_init_pull(&conn->crypt_i, msg->body, conn->rx));
            FREE(conn->rx);
        } else {
            unsigned long long plain_len;
            unsigned char tag;
            plain_text = malloc(msg->header.body_len);

            TRY(crypto, crypto_secretstream_xchacha20poly1305_pull(&conn->crypt_i, plain_text, &plain_len, &tag, msg->body, msg->header.body_len, NULL, 0));

            conn->data_cb(conn, plain_text, (int)plain_len);
        }

        CATCH(crypto) {
            conn->data_cb(conn, NULL, ZITI_CRYPTO_FAIL);
            LIST_REMOVE(conn, next);
            free(conn);
        }
        FREE(plain_text);
    } else {
        conn->data_cb(conn, msg->body, (int)msg->header.body_len);
    }
}

void connect_reply_cb(void *ctx, message *msg) {
    struct nf_conn_req* req = ctx;
    struct nf_conn *conn = req->conn;

    if (req->conn_timeout != NULL) {
        req->ref_count--;
        uv_timer_stop(req->conn_timeout);
    }

    switch (msg->header.content) {
        case ContentTypeStateClosed:
            ZITI_LOG(ERROR, "edge conn_id[%d]: failed to %s, reason=%*.*s",
                     conn->conn_id, conn->state == Binding ? "bind" : "connect",
                     msg->header.body_len, msg->header.body_len, msg->body);
            conn->state = Closed;
            req->cb(conn, ZITI_EOF);
            LIST_REMOVE(conn, next);
            break;

        case ContentTypeStateConnected:
            if (conn->state == Connecting) {
                ZITI_LOG(TRACE, "edge conn_id[%d]: connected.", conn->conn_id);
                establish_crypto(conn, msg);
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
                establish_crypto(conn, msg);
                conn->state = Connected;
                req->cb(conn, ZITI_OK);
            }
            else if (conn->state == Closed) {
                ZITI_LOG(WARN, "received connect reply for closed/timedout connection[%d]", conn->conn_id);
                ziti_disconnect(conn);
                LIST_REMOVE(conn, next);
            }
            break;

        default:
            ZITI_LOG(WARN, "unexpected content_type[%d] conn_id[%d]", msg->header.content, conn->conn_id);
            ziti_disconnect(conn);
            LIST_REMOVE(conn, next);
    }
    LIST_REMOVE(req, _next);
    free_conn_req(req);
}

int ziti_channel_start_connection(struct nf_conn_req *req) {
    ziti_channel_t *ch = req->channel;

    req->conn->channel = ch;

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

    LIST_INSERT_HEAD(&ch->connections, req->conn, next);

    int32_t conn_id = htole32(req->conn->conn_id);
    int32_t msg_seq = htole32(0);
    crypto_kx_keypair(req->conn->pk, req->conn->sk);

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
                    .header_id = PublicKeyHeader,
                    .length = sizeof(req->conn->pk),
                    .value = req->conn->pk,
            }
    };
    req->ref_count++;
    ziti_channel_send_for_reply(ch, content_type, headers, 3, req->conn->token, strlen(req->conn->token),
                                connect_reply_cb, req);

    return ZITI_OK;
}

int ziti_bind(nf_connection conn, const char *service, nf_listen_cb listen_cb, nf_client_cb on_clt_cb) {
    nf_context nf = conn->nf_ctx;

    NEWP(req, struct nf_conn_req);

    req->service_name = strdup(service);
    req->session_type = TYPE_BIND;
    req->conn = conn;
    req->cb = listen_cb;

    conn->client_cb = on_clt_cb;
    conn->state = Binding;

    LIST_INSERT_HEAD(&nf->connect_requests, req, _next);

    NEWP(async_cr, uv_async_t);
    uv_async_init(conn->nf_ctx->loop, async_cr, ziti_connect_async);
    async_cr->data = req;
    return uv_async_send(async_cr);

}

int ziti_accept(nf_connection conn, nf_conn_cb cb, nf_data_cb data_cb) {

    ziti_channel_t *ch = conn->parent->channel;

    conn->channel = ch;
    conn->data_cb = data_cb;

    LIST_INSERT_HEAD(&ch->connections, conn, next);

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
    LIST_INSERT_HEAD(&conn->nf_ctx->connect_requests, req, _next);

    ziti_channel_send_for_reply(ch, content_type, headers, 3, (const uint8_t *) &clt_conn_id, sizeof(clt_conn_id),
                                connect_reply_cb, req);

    return ZITI_OK;
}

int ziti_process_connect_reqs(nf_context nf) {
    ZITI_LOG(WARN, "TODO");

    return ZITI_OK;
}