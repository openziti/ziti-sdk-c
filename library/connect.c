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
#include <posture.h>

#include "zt_internal.h"
#include "utils.h"
#include "endian_internal.h"
#include "win32_compat.h"

static const char *TYPE_BIND = "Bind";
static const char *TYPE_DIAL = "Dial";
static const char *INVALID_SESSION = "Invalid Session";
static const int MAX_CONNECT_RETRY = 3;

#define crypto(func) crypto_secretstream_xchacha20poly1305_##func

struct ziti_conn_req {
    const char *session_type;
    char *service_id;
    ziti_net_session *session;
    ziti_conn_cb cb;
    ziti_dial_opts *dial_opts;
    ziti_listen_opts *listen_opts;

    int retry_count;
    uv_timer_t *conn_timeout;
    bool failed;
};

static void flush_to_client(uv_check_t *fl);

static void ziti_connect_async(uv_async_t *ar);

static int send_fin_message(ziti_connection conn);

static void process_edge_message(struct ziti_conn *conn, message *msg, int code);

int ziti_channel_start_connection(struct ziti_conn *conn);

static void free_handle(uv_handle_t *h) {
    free(h);
}

static ziti_dial_opts *clone_ziti_dial_opts(const ziti_dial_opts *dial_opts) {
    if (dial_opts == NULL) {
        ZITI_LOG(DEBUG, "refuse to clone NULL dial_opts");
        return NULL;
    }
    ziti_dial_opts *c = calloc(1, sizeof(ziti_dial_opts));
    memcpy(c, dial_opts, sizeof(ziti_dial_opts));
    if (dial_opts->identity != NULL) c->identity = strdup(dial_opts->identity);
    if (dial_opts->app_data != NULL) {
        c->app_data = malloc(dial_opts->app_data_sz);
        c->app_data_sz = dial_opts->app_data_sz;
        memcpy(c->app_data, dial_opts->app_data, dial_opts->app_data_sz);
    }
    return c;
}

static void free_ziti_dial_opts(ziti_dial_opts *dial_opts) {
    if (dial_opts == NULL) {
        ZITI_LOG(DEBUG, "refuse to free NULL dial_opts");
        return;
    }
    FREE(dial_opts->identity);
    FREE(dial_opts->app_data);
    free(dial_opts);
}

static ziti_listen_opts *clone_ziti_listen_opts(const ziti_listen_opts *ln_opts) {
    if (ln_opts == NULL) {
        ZITI_LOG(DEBUG, "refuse to clone NULL listen_opts");
        return NULL;
    }
    ziti_listen_opts *c = calloc(1, sizeof(ziti_listen_opts));
    memcpy(c, ln_opts, sizeof(ziti_listen_opts));
    if (ln_opts->identity != NULL) c->identity = strdup(ln_opts->identity);
    return c;
}

static void free_ziti_listen_opts(ziti_listen_opts *ln_opts) {
    if (ln_opts == NULL) {
        ZITI_LOG(DEBUG, "refuse to free NULL listen_opts");
        return;
    }
    FREE(ln_opts->identity);
    free(ln_opts);
}

static void free_conn_req(struct ziti_conn_req *r) {
    if (r->conn_timeout != NULL) {
        uv_close((uv_handle_t *) r->conn_timeout, free_handle);
    }

    if (r->session_type == TYPE_BIND && r->session) {
        free_ziti_net_session(r->session);
        FREE(r->session);
    }

    free_ziti_dial_opts(r->dial_opts);
    free_ziti_listen_opts(r->listen_opts);
    FREE(r->service_id);
    free(r);
};

int close_conn_internal(struct ziti_conn *conn) {
    if (conn->state == Closed && conn->write_reqs == 0) {
        ZITI_LOG(DEBUG, "removing conn_id[%d]", conn->conn_id);
        if (conn->channel) {
            ziti_channel_rem_receiver(conn->channel, conn->conn_id);
        }

        if (conn->conn_req) {
            free_conn_req(conn->conn_req);
        }

        LIST_REMOVE(conn, next);
        FREE(conn->rx);

        if (conn->flusher) {
            conn->flusher->data = NULL;
            uv_close((uv_handle_t *) conn->flusher, free_handle);
            conn->flusher = NULL;
        }

        if (conn->disconnector) {
            uv_close((uv_handle_t *) conn->disconnector, free_handle);
        }
        if (buffer_available(conn->inbound) > 0) {
            ZITI_LOG(WARN, "dumping %zd bytes of undelivered data conn[%d]",
                     buffer_available(conn->inbound), conn->conn_id);
        }
        free_buffer(conn->inbound);
        ZITI_LOG(TRACE, "connection[%d] is being free()'d", conn->conn_id);
        FREE(conn->service);
        FREE(conn->source_identity);
        FREE(conn);
        return 1;
    }
    return 0;
}

void on_write_completed(struct ziti_conn *conn, struct ziti_write_req_s *req, int status) {
    if (req->conn == NULL) {
        ZITI_LOG(DEBUG, "write completed for timed out or closed connection");
        free(req);
        return;
    }
    ZITI_LOG(TRACE, "connection[%d] status %d", conn->conn_id, status);
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
            ZITI_LOG(TRACE, "connection[%d] state is now Closed", conn->conn_id);
        }

        req->cb(conn, status, req->ctx);
    }

    free(req);

    if (conn->write_reqs == 0 && conn->state == CloseWrite) {
        ZITI_LOG(DEBUG, "sending FIN");
        send_fin_message(conn);
    }
}

static int
send_message(struct ziti_conn *conn, uint32_t content, uint8_t *body, uint32_t body_len, struct ziti_write_req_s *wr) {
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
    struct ziti_conn *conn = ctx;
    // check if it is still a valid connection
    // connection may be completed and gone by the time this channel gets connected
    struct ziti_conn *c;
    LIST_FOREACH(c, &ch->ctx->connections, next) {
        if (c == conn) { break; }
    }
    if (c == NULL) {
        ZITI_LOG(WARN, "ch[%d] connection(%p) is gone", ch->id, ctx);
        return;
    }

    // if channel was already selected
    if (conn->channel != NULL) {
        ZITI_LOG(TRACE, "conn[%d] is already using another channel", conn->conn_id);
    }
    else {
        if (status < 0) {
            ZITI_LOG(ERROR, "ch[%d] failed to connect status[%d](%s)", ch->id, status, uv_strerror(status));
        }
        else if (conn->conn_req && conn->conn_req->failed) {
            ZITI_LOG(DEBUG, "request already timed out or closed");
        }
        else { // first channel to connect
            ZITI_LOG(DEBUG, "selected ch[%s] status[%d] for conn_id[%d]", ch->name, status, conn->conn_id);

            conn->channel = ch;
            ziti_channel_start_connection(conn);
        }
    }
}

static void complete_conn_req(struct ziti_conn *conn, int code) {
    if (conn->conn_req && conn->conn_req->cb) {
        conn->conn_req->failed = code != ZITI_OK;
        conn->conn_req->cb(conn, code);
        conn->conn_req->cb = NULL;
        if(conn->conn_req->conn_timeout != NULL) {
            uv_timer_stop(conn->conn_req->conn_timeout);
        }
    } else {
        ZITI_LOG(WARN, "conn[%d] connection attempt was already completed", conn->conn_id);
    }
}

static void connect_timeout(uv_timer_t *timer) {
    struct ziti_conn *conn = timer->data;

    if (conn->state == Connecting) {
        ZITI_LOG(WARN, "ziti connection timed out");
        conn->state = Timedout;
        complete_conn_req(conn, ZITI_TIMEOUT);
    }
    else {
        ZITI_LOG(ERROR, "timeout for connection[%d] in unexpected state[%d]", conn->conn_id, conn->state);
    }
    uv_close((uv_handle_t *) timer, free_handle);
    conn->conn_req->conn_timeout = NULL;
}

static int ziti_connect(struct ziti_ctx *ctx, const ziti_net_session *session, struct ziti_conn *conn) {
    conn->token = session->token;
    conn->channel = NULL;

    if (session->edge_routers == NULL) {
        ZITI_LOG(ERROR, "no edge routers available for service[%s] session[%s]", conn->service, session->id);
        complete_conn_req(conn, ZITI_GATEWAY_UNAVAILABLE);
        return ZITI_GATEWAY_UNAVAILABLE;
    }

    ziti_edge_router **er;
    ziti_channel_t *best_ch = NULL;
    uint64_t best_latency = UINT64_MAX;

    for (er = session->edge_routers; *er != NULL; er++) {
        size_t ch_name_len = strlen((*er)->name) + strlen((*er)->ingress.tls) + 2;
        char *ch_name = malloc(ch_name_len);
        snprintf(ch_name, ch_name_len, "%s@%s", (*er)->name, (*er)->ingress.tls);
        ziti_channel_t *ch = model_map_get(&ctx->channels, ch_name);

        if (ch != NULL && ch->state == Connected) {
            if (ch->latency < best_latency) {
                best_ch = ch;
                best_latency = ch->latency;
            }
        }
        else {
            ZITI_LOG(TRACE, "connecting to %s(%s) for session[%s]", (*er)->name, (*er)->ingress.tls, conn->token);
            ziti_channel_connect(ctx, ch_name, (*er)->ingress.tls, on_channel_connected, conn);
        }
        free(ch_name);
    }

    if (best_ch) {
        ZITI_LOG(DEBUG, "selected ch[%s] for best latency(%ldms)", best_ch->name, best_ch->latency);
        on_channel_connected(best_ch, conn, ZITI_OK);
    }

    return 0;
}

static void connect_get_service_cb(ziti_service* s, ziti_error *err, void *ctx) {
    uv_async_t *ar = ctx;
    struct ziti_conn *conn = ar->data;
    struct ziti_conn_req *req = conn->conn_req;
    struct ziti_ctx *ztx = conn->ziti_ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to load service (%s): %s(%s)", conn->service, err->code, err->message);
    }
    if (s == NULL) {
        complete_conn_req(conn, ZITI_SERVICE_UNAVAILABLE);
    }
    else {
        ZITI_LOG(DEBUG, "got service[%s] id[%s]", s->name, s->id);
        for (int i = 0; s->permissions[i] != NULL; i++) {
            if (strcmp(s->permissions[i], "Dial") == 0) {
                 s->perm_flags |= ZITI_CAN_DIAL;
            }
            if (strcmp(s->permissions[i], "Bind") == 0) {
                s->perm_flags |= ZITI_CAN_BIND;
            }
        }

        model_map_set(&ztx->services, s->name, s);
        req->service_id = strdup(s->id);
        conn->encrypted = s->encryption;
        ziti_connect_async(ar);
    }

    free_ziti_error(err);
}

static void connect_get_net_session_cb(ziti_net_session * s, ziti_error *err, void *ctx) {
    uv_async_t *ar = ctx;
    struct ziti_conn *conn = ar->data;
    struct ziti_conn_req *req = conn->conn_req;
    struct ziti_ctx *ztx = conn->ziti_ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to get session for service[%s]: %s(%s)", conn->service, err->code, err->message);
    }
    if (s == NULL) {
        complete_conn_req(conn, ZITI_SERVICE_UNAVAILABLE);
    }
    else {
        req->session = s;
        s->service_id = strdup(req->service_id);
        if (req->session_type == TYPE_DIAL) {
            ziti_net_session *existing = model_map_get(&ztx->sessions, req->service_id);
            // this happen with concurrent connection requests for the same service (common with browsers)
            if (existing) {
                ZITI_LOG(DEBUG, "found session[%s] for service[%s]", existing->id, conn->service);
                free_ziti_net_session(s);
                free(s);
                req->session = existing;
            } else {
                ZITI_LOG(DEBUG, "got session[%s] for service[%s]", s->id, conn->service);
                model_map_set(&ztx->sessions, s->service_id, s);
            }
        }
        ziti_connect_async(ar);
    }

    free_ziti_error(err);
}

static void ziti_connect_async(uv_async_t *ar) {
    struct ziti_conn *conn = ar->data;
    struct ziti_conn_req *req = conn->conn_req;
    struct ziti_ctx *ztx = conn->ziti_ctx;
    uv_loop_t *loop = ar->loop;

    // find service
    if (req->service_id == NULL) {
        ziti_service *service = model_map_get(&ztx->services, conn->service);

        if (service == NULL) {
            ZITI_LOG(DEBUG, "service[%s] not loaded yet, requesting it", conn->service);
            ziti_ctrl_get_service(&ztx->controller, conn->service, connect_get_service_cb, ar);
            return;
        }
        req->service_id = strdup(service->id);
        conn->encrypted = service->encryption;
    }

    ziti_send_posture_data(ztx);
    if (req->session == NULL && req->session_type == TYPE_DIAL) {
        req->session = model_map_get(&ztx->sessions, req->service_id);
    }

    if (req->session == NULL) {
        ZITI_LOG(DEBUG, "requesting '%s' session for service[%s]", req->session_type, conn->service);
        ziti_ctrl_get_net_session(&ztx->controller, req->service_id, req->session_type, connect_get_net_session_cb, ar);
        return;
    }
    else {
        req->conn_timeout = calloc(1, sizeof(uv_timer_t));
        uv_timer_init(loop, req->conn_timeout);
        req->conn_timeout->data = conn;
        uv_timer_start(req->conn_timeout, connect_timeout, conn->timeout, 0);

        ZITI_LOG(DEBUG, "starting %s connection for service[%s] with session[%s]", req->session_type, conn->service, req->session->id);
        ziti_connect(ztx, req->session, conn);
    }

    uv_close((uv_handle_t *) ar, free_handle);
}

static int do_ziti_dial(ziti_connection conn, const char *service, ziti_dial_opts *dial_opts, ziti_conn_cb conn_cb, ziti_data_cb data_cb) {
    if (conn->state != Initial) {
        ZITI_LOG(ERROR, "conn[%d] can not dial in state[%d]", conn->conn_id, conn->state);
        return ZITI_INVALID_STATE;
    }

    NEWP(req, struct ziti_conn_req);
    conn->service = strdup(service);
    conn->conn_req = req;

    req->session_type = TYPE_DIAL;
    req->cb = conn_cb;

    if (dial_opts != NULL) {
        // clone dial_opts to survive the async request
        req->dial_opts = clone_ziti_dial_opts(dial_opts);

        // override connection timeout if set in dial_opts
        if (dial_opts->connect_timeout_seconds > 0) {
            conn->timeout = dial_opts->connect_timeout_seconds * 1000;
        }
    }

    conn->data_cb = data_cb;
    conn->state = Connecting;


    NEWP(async_cr, uv_async_t);
    uv_async_init(conn->ziti_ctx->loop, async_cr, ziti_connect_async);

    conn->flusher = calloc(1, sizeof(uv_async_t));
    uv_check_init(conn->ziti_ctx->loop, conn->flusher);
    conn->flusher->data = conn;
    uv_unref((uv_handle_t *) conn->flusher);

    async_cr->data = conn;

    return uv_async_send(async_cr);
}

int ziti_dial(ziti_connection conn, const char *service, ziti_conn_cb conn_cb, ziti_data_cb data_cb) {
    return ziti_dial_with_options(conn, service, NULL, conn_cb, data_cb);
}
int ziti_dial_with_options(ziti_connection conn, const char *service, ziti_dial_opts *dial_opts, ziti_conn_cb conn_cb, ziti_data_cb data_cb) {
    return do_ziti_dial(conn, service, dial_opts, conn_cb, data_cb);
}

static void ziti_write_timeout(uv_timer_t *t) {
    struct ziti_write_req_s *req = t->data;
    struct ziti_conn *conn = req->conn;

    conn->write_reqs--;
    req->timeout = NULL;
    req->conn = NULL;

    if (conn->state != Closed) {
        conn->state = Closed;
        req->cb(conn, ZITI_TIMEOUT, req->ctx);
    }

    uv_close((uv_handle_t *) t, free_handle);
}

static void ziti_write_async(uv_async_t *ar) {
    struct ziti_write_req_s *req = ar->data;
    struct ziti_conn *conn = req->conn;

    if (conn->state == Closed) {
        ZITI_LOG(WARN, "got write req for closed conn[%d]", conn->conn_id);
        conn->write_reqs--;

        req->cb(conn, ZITI_CONN_CLOSED, req->ctx);
        free(req);
    }
    else {
        if (req->cb) {
            req->timeout = calloc(1, sizeof(uv_timer_t));
            uv_timer_init(ar->loop, req->timeout);
            req->timeout->data = req;
            uv_timer_start(req->timeout, ziti_write_timeout, conn->timeout, 0);
        }

        if (conn->encrypted) {
            uint32_t crypto_len = req->len + crypto_secretstream_xchacha20poly1305_abytes();
            unsigned char *cipher_text = malloc(crypto_len);
            crypto_secretstream_xchacha20poly1305_push(&conn->crypt_o, cipher_text, NULL, req->buf, req->len, NULL, 0,
                                                       0);
            send_message(conn, ContentTypeData, cipher_text, crypto_len, req);
            free(cipher_text);
        }
        else {
            send_message(conn, ContentTypeData, req->buf, req->len, req);
        }
    }
    uv_close((uv_handle_t *) ar, free_handle);
}

int ziti_write_req(struct ziti_write_req_s *req) {
    NEWP(ar, uv_async_t);
    uv_async_init(req->conn->ziti_ctx->loop, ar, ziti_write_async);
    req->conn->write_reqs++;
    ar->data = req;

    if (uv_thread_self() == req->conn->ziti_ctx->loop_thread) {
        ziti_write_async(ar);
        return 0;
    }
    return uv_async_send(ar);
}

static void ziti_disconnect_cb(ziti_connection conn, ssize_t status, void *ctx) {
    conn->state = Closed;
}

static void ziti_disconnect_async(uv_async_t *ar) {
    struct ziti_conn *conn = ar->data;
    switch (conn->state) {
        case Bound:
        case Accepting:
        case Connected:
        case CloseWrite: {
            NEWP(wr, struct ziti_write_req_s);
            wr->conn = conn;
            wr->cb = ziti_disconnect_cb;
            conn->write_reqs++;
            send_message(conn, ContentTypeStateClosed, NULL, 0, wr);
            break;
        }

        default:
            ZITI_LOG(DEBUG, "conn[%d] can't send StateClosed in state[%d]", conn->conn_id, conn->state);
    }
}

int ziti_disconnect(struct ziti_conn *conn) {
    NEWP(ar, uv_async_t);
    if (conn->channel) {
        uv_async_init(conn->channel->ctx->loop, ar, ziti_disconnect_async);
        ar->data = conn;
        conn->disconnector = ar;
        return uv_async_send(conn->disconnector);
    }
    else {
        conn->state = Closed;
    }
    return ZITI_OK;
}

static void crypto_wr_cb(ziti_connection conn, ssize_t status, void *ctx) {
    if (status < 0) {
        ZITI_LOG(ERROR, "crypto header write failed with status[%zd]", status);
        conn->state = Closed;
        conn->data_cb(conn, NULL, status);
    }
}

int establish_crypto(ziti_connection conn, message *msg) {

    size_t peer_key_len;
    uint8_t *peer_key;
    bool peer_key_sent = message_get_bytes_header(msg, PublicKeyHeader, &peer_key, &peer_key_len);
    if (!peer_key_sent) {
        if (conn->encrypted) {
            ZITI_LOG(ERROR, "conn[%d] failed to establish crypto for encrypted service: did not receive peer key",
                     conn->conn_id);
            return ZITI_CRYPTO_FAIL;
        }
        else {
            // service is not required to be encrypted and hosting side did not send the key
            return ZITI_OK;
        }
    }
    conn->encrypted = true;

    conn->tx = calloc(1, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    conn->rx = calloc(1, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    int rc;
    if (conn->state == Connecting) {
        rc = crypto_kx_client_session_keys(conn->rx, conn->tx, conn->pk, conn->sk, peer_key);
    }
    else if (conn->state == Accepting) {
        rc = crypto_kx_server_session_keys(conn->rx, conn->tx, conn->parent->pk, conn->parent->sk, peer_key);
    }
    else {
        ZITI_LOG(ERROR, "conn[%d] cannot establish crypto in %d state", conn->conn_id, conn->state);
        return ZITI_INVALID_STATE;
    }
    if (rc != 0) {
        ZITI_LOG(ERROR, "conn[%d] failed to establish encryption: crypto error", conn->state);
        return ZITI_CRYPTO_FAIL;
    }
    return ZITI_OK;
}

static int send_crypto_header(ziti_connection conn) {
    if (conn->encrypted) {
        NEWP(wr, struct ziti_write_req_s);
        wr->conn = conn;
        uint8_t *header = calloc(1, crypto_secretstream_xchacha20poly1305_headerbytes());
        wr->buf = header;
        wr->cb = crypto_wr_cb;

        crypto_secretstream_xchacha20poly1305_init_push(&conn->crypt_o, header, conn->tx);
        conn->write_reqs++;
        send_message(conn, ContentTypeData, header, crypto_secretstream_xchacha20poly1305_headerbytes(), wr);
        free(header);
        memset(conn->tx, 0, crypto_secretstream_xchacha20poly1305_KEYBYTES);
        FREE(conn->tx);
    }
    return ZITI_OK;
}

static void flush_to_client(uv_check_t *fl) {
    ziti_connection conn = fl->data;
    if (conn == NULL || conn->state == Closed) {
        uv_check_stop(fl);
        return;
    }

    // if fin was received and all data is flushed, signal EOF
    if (conn->fin_recv && buffer_available(conn->inbound) == 0) {
        conn->data_cb(conn, NULL, ZITI_EOF);
        return;
    }

    ZITI_LOG(TRACE, "conn[%d] flushing %zd bytes to client", conn->conn_id, buffer_available(conn->inbound));

    while (buffer_available(conn->inbound) > 0) {
        uint8_t *chunk;
        ssize_t chunk_len = buffer_get_next(conn->inbound, 16 * 1024, &chunk);
        ssize_t consumed = conn->data_cb(conn, chunk, chunk_len);
        if (consumed < 0) {
            ZITI_LOG(WARN, "client conn[%d] indicated error[%zd] accepting data (%zd bytes buffered)",
                     conn->conn_id, consumed, buffer_available(conn->inbound));
        }
        else if (consumed < chunk_len) {
            buffer_push_back(conn->inbound, (chunk_len - consumed));
            ZITI_LOG(VERBOSE, "client conn[%d] stalled: %zd bytes buffered", conn->conn_id,
                     buffer_available(conn->inbound));
            // client indicated that it cannot accept any more data
            // schedule retry
            if (!uv_is_active((const uv_handle_t *) fl)) {
                uv_check_start(fl, flush_to_client);
            }
            return;
        }
    }
    uv_check_stop(fl);
}

void conn_inbound_data_msg(ziti_connection conn, message *msg) {
    uint8_t *plain_text = NULL;
    if (conn->state == Closed || conn->fin_recv) {
        ZITI_LOG(WARN, "inbound data on closed connection");
        return;
    }

    if (conn->encrypted) {
        PREP(crypto);
        // first message is expected to be peer crypto header
        if (conn->rx != NULL) {
            ZITI_LOG(VERBOSE, "conn[%d] processing crypto header(%d bytes)", conn->conn_id, msg->header.body_len);
            TRY(crypto, msg->header.body_len != crypto_secretstream_xchacha20poly1305_HEADERBYTES);
            TRY(crypto, crypto_secretstream_xchacha20poly1305_init_pull(&conn->crypt_i, msg->body, conn->rx));
            ZITI_LOG(VERBOSE, "conn[%d] processed crypto header", conn->conn_id);
            FREE(conn->rx);
        } else {
            unsigned long long plain_len;
            unsigned char tag;
            if (msg->header.body_len > 0) {
                plain_text = malloc(msg->header.body_len - crypto_secretstream_xchacha20poly1305_ABYTES);
                ZITI_LOG(VERBOSE, "conn[%d] decrypting %d bytes", conn->conn_id, msg->header.body_len);
                TRY(crypto, crypto_secretstream_xchacha20poly1305_pull(&conn->crypt_i,
                                                                       plain_text, &plain_len, &tag,
                                                                       msg->body, msg->header.body_len, NULL, 0));
                ZITI_LOG(VERBOSE, "conn[%d] decrypted %lld bytes", conn->conn_id, plain_len);
                buffer_append(conn->inbound, plain_text, plain_len);
                metrics_rate_update(&conn->ziti_ctx->down_rate, (int64_t) plain_len);
            }
        }

        CATCH(crypto) {
            FREE(plain_text);
            conn->state = Closed;
            conn->data_cb(conn, NULL, ZITI_CRYPTO_FAIL);
            return;
        }
    }
    else if (msg->header.body_len > 0) {
        plain_text = malloc(msg->header.body_len);
        memcpy(plain_text, msg->body, msg->header.body_len);
        buffer_append(conn->inbound, plain_text, msg->header.body_len);
        metrics_rate_update(&conn->ziti_ctx->down_rate, msg->header.body_len);
    }

    int32_t flags;
    if (message_get_int32_header(msg, FlagsHeader, &flags) && (flags & EDGE_FIN)) {
        conn->fin_recv = true;
    }

    flush_to_client(conn->flusher);
}

static void restart_connect(struct ziti_conn *conn) {
    if (!conn->conn_req || conn->state != Connecting) {
        ZITI_LOG(ERROR, "connect retry in invalid state");
        return;
    }

    if (++conn->conn_req->retry_count >= MAX_CONNECT_RETRY) {
        ZITI_LOG(ERROR, "conn[%d] failed to connect after %d retries", conn->conn_id, conn->conn_req->retry_count);
        complete_conn_req(conn, ZITI_SERVICE_UNAVAILABLE);
        return;
    }

    ZITI_LOG(DEBUG, "conn[%d] restarting connect sequence", conn->conn_id);
    conn->channel = NULL;

    NEWP(ar, uv_async_t);
    uv_async_init(conn->ziti_ctx->loop, ar, ziti_connect_async);
    ar->data = conn;
    ziti_connect_async(ar);
}

void connect_reply_cb(void *ctx, message *msg) {
    struct ziti_conn *conn = ctx;
    struct ziti_conn_req *req = conn->conn_req;

    if (req->conn_timeout) {
        uv_timer_stop(req->conn_timeout);
    }

    switch (msg->header.content) {
        case ContentTypeStateClosed:
            if (strncmp(INVALID_SESSION, (const char *) msg->body, msg->header.body_len) == 0) {
                ZITI_LOG(WARN, "conn[%d] session for service[%s] became invalid", conn->conn_id, conn->service);
                ziti_net_session *s = model_map_remove(&conn->ziti_ctx->sessions, req->service_id);
                free_ziti_net_session(s);
                free(s);
                ziti_channel_rem_receiver(conn->channel, conn->conn_id);
                conn->channel = NULL;
                restart_connect(conn);
            }
            else {
                ZITI_LOG(ERROR, "edge conn_id[%d]: failed to %s, reason=%*.*s",
                         conn->conn_id, conn->state == Binding ? "bind" : "connect",
                         msg->header.body_len, msg->header.body_len, msg->body);
                conn->state = Closed;
                complete_conn_req(conn, ZITI_CONN_CLOSED);
            }
            break;

        case ContentTypeStateConnected:
            if (conn->state == Connecting) {
                ZITI_LOG(TRACE, "edge conn_id[%d]: connected.", conn->conn_id);
                int rc = establish_crypto(conn, msg);
                if (rc == ZITI_OK && conn->encrypted) {
                    send_crypto_header(conn);
                }
                conn->state = rc == ZITI_OK ? Connected : Closed;
                complete_conn_req(conn, rc);
            }
            else if (conn->state == Binding) {
                ZITI_LOG(TRACE, "edge conn_id[%d]: bound.", conn->conn_id);
                conn->state = Bound;
                complete_conn_req(conn, ZITI_OK);
            }
            else if (conn->state == Accepting) {
                ZITI_LOG(TRACE, "edge conn_id[%d]: accepted.", conn->conn_id);
                if (conn->encrypted) {
                    send_crypto_header(conn);
                }
                conn->state = Connected;
                complete_conn_req(conn, ZITI_OK);
            }
            else if (conn->state == Closed || conn->state == Timedout) {
                ZITI_LOG(WARN, "received connect reply for closed/timedout connection[%d]", conn->conn_id);
                ziti_disconnect(conn);
            }
            break;

        default:
            ZITI_LOG(WARN, "unexpected content_type[%d] conn_id[%d]", msg->header.content, conn->conn_id);
            ziti_disconnect(conn);
    }
}

int ziti_channel_start_connection(struct ziti_conn *conn) {
    struct ziti_conn_req *req = conn->conn_req;
    ziti_channel_t *ch = conn->channel;

    ZITI_LOG(TRACE, "ch[%d] => Edge Connect request token[%s] conn_id[%d]", ch->id, conn->token,
             conn->conn_id);

    uint32_t content_type;
    switch (conn->state) {
        case Binding:
            content_type = ContentTypeBind;
            break;
        case Connecting:
            content_type = ContentTypeConnect;
            break;
        case Closed:
            ZITI_LOG(WARN, "channel did not connect in time for connection[%d]. ", conn->conn_id);
            return ZITI_OK;
        default:
            ZITI_LOG(ERROR, "connection[%d] is in unexpected state[%d]", conn->conn_id, conn->state);
            return ZITI_WTF;
    }

    ziti_channel_add_receiver(ch, conn->conn_id, conn,
                              (void (*)(void *, message *, int)) process_edge_message);

    int32_t conn_id = htole32(conn->conn_id);
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
            },
            {
                    .header_id = CallerIdHeader,
                    .length = strlen(conn->ziti_ctx->session->identity->name),
                    .value = conn->ziti_ctx->session->identity->name,
            },
            {
                    .header_id = PublicKeyHeader,
                    .length = sizeof(conn->pk),
                    .value = conn->pk,
            },
            // blank hdr_t's to be filled in if needed by options
            {
                    .header_id = -1,
                    .length = 0,
                    .value = NULL,
            },
            {
                    .header_id = -1,
                    .length = 0,
                    .value = NULL,
            },
            {
                    .header_id = -1,
                    .length = 0,
                    .value = NULL,
            }
    };
    int nheaders = 3;
    if (conn->encrypted) {
        crypto_kx_keypair(conn->pk, conn->sk);
        nheaders++;
    }
    switch (conn->state) {
        case Connecting:
            if (req->dial_opts != NULL) {
                if (req->dial_opts->identity != NULL) {
                    headers[nheaders].header_id = TerminatorIdentityHeader;
                    headers[nheaders].value = (uint8_t *) req->dial_opts->identity;
                    headers[nheaders].length = strlen(req->dial_opts->identity);
                    nheaders++;
                }
                if (req->dial_opts->app_data != NULL) {
                    headers[nheaders].header_id = AppDataHeader;
                    headers[nheaders].value = req->dial_opts->app_data;
                    headers[nheaders].length = req->dial_opts->app_data_sz;
                    nheaders++;
                }
            }
            break;
        case Binding:
            if (req->listen_opts != NULL) {
                ziti_listen_opts *opts = req->listen_opts;
                char *identity = opts->identity;
                if (opts->bind_using_edge_identity) {
                    if (opts->identity != NULL) {
                        ZITI_LOG(WARN,
                                 "listen_opts for service[%s] specifies 'identity' and 'bind_using_edge_identity'; ignoring 'identity'",
                                 conn->service);
                    }
                    identity = conn->ziti_ctx->session->identity->name;
                }
                if (identity != NULL) {
                    headers[nheaders].header_id = TerminatorIdentityHeader;
                    headers[nheaders].value = (uint8_t *) identity;
                    headers[nheaders].length = strlen(identity);
                    nheaders++;
                }
                if (opts->terminator_cost > 0) {
                    int32_t cost = htole32(opts->terminator_cost);
                    headers[nheaders].header_id = CostHeader;
                    headers[nheaders].value = (uint8_t *) &cost;
                    headers[nheaders].length = sizeof(cost);
                    nheaders++;
                }
                if (opts->terminator_precedence != PRECEDENCE_DEFAULT) {
                    int32_t precedence = htole32(opts->terminator_precedence);
                    headers[nheaders].header_id = PrecedenceHeader;
                    headers[nheaders].value = (uint8_t *) &precedence;
                    headers[nheaders].length = sizeof(precedence);
                    nheaders++;
                }
            }
            break;
    }
    ziti_channel_send_for_reply(ch, content_type, headers, nheaders, conn->token, strlen(conn->token),
                                connect_reply_cb, conn);

    return ZITI_OK;
}

int ziti_bind(ziti_connection conn, const char *service, ziti_listen_opts *listen_opts, ziti_listen_cb listen_cb, ziti_client_cb on_clt_cb) {
    NEWP(req, struct ziti_conn_req);
    conn->service = strdup(service);
    conn->conn_req = req;

    req->session_type = TYPE_BIND;
    req->cb = listen_cb;

    if (listen_opts != NULL) {
        // clone listen_opts to survive the async request
        req->listen_opts = clone_ziti_listen_opts(listen_opts);

        // override connection timeout if set in listen_opts
        if (listen_opts->connect_timeout_seconds > 0) {
            conn->timeout = listen_opts->connect_timeout_seconds * 1000;
        }
    }

    conn->client_cb = on_clt_cb;
    conn->state = Binding;

    NEWP(async_cr, uv_async_t);
    uv_async_init(conn->ziti_ctx->loop, async_cr, ziti_connect_async);
    async_cr->data = conn;
    return uv_async_send(async_cr);
}

int ziti_accept(ziti_connection conn, ziti_conn_cb cb, ziti_data_cb data_cb) {

    ziti_channel_t *ch = conn->parent->channel;

    conn->channel = ch;
    conn->data_cb = data_cb;

    conn->flusher = calloc(1, sizeof(uv_check_t));
    uv_check_init(conn->ziti_ctx->loop, conn->flusher);
    conn->flusher->data = conn;
    uv_unref((uv_handle_t *) &conn->flusher);

    ziti_channel_add_receiver(ch, conn->conn_id, conn, process_edge_message);

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
    NEWP(req, struct ziti_conn_req);
    req->cb = cb;
    conn->conn_req = req;

    ziti_channel_send_for_reply(ch, content_type, headers, 3, (const uint8_t *) &clt_conn_id, sizeof(clt_conn_id),
                                connect_reply_cb, conn);

    return ZITI_OK;
}

int ziti_process_connect_reqs(ziti_context ztx) {
    ZITI_LOG(WARN, "TODO");

    return ZITI_OK;
}

static int send_fin_message(ziti_connection conn) {
    ziti_channel_t *ch = conn->channel;
    int32_t conn_id = htole32(conn->conn_id);
    int32_t msg_seq = htole32(conn->edge_msg_seq++);
    int32_t flags = htole32(EDGE_FIN);
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
                    .header_id = FlagsHeader,
                    .length = sizeof(flags),
                    .value = (uint8_t *) &flags
            },
    };
    NEWP(wr, struct ziti_write_req_s);
    return ziti_channel_send(ch, ContentTypeData, headers, 3, NULL, 0, wr);
}

int ziti_close_write(ziti_connection conn) {
    if (conn->fin_sent || conn->state == Closed) {
        return ZITI_OK;
    }
    conn->state = CloseWrite;
    if (conn->write_reqs == 0) {
        return send_fin_message(conn);
    }
    return ZITI_OK;
}

static void process_edge_message(struct ziti_conn *conn, message *msg, int code) {

    if (msg == NULL) {
        ZITI_LOG(DEBUG, "conn[%d] is closed due to err[%d](%s)", conn->conn_id, code, ziti_errorstr(code));
        if (conn->state == Connected) {
            conn->data_cb(conn, NULL, code);
        } else if (conn->state == Bound) {
            conn->client_cb(conn, NULL, code);
        }
        conn->state = Closed;
        return;
    }

    int32_t seq;
    int32_t conn_id;
    bool has_seq = message_get_int32_header(msg, SeqHeader, &seq);
    bool has_conn_id = message_get_int32_header(msg, ConnIdHeader, &conn_id);

    ZITI_LOG(TRACE, "conn_id[%d] <= ct[%X] edge_seq[%d] body[%d]", conn->conn_id, msg->header.content, seq,
             msg->header.body_len);

    switch (msg->header.content) {
        case ContentTypeStateClosed:
            ZITI_LOG(VERBOSE, "connection status[%d] conn_id[%d] seq[%d]", msg->header.content, conn_id, seq);
            if (conn->state == Bound) {
                conn->client_cb(conn, NULL, ZITI_CONN_CLOSED);
            }
            else if (conn->state == Connected || conn->state == CloseWrite) {
                conn->data_cb(conn, NULL, ZITI_CONN_CLOSED);
            }
            conn->state = Closed;
            break;

        case ContentTypeData:
            switch (conn->state) {
                case Connected:
                case CloseWrite:
                    conn_inbound_data_msg(conn, msg);
                    break;
                default:
                    ZITI_LOG(WARN, "data[%d bytes] received for connection[%d] in state[%d]",
                             msg->header.body_len, conn_id, conn->state);
            }
            break;

        case ContentTypeDial:
            if (conn->state != Bound) {
                ZITI_LOG(ERROR, "invalid message received");
            }
            uint8_t *app_data = NULL;
            size_t app_data_sz = 0;
            message_get_bytes_header(msg, AppDataHeader, &app_data, &app_data_sz);
            ziti_connection clt;
            ziti_conn_init(conn->ziti_ctx, &clt, app_data);
            uint8_t *source_identity = NULL;
            size_t source_identity_sz = 0;
            bool caller_id_sent = message_get_bytes_header(msg, CallerIdHeader, &source_identity, &source_identity_sz);
            if (caller_id_sent) {
                clt->source_identity = strndup((char *)source_identity, source_identity_sz);
            }
            clt->state = Accepting;
            clt->parent = conn;
            clt->channel = conn->channel;
            clt->dial_req_seq = msg->header.seq;
            clt->encrypted = conn->encrypted;
            if (conn->encrypted) {
                establish_crypto(clt, msg);
            }
            conn->client_cb(conn, clt, ZITI_OK);
            break;

        default:
            ZITI_LOG(ERROR, "conn[%d] received unexpected content_type[%d]", conn_id, msg->header.content);
    }
}
