// Copyright (c) 2022-2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>

#include "message.h"
#include "zt_internal.h"
#include "utils.h"
#include "endian_internal.h"

#if _WIN32
#include "win32_compat.h"
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#define CONNECT_TIMEOUT (20*1000)
#define LATENCY_TIMEOUT (10*1000)
#define LATENCY_INTERVAL (60*1000) /* 1 minute */
#define BACKOFF_TIME 5000 /* 5 seconds */
#define MAX_BACKOFF 5 /* max reconnection timeout: (1 << MAX_BACKOFF) * BACKOFF_TIME = 160 seconds */
#define WRITE_DELAY_WARNING (1000)

#define POOLED_MESSAGE_SIZE (32 * 1024)
#define INBOUND_POOL_SIZE (32)

#define CH_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "ch[%d] " fmt, ch->id, ##__VA_ARGS__)

enum ChannelState {
    Initial,
    Connecting,
    Connected,
    Disconnected,
    Closed,
};

static const char *edge_alpn[] = {
        "ziti-edge",
};

static inline const char *ch_state_str(ziti_channel_t *ch) {
    switch (ch->state) {
        case Initial:
            return to_str(Initial);
        case Connecting:
            return to_str(Connecting);
        case Connected:
            return to_str(Connected);
        case Disconnected:
            return to_str(Disconnected);
        case Closed:
            return to_str(Closed);
    }
    return "unexpected";
}

static const char *get_timeout_cb(ziti_channel_t *ch);

static void reconnect_channel(ziti_channel_t *ch, bool now);

static void reconnect_cb(void *data);

static void on_tls_connect(uv_connect_t *req, int status);

static struct msg_receiver *find_receiver(ziti_channel_t *ch, uint32_t conn_id);

static void on_channel_close(ziti_channel_t *ch, int ziti_err, ssize_t uv_err);

static void send_latency_probe(void *data);

static void ch_connect_timeout(void *data);

static void hello_reply_cb(void *ctx, message *msg, int err);

static void channel_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void on_channel_data(uv_stream_t *s, ssize_t len, const uv_buf_t *buf);
static void process_inbound(ziti_channel_t *ch);
static void on_tls_close(uv_handle_t *s);

static inline void close_connection(ziti_channel_t *ch) {
    tlsuv_stream_t *tls = ch->connection;
    ch->connection = NULL;

    if (tls) {
        CH_LOG(DEBUG, "closing TLS[%p]", tls);
        tlsuv_stream_close(tls, on_tls_close);
    }
}

// global channel sequence
static uint32_t channel_counter = 0;

struct waiter_s {
    uint32_t seq;
    reply_cb cb;
    void *reply_ctx;
};

struct msg_receiver {
    uint32_t id;
    void *receiver;

    void (*receive)(void *receiver, message *m, int code);
};

static void ch_init_stream(ziti_channel_t *ch) {
    assert(ch->connection == NULL);

    ch->connection = calloc(1, sizeof(*ch->connection));
    tlsuv_stream_init(ch->loop, ch->connection, ch->ztx->tlsCtx);
    tlsuv_stream_keepalive(ch->connection, true, 30);
    tlsuv_stream_nodelay(ch->connection, true);
    tlsuv_stream_set_protocols(ch->connection, 1, edge_alpn);
    ch->connection->data = ch;
    ch->reconnect = false;
}

int ziti_channel_prepare(ziti_channel_t *ch) {
    process_inbound(ch);

    // process_inbound() may consume all message buffers from the pool,
    // but it will put ziti connection(s) into `flush` state
    // activating uv_idle_t handle, causing zero-timeout IO
    // and a flush attempt on the next loop iteration
    if (ch->state == Connected) {
        if (pool_has_available(ch->in_msg_pool) || ch->in_next != NULL) {
            tlsuv_stream_read_start(ch->connection, channel_alloc_cb, on_channel_data);
        } else {
            tlsuv_stream_read_stop(ch->connection);
        }
    }
    return 0;
}

static int ziti_channel_init(struct ziti_ctx *ctx, ziti_channel_t *ch, uint32_t id) {
    ch->ztx = ctx;
    ch->loop = ctx->loop;
    ch->id = id;
//    ch->msg_seq = 0;

    char hostname[MAXHOSTNAMELEN];
    size_t hostlen = sizeof(hostname);
    uv_os_gethostname(hostname, &hostlen);

    snprintf(ch->token, sizeof(ch->token), "ziti-sdk-c[%d]@%*.*s", ch->id, (int) hostlen, (int) hostlen, hostname);

    ch->state = Initial;

    ch->name = NULL;
    ch->in_next = NULL;
    ch->in_body_offset = 0;
    ch->incoming = new_buffer();
    ch->in_msg_pool = pool_new(POOLED_MESSAGE_SIZE, INBOUND_POOL_SIZE, (void (*)(void *)) message_free);

    ch->waiters = (model_map){0};

    ch->notify_cb = (ch_notify_state) ziti_on_channel_event;
    ch->notify_ctx = ctx;
    return 0;
}

void ziti_channel_free(ziti_channel_t *ch) {
    if (ch->connection) {
        ch->connection->data = NULL;
        ch->connection = NULL;
    }
    clear_deadline(&ch->deadline);
    free_buffer(ch->incoming);
    pool_destroy(ch->in_msg_pool);
    ch->in_msg_pool = NULL;
    FREE(ch->name);
    FREE(ch->url);
    FREE(ch->version);
    FREE(ch->host);
}

int ziti_close_channels(struct ziti_ctx *ztx, int err) {
    const char *url;
    model_list ch_ids = {0};
    MODEL_MAP_FOR(it, ztx->channels) {
        model_list_append(&ch_ids, model_map_it_key(it));
    }

    MODEL_LIST_FOR(it, ch_ids) {
        url = model_list_it_element(it);
        ziti_channel_t *ch = model_map_get(&ztx->channels, url);
        if (ch != NULL) {
            ZTX_LOG(DEBUG, "closing channel[%s]: %s", url, ziti_errorstr(err));
            ziti_channel_close(ch, err);
        }
    }
    model_list_clear(&ch_ids, NULL);
    return ZITI_OK;
}

static void on_tls_close(uv_handle_t *s) {
    tlsuv_stream_t *tls = (tlsuv_stream_t *) s;
    tlsuv_stream_free(tls);
    free(tls);
}

int ziti_channel_close(ziti_channel_t *ch, int err) {
    if (ch->state != Closed) {
        CH_LOG(INFO, "closing[%s]", ch->name);

        on_channel_close(ch, err, 0);
        ch->state = Closed;
        ziti_on_channel_event(ch, EdgeRouterRemoved, ch->ztx);

        ziti_channel_free(ch);
        free(ch);
    }
    return 0;
}

void ziti_channel_add_receiver(ziti_channel_t *ch, uint32_t id, void *receiver, void (*receive_f)(void *, message *, int)) {
    NEWP(r, struct msg_receiver);
    r->id = id;
    r->receiver = receiver;
    r->receive = receive_f;

    model_map_setl(&ch->receivers, r->id, r);
    CH_LOG(DEBUG, "added receiver[%u]", id);
}

void ziti_channel_rem_receiver(ziti_channel_t *ch, uint32_t id) {
    if (ch == NULL) return;

    struct msg_receiver *r = model_map_removel(&ch->receivers, id);

    if (r) {
        CH_LOG(DEBUG, "removed receiver[%u]", id);
        free(r);
    }
}

bool ziti_channel_is_connected(ziti_channel_t *ch) {
    return ch->state == Connected;
}

uint64_t ziti_channel_latency(ziti_channel_t *ch) {
    return ch->latency;
}

static ziti_channel_t *new_ziti_channel(ziti_context ztx, const char *ch_name, const char *url) {
    ziti_channel_t *ch = calloc(1, sizeof(ziti_channel_t));
    ziti_channel_init(ztx, ch, channel_counter++);
    const ziti_identity *identity = ziti_get_identity(ztx);
    ch->name = strdup(ch_name);
    ch->url = strdup(url);
    CH_LOG(INFO, "(%s) new channel for ztx[%d] identity[%s]", ch->name, ztx->id, identity->name);

    struct tlsuv_url_s ingress;
    tlsuv_parse_url(&ingress, url);

    ch->host = calloc(1, ingress.hostname_len + 1);
    snprintf(ch->host, ingress.hostname_len + 1, "%.*s", (int) ingress.hostname_len, ingress.hostname);
    ch->port = ingress.port;
    model_map_set(&ztx->channels, url, ch);
    return ch;
}

static void check_connecting_state(ziti_channel_t *ch) {
    // verify channel state
    bool reset = false;
    if (ch->deadline.expire_cb == NULL) {
        CH_LOG(DEBUG, "state check: timer not active!");
        reset = true;
    }

    if (ch->deadline.expire_cb != ch_connect_timeout) {
        CH_LOG(DEBUG, "state check: unexpected callback(%s)!", get_timeout_cb(ch));
        reset = true;
    }

    if (ch->deadline.expiration < uv_now(ch->loop)) {
        CH_LOG(DEBUG, "state check: timer is in the past!");
        reset = true;
    }

    if (ch->deadline.expiration - uv_now(ch->loop) > CONNECT_TIMEOUT) {
        CH_LOG(DEBUG, "state check: timer is too far into the future!");
        reset = true;
    }
}

static void token_update_cb(void *ctx, message *m, int status) {
    ziti_channel_t *ch = ctx;
    if (status != ZITI_OK) {
        CH_LOG(ERROR, "failed to update token: %d[%s]", status, ziti_errorstr(status));
    } else if (m->header.content == ContentTypeUpdateTokenSuccess) {
        CH_LOG(DEBUG, "token update success");
    } else if (m->header.content == ContentTypeUpdateTokenFailure) {
        CH_LOG(WARN, "failed to update token: %.*s", m->header.body_len, m->body);
    } else {
        CH_LOG(ERROR, "expected ContentType[%04x]", m->header.content);
    }
}

int ziti_channel_update_token(ziti_channel_t *ch, const char *token) {
    if (ch == NULL) {
        return ZITI_INVALID_STATE;
    }

    if (token == NULL) {
        return ZITI_NOT_AUTHORIZED;
    }

    if (ch->state != Connected) {
        return ZITI_GATEWAY_UNAVAILABLE;
    }

    CH_LOG(DEBUG, "sending token update");
    ziti_channel_send_for_reply(ch, ContentTypeUpdateToken, NULL, 0,
                                (const uint8_t *)token, strlen(token),
                                token_update_cb, ch);
    return ZITI_OK;
}

int ziti_channel_force_connect(ziti_channel_t *ch) {
    if (ch == NULL) {
        return ZITI_INVALID_STATE;
    }

    if (ch->state == Closed) {
        return ZITI_GATEWAY_UNAVAILABLE;
    }

    if (ch->state == Disconnected) {
        reconnect_channel(ch, true);
    }

    return ZITI_OK;
}

int ziti_channel_connect(ziti_context ztx, const char *ch_name, const char *url) {
    ziti_channel_t *ch = model_map_get(&ztx->channels, url);

    if (ch != NULL) {
        ZTX_LOG(DEBUG, "existing ch[%d](%s) found for ingress[%s]", ch->id, ch_state_str(ch), url);
    }
    else {
        ch = new_ziti_channel(ztx, ch_name, url);
        ch->notify_cb(ch, EdgeRouterAdded, ch->notify_ctx);
    }

    if (ch->state == Connecting) {
        check_connecting_state(ch);
    }

    if (ch->state == Initial || ch->state == Disconnected) {
        reconnect_channel(ch, true);
    }
    return ZITI_OK;
}

void on_channel_send(uv_write_t *w, int status) {
    struct ziti_write_req_s *zwreq = w->data;

    ziti_channel_t *ch = zwreq->ch;
    uint64_t now = uv_now(ch->loop);

    // time to get on-wire
    uint64_t write_delay = now - zwreq->start_ts;
    if (write_delay > WRITE_DELAY_WARNING && ch->last_write_delay < WRITE_DELAY_WARNING) {
        CH_LOG(WARN, "write delay = %" PRIu64 ".%03" PRIu64 " q=%zd qs=%zd",
               write_delay / 1000L, write_delay % 1000L, ch->out_q, ch->out_q_bytes);
    } else {
        CH_LOG(TRACE, "write delay = %" PRIu64 ".%03" PRIu64 "d q=%ld qs=%ld",
               write_delay / 1000L, write_delay % 1000L, ch->out_q, ch->out_q_bytes);
    }
    ch->last_write = now;
    ch->last_write_delay = write_delay;
    ch->out_q--;
    ch->out_q_bytes -= zwreq->message->msgbuflen;

    pool_return_obj(zwreq->message);
    zwreq->message = NULL;

    if (zwreq->conn) {
        on_write_completed(zwreq->conn, zwreq, status);
    } else {
        free(zwreq);
    }

    if (status < 0) {
        CH_LOG(ERROR, "write failed [%d/%s]", status, uv_strerror(status));
        if (ch->out_q == 0) {
            on_channel_close(ch, ZITI_CONNABORT, status);
        }
    }

    free(w);
}

int ziti_channel_send_message(ziti_channel_t *ch, message *msg, struct ziti_write_req_s *ziti_write) {
    uv_buf_t buf = uv_buf_init((char *) msg->msgbufp, msg->msgbuflen);
    message_set_seq(msg, &ch->msg_seq);
    CH_LOG(TRACE, "=> ct[%s] seq[%d] len[%d]", content_type_id(msg->header.content),
           msg->header.seq, msg->header.body_len);

    NEWP(req, uv_write_t);
    if (ziti_write == NULL) {
        ziti_write = calloc(1, sizeof(struct ziti_write_req_s));
    }
    ziti_write->ch = ch;

    req->data = ziti_write;
    ziti_write->message = msg;
    ziti_write->start_ts = uv_now(ch->loop);
    ch->out_q++;
    ch->out_q_bytes += buf.len;
    int rc = tlsuv_stream_write(req, ch->connection, &buf, on_channel_send);
    if (rc != 0) {
        on_channel_send(req, rc);
        return ZITI_GATEWAY_UNAVAILABLE;
    }
    return 0;
}

int ziti_channel_send(ziti_channel_t *ch, uint32_t content, const hdr_t *hdrs, int nhdrs, const uint8_t *body,
                      uint32_t body_len,
                      struct ziti_write_req_s *ziti_write) {
    message *m = message_new(NULL, content, hdrs, nhdrs, body_len);
    message_set_seq(m, &ch->msg_seq);
    CH_LOG(TRACE, "=> ct[%s] seq[%d] len[%d]", content_type_id(content), m->header.seq, body_len);
    memcpy(m->body, body, body_len);

    return ziti_channel_send_message(ch, m, ziti_write);
}

void ziti_channel_remove_waiter(ziti_channel_t *ch, struct waiter_s *waiter) {
    if (ch && waiter) {
        struct waiter_s *w = model_map_removel(&ch->waiters, (long)waiter->seq);
        assert(w == waiter);
        free(waiter);
    }
}

struct waiter_s *ziti_channel_send_for_reply(ziti_channel_t *ch, uint32_t content,
                                             const hdr_t *hdrs, int nhdrs,
                                             const uint8_t *body, uint32_t body_len,
                                             reply_cb rep_cb, void *reply_ctx) {
    assert(rep_cb != NULL);

    struct waiter_s *result = NULL;
    message *m = message_new(NULL, content, hdrs, nhdrs, body_len);
    message_set_seq(m, &ch->msg_seq);
    memcpy(m->body, body, body_len);

    uint32_t seq = m->header.seq;

    int rc = ziti_channel_send_message(ch, m, NULL);

    if (rc == ZITI_OK) {
        NEWP(w, struct waiter_s);
        w->seq = seq;
        w->cb = rep_cb;
        w->reply_ctx = reply_ctx;
        model_map_setl(&ch->waiters, (long)w->seq, w);
        result = w;
    } else {
        rep_cb(reply_ctx, NULL, rc);
    }

    return result;
}

static struct msg_receiver *find_receiver(ziti_channel_t *ch, uint32_t conn_id) {
    struct msg_receiver *c = model_map_getl(&ch->receivers, conn_id);
    return c;
}


static bool is_edge(uint32_t content) {
    switch (content) {
        case ContentTypeConnect:
        case ContentTypeStateConnected:
        case ContentTypeStateClosed:
        case ContentTypeData:
        case ContentTypeDial:
        case ContentTypeDialSuccess:
        case ContentTypeDialFailed:
        case ContentTypeBind:
        case ContentTypeUnbind:
        case ContentTypeConnInspectRequest:
            return true;
        default:
            return false;
    }
}

static void dispatch_message(ziti_channel_t *ch, message *m) {
    struct waiter_s *w = NULL;

    uint32_t reply_to;
    bool is_reply = message_get_int32_header(m, ReplyForHeader, (int32_t*)&reply_to);

    uint32_t ct = m->header.content;
    if (is_reply) {
        w = model_map_removel(&ch->waiters, (long)reply_to);

        if (w) {
            w->cb(w->reply_ctx, m, 0);
            free(w);
            pool_return_obj(m);
            return;
        }

        CH_LOG(ERROR, "could not find waiter for reply_to = %d ct[%s]", reply_to, content_type_id(ct));
    }

    if (ch->state == Connecting) {
        if (ct == ContentTypeResultType) {
            CH_LOG(WARN, "lost hello reply waiter");
            hello_reply_cb(ch, m, ZITI_OK);
            pool_return_obj(m);
            return;
        }

        CH_LOG(ERROR, "received unexpected message ct[%s] in Connecting state", content_type_id(ct));
    }

    if (is_edge(ct)) {
        int32_t conn_id = 0;
        bool has_conn_id = message_get_int32_header(m, ConnIdHeader, &conn_id);
        struct msg_receiver *conn = has_conn_id ? find_receiver(ch, conn_id) : NULL;

        if (conn) {
            conn->receive(conn->receiver, m, ZITI_OK);
        } else {
            if (ct == ContentTypeConnInspectRequest) {
                char msg[128];
                size_t len = snprintf(msg, sizeof(msg), "invalid conn id [%d]", conn_id);
                message *reply = new_inspect_result(m->header.seq, conn_id, ConnTypeInvalid, msg, len);
                ziti_channel_send_message(ch, reply, NULL);
            } else if (ct != ContentTypeStateClosed) {
                // close confirmation is OK if connection is gone already
                CH_LOG(WARN, "received message without conn_id or for unknown connection ct[%s] conn_id[%d]",
                       content_type_id(ct), conn_id);
                // notify ER that this connection is not available
                ch_send_conn_closed(ch, conn_id);
            }
            pool_return_obj(m);
        }
    } else {
        CH_LOG(WARN, "unsupported content type [%s]", content_type_id(ct));
        pool_return_obj(m);
    }
}

static void process_inbound(ziti_channel_t *ch) {
    uint8_t *ptr;
    ssize_t len;
    int rc = 0;
    do {
        if (ch->in_next == NULL && pool_has_available(ch->in_msg_pool)) {
            if (buffer_available(ch->incoming) < HEADER_SIZE) {
                break;
            }

            uint8_t header_buf[HEADER_SIZE];
            size_t header_read = 0;

            while (header_read < HEADER_SIZE) {
                len = buffer_get_next(ch->incoming, HEADER_SIZE - header_read, &ptr);
                memcpy(header_buf + header_read, ptr, len);
                header_read += len;
            }

            assert(header_read == HEADER_SIZE);


            rc = message_new_from_header(ch->in_msg_pool, header_buf, &ch->in_next);
            if (rc != ZITI_OK) break;
            ch->in_body_offset = 0;

            CH_LOG(TRACE, "<= ct[%s] seq[%d] len[%d] hdrs[%d]", content_type_id(ch->in_next->header.content),
                   ch->in_next->header.seq,
                   ch->in_next->header.body_len, ch->in_next->header.headers_len);
        }

        if (ch->in_next == NULL) { break; }

        // to complete the message need to read headers_len + body_len - (whatever was read already)
        uint32_t total = ch->in_next->header.body_len + ch->in_next->header.headers_len;
        uint32_t want = total - ch->in_body_offset;
        len = buffer_get_next(ch->incoming, want, &ptr);
        CH_LOG(TRACE, "completing msg seq[%d] body+hrds=%d+%d, in_offset=%zd, want=%d, got=%zd", ch->in_next->header.seq,
               ch->in_next->header.body_len, ch->in_next->header.headers_len, ch->in_body_offset, want, len);

        if (len == -1) {
            break;
        }
        if (len > 0) {
            memcpy(ch->in_next->headers + ch->in_body_offset, ptr, (size_t) len);
            ch->in_body_offset += len;

            if (ch->in_body_offset == total) {
                message *msg = ch->in_next;
                ch->in_next = NULL;

                CH_LOG(TRACE, "message is complete seq[%d] ct[%s]",
                       msg->header.seq, content_type_id(msg->header.content));

                rc = parse_hdrs(msg->headers, msg->header.headers_len, &msg->hdrs);
                if (rc < 0) {
                    pool_return_obj(msg);
                    CH_LOG(ERROR, "failed to parse incoming message: %s", ziti_errorstr(rc));
                    break;
                }
                msg->nhdrs = rc;
                rc = 0;
                dispatch_message(ch, msg);
            }
        }
    } while (1);

    buffer_cleanup(ch->incoming);
    if (rc != 0) {
        on_channel_close(ch, rc, 0);
    }
}

static void latency_reply_cb(void *ctx, message *reply, int err) {
    ziti_channel_t *ch = ctx;

    if (err) {
        CH_LOG(DEBUG, "latency probe was canceled: %d(%s)", err, ziti_errorstr(err));
        ch->latency = UINT64_MAX;
        return;
    }

    uint64_t ts;
    if (reply->header.content == ContentTypeResultType &&
        message_get_uint64_header(reply, LatencyProbeTime, &ts)) {
        ch->latency = uv_now(ch->loop) - ts;
        CH_LOG(VERBOSE, "latency is now %llu", (unsigned long long)ch->latency);
    } else {
        CH_LOG(WARN, "invalid latency probe result ct[%s]", content_type_id(reply->header.content));
    }
    ztx_set_deadline(ch->ztx, LATENCY_INTERVAL, &ch->deadline, send_latency_probe, ch);
}

static void latency_timeout(void *data) {
    ziti_channel_t *ch = data;
    if (uv_now(ch->loop) - MAX(ch->last_read, ch->last_write) < LATENCY_TIMEOUT) {
        CH_LOG(DEBUG, "latency timeout on active channel, extending timeout");
        ztx_set_deadline(ch->ztx, LATENCY_TIMEOUT, &ch->deadline, latency_timeout, ch);
    } else {
        CH_LOG(ERROR, "no read/write traffic on channel since before latency probe was sent, closing channel");

        ziti_channel_remove_waiter(ch, ch->latency_waiter);
        ch->latency_waiter = NULL;
        ch->latency = UINT64_MAX;

        on_channel_close(ch, ZITI_TIMEOUT, UV_ETIMEDOUT);
    }
}

static void send_latency_probe(void *data) {
    ziti_channel_t *ch = data;
    uint64_t now = htole64(uv_now(ch->loop));
    hdr_t headers[] = {
            {
                    .header_id = LatencyProbeTime,
                    .length = sizeof(now),
                    .value = (uint8_t *) &now,
            }
    };

    ztx_set_deadline(ch->ztx, LATENCY_TIMEOUT, &ch->deadline, latency_timeout, ch);
    ch->latency_waiter = ziti_channel_send_for_reply(ch, ContentTypeLatencyType,
                                                     headers, 1, NULL, 0, latency_reply_cb, ch);

}

static void hello_reply_cb(void *ctx, message *msg, int err) {
    int cb_code = ZITI_OK;
    ziti_channel_t *ch = ctx;
    bool success = false;

    if (msg && msg->header.content == ContentTypeResultType) {
        message_get_bool_header(msg, ResultSuccessHeader, &success);
    }
    else if (msg) {
        CH_LOG(ERROR, "unexpected Hello response ct[%s]", content_type_id(msg->header.content));
        cb_code = ZITI_GATEWAY_UNAVAILABLE;
    }
    else {
        CH_LOG(ERROR, "failed to receive Hello response due to %d(%s)", err, ziti_errorstr(err));
        cb_code = ZITI_GATEWAY_UNAVAILABLE;
    }

    if (success) {
        const char *erVersion = "<unknown>";
        size_t erVersionLen = strlen(erVersion);
        message_get_bytes_header(msg, HelloVersionHeader, (const uint8_t **) &erVersion, &erVersionLen);
        CH_LOG(INFO, "connected. EdgeRouter version: %.*s", (int) erVersionLen, erVersion);
        ch->state = Connected;
        FREE(ch->version);
        ch->version = calloc(1, erVersionLen + 1);
        memcpy(ch->version, erVersion, erVersionLen);
        ch->notify_cb(ch, EdgeRouterConnected, ch->notify_ctx);
        ch->latency = uv_now(ch->loop) - ch->latency;
        ztx_set_deadline(ch->ztx, LATENCY_INTERVAL, &ch->deadline, send_latency_probe, ch);
    } else {
        if (msg) {
            CH_LOG(ERROR, "connect rejected: %d %*s", success, msg->header.body_len, msg->body);
        }

        on_channel_close(ch, ZITI_CONNABORT, 0);
    }
}

static void send_hello(ziti_channel_t *ch, const char *token) {
    uint8_t true_val = 1;
    hdr_t headers[] = {
            {
                    .header_id = SessionTokenHeader,
                    .length = strlen(token),
                    .value = (uint8_t *)token
            },
            {
                .header_id = SupportsInspectHeader,
                .length = sizeof(true_val),
                .value = &true_val,
            },
    };
    ch->latency = uv_now(ch->loop);
    ziti_channel_send_for_reply(ch, ContentTypeHelloType, headers, 2, ch->token, strlen(ch->token), hello_reply_cb, ch);
}


static void ch_connect_timeout(void *data) {
    ziti_channel_t *ch = data;
    CH_LOG(ERROR, "connect timeout");

    if (ch->connection && ch->connection->conn_req == NULL) {
        // diagnostics
        CH_LOG(WARN, "diagnostics: no conn_req in connect timeout");
    }

    on_channel_close(ch, ZITI_TIMEOUT, UV_ETIMEDOUT);
}

static void reconnect_cb(void *data) {
    ziti_channel_t *ch = data;
    ziti_context ztx = ch->ztx;

    if (ziti_get_api_session_token(ztx) == NULL) {
        CH_LOG(INFO, "ziti context is not fully authenticated (auth_state[%d]), delaying re-connect",
               ztx->auth_state);
        reconnect_channel(ch, false);
    } else if (ch->connection != NULL) {
        CH_LOG(DEBUG, "connection still closing, deferring reconnect");
        ch->reconnect = true;
    } else {
        ch->msg_seq = 0;

        uv_connect_t *req = calloc(1, sizeof(uv_connect_t));
        req->data = ch;

        ch->state = Connecting;
        ch_init_stream(ch);

        CH_LOG(DEBUG, "connecting to %s", ch->url);

        int rc = tlsuv_stream_connect(req, ch->connection, ch->host, ch->port, on_tls_connect);
        if (rc != 0) {
            on_tls_connect(req, rc);
        } else {
            ztx_set_deadline(ch->ztx, CONNECT_TIMEOUT, &ch->deadline, ch_connect_timeout, ch);
        }
    }
}

static void reconnect_channel(ziti_channel_t *ch, bool now) {
    if (ch->state == Closed) {
        CH_LOG(DEBUG, "not reconnecting closed channel");
        return;
    }

    uint64_t timeout = 0;
    if (!now) {

        if (ch->deadline.expire_cb == reconnect_cb) {
            // reconnect is already scheduled
            return;
        }

        ch->reconnect_count++;
        int backoff = MIN(ch->reconnect_count, MAX_BACKOFF);

        uint32_t random;
        uv_random(ch->loop, NULL, &random, sizeof(random), 0, NULL);

        timeout = random % ((1U << backoff) * BACKOFF_TIME);
        CH_LOG(INFO, "reconnecting in %" PRIu64 "ms (attempt = %d)", timeout, ch->reconnect_count);
    } else {
        CH_LOG(INFO, "reconnecting NOW");
    }
    ztx_set_deadline(ch->ztx, timeout, &ch->deadline, reconnect_cb, ch);
}

static void on_channel_close(ziti_channel_t *ch, int ziti_err, ssize_t uv_err) {
    ziti_context ztx = ch->ztx;

    if (ch->state == Closed || ch->state == Disconnected) {
        return;
    }

    if (ch->state == Connected) {
        ch->notify_cb(ch, EdgeRouterDisconnected, ch->notify_ctx);
    }
    ch->state = Disconnected;

    ch->latency = UINT64_MAX;
    clear_deadline(&ch->deadline);

    model_map_iter it = model_map_iterator(&ch->waiters);
    while (it != NULL) {
        struct waiter_s *w = model_map_it_value(it);
        it = model_map_it_remove(it);
        w->cb(w->reply_ctx, NULL, ziti_err);
        free(w);
    }

    it = model_map_iterator(&ch->receivers);
    while (it != NULL) {
        struct msg_receiver *con = model_map_it_value(it);
        it = model_map_it_remove(it);
        con->receive(con->receiver, NULL, (int) ziti_err);
        free(con);
    }

    // dump all buffered data
    free_buffer(ch->incoming);
    ch->incoming = new_buffer();

    if (ch->in_next) { // discard partially read message
        pool_return_obj(ch->in_next);
        ch->in_next = NULL;
    }

    close_connection(ch);

    if (ziti_err == ZITI_DISABLED || ziti_err == ZITI_GATEWAY_UNAVAILABLE) {
        return;
    }

    if (uv_err == UV_EOF) {
        ZTX_LOG(VERBOSE, "edge router closed connection, trying to refresh api session");
        ziti_force_api_session_refresh(ch->ztx);
    }

    reconnect_channel(ch, ch->reconnect);
    ch->reconnect = false;
}

static void channel_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    tlsuv_stream_t *tls = (tlsuv_stream_t *) handle;
    ziti_channel_t *ch = tls->data;
    if (ch->in_next || pool_has_available(ch->in_msg_pool)) {
        buf->base = (char *) malloc(suggested_size);
        if (buf->base == NULL) {
            ZITI_LOG(ERROR, "failed to allocate %zd bytes. Prepare for crash", suggested_size);
            buf->len = 0;
        } else {
            buf->len = suggested_size;
        }
    } else {
        CH_LOG(DEBUG, "message pool is empty. stop reading until available");

        buf->len = 0;
        buf->base = NULL;
    }
}

static void on_channel_data(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    tlsuv_stream_t *tls = (tlsuv_stream_t *) s;
    ziti_channel_t *ch = tls->data;

    if (len == UV_ENOBUFS) {
        tlsuv_stream_read_stop(tls);
        CH_LOG(VERBOSE, "blocked until messages are processed");
        return;
    }

    if (len < 0) {
        free(buf->base);
        CH_LOG(INFO, "channel disconnected [%zd/%s]", len, uv_strerror(len));
        // propagate close
        on_channel_close(ch, ZITI_CONNABORT, len);
        return;
    }

    if (len == 0) {
        // sometimes SSL message has no payload
        CH_LOG(TRACE, "read no data");
        free(buf->base);
        return;
    }

    CH_LOG(TRACE, "on_data [len=%zd]", len);
    ch->last_read = uv_now(ch->loop);
    buffer_append(ch->incoming, buf->base, (uint32_t) len);
    process_inbound(ch);
}

static void on_tls_connect(uv_connect_t *req, int status) {
    tlsuv_stream_t *tls = (tlsuv_stream_t *)req->handle;

    // connect request was cancelled via tlsuv_stream_close
    // cleanup in close callback
    if (status == UV_ECANCELED || tls->data == NULL) {
        goto done;
    }

    ziti_channel_t *ch = tls->data;
    assert(ch);

    if (tls != ch->connection) {
        // this should never happen but handle it anyway -- close connected tls stream
        CH_LOG(ERROR, "invalid state, mismatch req->conn[%p] != ch->conn[%p]", tls, ch->connection);
        tls->data = NULL;
        tlsuv_stream_close(tls, on_tls_close);
        goto done;
    }

    if (status == 0) {
        const char *token = ziti_get_api_session_token(ch->ztx);
        if (token != NULL) {
            CH_LOG(DEBUG, "connected alpn[%s]", tlsuv_stream_get_protocol(tls));
            tlsuv_stream_read_start(tls, channel_alloc_cb, on_channel_data);
            ch->reconnect_count = 0;
            send_hello(ch, token);
        } else {
            CH_LOG(WARN, "api session invalidated, while connecting");
            on_channel_close(ch, ZITI_CONNABORT, 0);
        }
    } else {
        CH_LOG(ERROR, "failed to connect to ER[%s] [%d/%s]", ch->name, status, uv_strerror(status));
        on_channel_close(ch, ZITI_CONNABORT, status);
    }
    done:
    free(req);
}



#define TIMEOUT_CALLBACKS(XX) \
XX(latency_timeout) \
XX(ch_connect_timeout) \
XX(reconnect_cb)    \
XX(send_latency_probe)

static const char *get_timeout_cb(ziti_channel_t *ch) {
#define to_lbl(n) if (ch->deadline.expire_cb == (n)) return #n;

    TIMEOUT_CALLBACKS(to_lbl)

    return "unknown";
}

static void on_posture_update_reply(void *ctx, message *m, int status) {
    ziti_channel_t *ch = ctx;
    if (status != ZITI_OK) {
        CH_LOG(ERROR, "failed to update posture: %d[%s]", status, ziti_errorstr(status));
    } else {
        CH_LOG(INFO, "received ContentType[%04x]", m->header.content);
    }
}

int ziti_channel_update_posture(ziti_channel_t *ch, const uint8_t *data, size_t len) {
    if (ch->state == Connected) {
        ziti_channel_send(ch, ContentTypePostureResponse, NULL, 0, data, len, NULL);
        return ZITI_OK;
    }

    return ZITI_GATEWAY_UNAVAILABLE;
}

int ch_send_conn_closed(ziti_channel_t *ch, uint32_t conn_id) {
    hdr_t hdr = (hdr_t) {
            .header_id = ConnIdHeader,
            .length = sizeof(conn_id),
            .value = (const uint8_t *) &conn_id,
    };

    return ziti_channel_send(ch, ContentTypeStateClosed, &hdr, 1, NULL, 0, NULL);
}
