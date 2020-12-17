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
#include <http_parser.h>
#include <assert.h>

#include "zt_internal.h"
#include "utils.h"
#include "endian_internal.h"
#include "win32_compat.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#define BACKOFF_TIME 3000 /* 3 seconds */
#define MAX_BACKOFF 5 /* max reconnection timeout: (1 << 5) * BACKOFF_TIME = 96 seconds */

enum ChannelState {
    Initial,
    Connecting,
    Connected,
    Disconnected,
    Closed,
};

static void reconnect_channel(ziti_channel_t *ch);

static void on_channel_connect_internal(uv_connect_t *req, int status);

static void on_write(uv_write_t *req, int status);

static void async_write(uv_async_t *ar);

static struct msg_receiver *find_receiver(ziti_channel_t *ch, uint32_t conn_id);

struct async_write_req {
    uv_buf_t buf;
    ziti_channel_t *ch;
};

struct waiter_s {
    int32_t seq;
    reply_cb cb;
    void *reply_ctx;

    LIST_ENTRY(waiter_s) next;
};

struct ch_conn_req {
    ch_connect_cb cb;
    void *ctx;
};

struct msg_receiver {
    int id;
    void *receiver;

    void (*receive)(void *receiver, message *m, int code);

    LIST_ENTRY(msg_receiver) _next;
};

static int ziti_channel_init(struct ziti_ctx *ctx, ziti_channel_t *ch, uint32_t id, tls_context *tls) {
    ch->ctx = ctx;
    ch->loop = ctx->loop;
    ch->id = id;
    ch->msg_seq = -1;

    char hostname[MAXHOSTNAMELEN];
    size_t hostlen = sizeof(hostname);
    uv_os_gethostname(hostname, &hostlen);

    snprintf(ch->token, sizeof(ch->token), "ziti-sdk-c[%d]@%*.*s", ch->id, (int) hostlen, (int) hostlen, hostname);

    ch->state = Initial;
    // 32 concurrent connect requests for the same channel is probably enough
    ch->conn_reqs = calloc(32, sizeof(struct ch_conn_req *));
    ch->conn_reqs_n = 0;

    ch->name = NULL;
    ch->in_next = NULL;
    ch->in_body_offset = 0;
    ch->incoming = new_buffer();

    LIST_INIT(&ch->receivers);
    LIST_INIT(&ch->waiters);

    uv_mbed_init(ch->loop, &ch->connection, tls);
    uv_mbed_keepalive(&ch->connection, true, 60);
    uv_mbed_nodelay(&ch->connection, true);
    ch->connection._stream.data = ch;

    ch->notify_cb = ziti_on_channel_event;
    ch->notify_ctx = ctx;
    return 0;
}

void ziti_channel_free(ziti_channel_t* ch) {
    free(ch->conn_reqs);
    free_buffer(ch->incoming);
    FREE(ch->name);
    FREE(ch->version);
    FREE(ch->host);
}

int ziti_close_channels(struct ziti_ctx *ziti) {
    ziti_channel_t *ch;
    const char *url;
    MODEL_MAP_FOREACH(url, ch, &ziti->channels) {
        ziti_channel_close(ch);
    }
    return ZITI_OK;
}

static void close_handle_cb(uv_handle_t *h) {
    uv_mbed_t *mbed = (uv_mbed_t *) h;
    ziti_channel_t *ch = mbed->_stream.data;

    uv_mbed_free(mbed);
    ziti_channel_free(ch);
    free(ch);
}

int ziti_channel_close(ziti_channel_t *ch) {
    int r = 0;
    if (ch->state != Closed) {
        ZITI_LOG(INFO, "closing ch[%d](%s)", ch->id, ch->name);
        r = uv_mbed_close(&ch->connection, close_handle_cb);
        uv_timer_stop(&ch->latency_timer);
        uv_close((uv_handle_t *) &ch->latency_timer, NULL);
        ch->state = Closed;
    }
    return r;
}

void ziti_channel_add_receiver(ziti_channel_t *ch, int id, void *receiver, void (*receive_f)(void *, message *, int)) {
    NEWP(r, struct msg_receiver);
    r->id = id;
    r->receiver = receiver;
    r->receive = receive_f;

    LIST_INSERT_HEAD(&ch->receivers, r, _next);
    ZITI_LOG(DEBUG, "ch[%d] added receiver[%d]", ch->id, id);
}

void ziti_channel_rem_receiver(ziti_channel_t *ch, int id) {
    struct msg_receiver *r = find_receiver(ch, id);

    if (r) {
        LIST_REMOVE(r, _next);
        ZITI_LOG(DEBUG, "ch[%d] removed receiver[%d]", ch->id, id);
        free(r);
    }
}

bool ziti_channel_is_connected(ziti_channel_t *ch) {
    return ch->state == Connected;
}

int ziti_channel_connect(ziti_context ztx, const char *ch_name, const char *url, ch_connect_cb cb, void *cb_ctx) {
    ziti_channel_t *ch = model_map_get(&ztx->channels, ch_name);

    if (ch != NULL) {
        ZITI_LOG(DEBUG, "existing channel found for ingress[%s]", url);

        if (ch->state == Connected) {
            cb(ch, cb_ctx, ZITI_OK);
        }
        else if (ch->state == Connecting || ch->state == Initial) {
            // not connected yet, add to the callbacks
            if (cb != NULL) {
                NEWP(r, struct ch_conn_req);
                r->cb = cb;
                r->ctx = cb_ctx;
                ch->conn_reqs[ch->conn_reqs_n++] = r;
            }
        }
        else if (ch->state == Disconnected) {
            if (cb) {
                cb(ch, cb_ctx, UV_ENOTCONN);
            }
            return ZITI_GATEWAY_UNAVAILABLE;
        }
        else {
            ZITI_LOG(ERROR, "should not be here: %s", ziti_errorstr(ZITI_WTF));
            return ZITI_WTF;
        }
        return ZITI_OK;
    }

    ch = calloc(1, sizeof(ziti_channel_t));
    ziti_channel_init(ztx, ch, ztx->ch_counter++, ztx->tlsCtx);
    ch->name = strdup(ch_name);
    ZITI_LOG(INFO, "opening new channel for ingress[%s] ch[%d]", ch->name, ch->id);

    struct http_parser_url ingress;
    http_parser_url_init(&ingress);
    http_parser_parse_url(url, strlen(url), 0, &ingress);

    char host[128];
    int hostlen = ingress.field_data[UF_HOST].len;
    int hostoffset = ingress.field_data[UF_HOST].off;
    snprintf(host, sizeof(host), "%*.*s", hostlen, hostlen, url + hostoffset);

    ch->host = strdup(host);
    ch->port = ingress.port;
    model_map_set(&ztx->channels, ch->name, ch);

    uv_connect_t *req = calloc(1, sizeof(uv_connect_t));
    req->data = ch;

    if (cb != NULL) {
        NEWP(r, struct ch_conn_req);
        r->cb = cb;
        r->ctx = cb_ctx;
        ch->conn_reqs[ch->conn_reqs_n++] = r;
    }

    ch->state = Connecting;

    uv_mbed_connect(req, &ch->connection, ch->host, ch->port, on_channel_connect_internal);
    return ZITI_OK;
}

void on_channel_send(uv_write_t *w, int status) {
    struct ziti_write_req_s *ziti_write = w->data;

    if (ziti_write != NULL) {
        free(ziti_write->payload);
        on_write_completed(ziti_write->conn, ziti_write, status);
    }

    free(w);
}

int ziti_channel_send(ziti_channel_t *ch, uint32_t content, const hdr_t *hdrs, int nhdrs, const uint8_t *body,
                      uint32_t body_len,
                      struct ziti_write_req_s *ziti_write) {
    header_t header;
    header_init(&header, ch->msg_seq++);

    ZITI_LOG(TRACE, "ch[%d]=> ct[%x] seq[%d] len[%d]", ch->id, content, header.seq, body_len);
    header.content = content;
    header.body_len = body_len;

    uint32_t hdrs_len = 0;
    for (int i = 0; i < nhdrs; i++) {
        hdrs_len += sizeof(uint32_t) * 2 + hdrs[i].length; // header id + val(length) + length
    }
    header.headers_len = hdrs_len;

    unsigned int msg_size = body_len + HEADER_SIZE + hdrs_len;
    uint8_t *msg_buf = malloc(msg_size);
    header_to_buffer(&header, msg_buf);

    uint8_t *p = msg_buf + HEADER_SIZE;
    for (int i = 0; i < nhdrs; i++) {
        p = write_hdr(&hdrs[i], p);
    }
    assert(p == msg_buf + HEADER_SIZE + hdrs_len);
    memcpy(p, body, body_len);

    uv_buf_t buf = uv_buf_init(msg_buf, msg_size);
    NEWP(req, uv_write_t);
    req->data = ziti_write;
    ziti_write->payload = msg_buf;
    return uv_mbed_write(req, &ch->connection, &buf, on_channel_send);
}

void ziti_channel_remove_waiter(ziti_channel_t *ch, struct waiter_s *waiter) {
    if (waiter) {
        LIST_REMOVE(waiter, next);
        free(waiter);
    }
}

struct waiter_s* ziti_channel_send_for_reply(ziti_channel_t *ch, uint32_t content, const hdr_t *hdrs, int nhdrs, const uint8_t *body,
                                uint32_t body_len,
                                reply_cb rep_cb, void *reply_ctx) {
    struct waiter_s* result = NULL;
    header_t header;
    header_init(&header, ch->msg_seq++);

    ZITI_LOG(TRACE, "ch[%d]=> ct[%x] seq[%d] len[%d]", ch->id, content, header.seq, body_len);
    header.content = content;
    header.body_len = body_len;

    uint32_t hdrs_len = 0;
    for (int i = 0; i < nhdrs; i++) {
        hdrs_len += sizeof(uint32_t) * 2 + hdrs[i].length; // header id + val(length) + length
    }
    header.headers_len = hdrs_len;
    unsigned int msg_size = HEADER_SIZE + hdrs_len + body_len;
    uint8_t *msg_buf = malloc(msg_size);
    header_to_buffer(&header, msg_buf);

    uint8_t *p = msg_buf + HEADER_SIZE;
    for (int i = 0; i < nhdrs; i++) {
        p = write_hdr(&hdrs[i], p);
    }
    assert(p == msg_buf + HEADER_SIZE + hdrs_len);

    memcpy(p, body, body_len);

    if (rep_cb != NULL) {
        NEWP(w, struct waiter_s);
        w->seq = header.seq;
        w->cb = rep_cb;
        w->reply_ctx = reply_ctx;

        LIST_INSERT_HEAD(&ch->waiters, w, next);
        result = w;
    }

    NEWP(wr, struct async_write_req);
    wr->buf = uv_buf_init(msg_buf, msg_size);
    wr->ch = ch;

    NEWP(async_req, uv_async_t);
    uv_async_init(ch->loop, async_req, async_write);
    async_req->data = wr;

    // Guard against write requests coming on a thread different from our loop
    if (uv_thread_self() == ch->ctx->loop_thread) {
        async_write(async_req);
    }
    else {
        uv_async_send(async_req);
    }

    return result;
}

static struct msg_receiver *find_receiver(ziti_channel_t *ch, uint32_t conn_id) {
    struct msg_receiver *c;
    LIST_FOREACH(c, &ch->receivers, _next) {
        if (c->id == conn_id) {
            return c;
        }
    }
    return NULL;
}


static bool is_edge(int32_t content) {
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
            return true;
        default:
            return false;
    }
}
static void dispatch_message(ziti_channel_t *ch, message *m) {
    struct waiter_s *w = NULL;

    m->nhdrs = parse_hdrs(m->headers, m->header.headers_len, &m->hdrs);

    int32_t reply_to;
    bool is_reply = message_get_int32_header(m, ReplyForHeader, &reply_to);

    if (is_reply) {
        LIST_FOREACH(w, &ch->waiters, next) {
            if (w->seq == reply_to) {
                break;
            }
        }

        if (w) {
            LIST_REMOVE(w, next);
            ZITI_LOG(TRACE, "ch[%d] found waiter for [rep_to=%d]", ch->id, w->seq);

            w->cb(w->reply_ctx, m);
            free(w);
            return;
        }
    }

    if (is_edge(m->header.content)) {
        int32_t conn_id;
        bool has_conn_id = message_get_int32_header(m, ConnIdHeader, &conn_id);

        if (!has_conn_id) {
            ZITI_LOG(ERROR, "ch[%d] received message without conn_id ct[%d]", ch->id, m->header.content);
        }
        else {
            struct msg_receiver *conn = find_receiver(ch, conn_id);
            if (conn == NULL) {
                ZITI_LOG(DEBUG, "ch[%d] received message for unknown connection conn_id[%d] ct[%d]",
                         ch->id, conn_id, m->header.content);
            }
            else {
                conn->receive(conn->receiver, m, ZITI_OK);
            }
        }
    }
    else {
        ZITI_LOG(WARN, "ch[%d] unsupported content type [%d]", ch->id,  m->header.content);
    }
}

static void process_inbound(ziti_channel_t *ch) {
    uint8_t *ptr;
    int len;
    do {
        if (ch->in_next == NULL) {
            if (buffer_available(ch->incoming) < HEADER_SIZE) {
                ZITI_LOG(TRACE, "not enough data in buffer for complete header");
                break;
            }

            uint8_t header_buf[HEADER_SIZE];
            int header_read = 0;

            while(header_read < HEADER_SIZE) {
                len = buffer_get_next(ch->incoming, HEADER_SIZE - header_read, &ptr);
                memcpy(header_buf + header_read, ptr, len);
                header_read += len;
            }

            assert(header_read == HEADER_SIZE);

            ch->in_next = malloc(sizeof(message));
            message_init(ch->in_next);

            header_from_buffer(&ch->in_next->header, header_buf);

            // allocate single memory block for both headers and body
            // body ptr will point to inside the block
            ch->in_next->headers = malloc(ch->in_next->header.headers_len + ch->in_next->header.body_len);
            ch->in_next->body = ch->in_next->headers + ch->in_next->header.headers_len;

            ch->in_body_offset = 0;

            ZITI_LOG(TRACE, "ch[%d] <= ct[%x] seq[%d] len[%d] hdrs[%d]", ch->id, ch->in_next->header.content,
                     ch->in_next->header.seq,
                     ch->in_next->header.body_len, ch->in_next->header.headers_len);
        }

        // to complete the message need to read headers_len + body_len - (whatever was read already)
        uint32_t total = ch->in_next->header.body_len + ch->in_next->header.headers_len;
        uint32_t want = total - ch->in_body_offset;
        len = buffer_get_next(ch->incoming, want, &ptr);
        ZITI_LOG(TRACE, "ch[%d] completing msg seq[%d] body+hrds=%d+%d, in_offset=%d, want=%d, got=%d",
                 ch->id, ch->in_next->header.seq,
                 ch->in_next->header.body_len, ch->in_next->header.headers_len, ch->in_body_offset, want, len);

        if (len == -1) {
            break;
        }
        if (len > 0) {
            memcpy(ch->in_next->headers + ch->in_body_offset, ptr, (size_t) len);
            ch->in_body_offset += len;

            if (ch->in_body_offset == total) {
                ZITI_LOG(TRACE, "ch[%d] message is complete seq[%d]", ch->id, ch->in_next->header.seq);

                dispatch_message(ch, ch->in_next);

                message_free(ch->in_next);
                free(ch->in_next);
                ch->in_next = NULL;
            }
        }
    } while (1);

    buffer_cleanup(ch->incoming);
}

static void latency_reply_cb(void *ctx, message *reply) {
    ziti_channel_t *ch = ctx;
    uint64_t ts;
    if (reply->header.content == ContentTypeResultType &&
        message_get_uint64_header(reply, LatencyProbeTime, &ts)) {
        ch->latency = uv_now(ch->loop) - ts;
        ZITI_LOG(VERBOSE, "ch[%d](%s) latency is now %ld", ch->id, ch->name, ch->latency);
    } else {
        ZITI_LOG(WARN, "invalid latency probe result ct[%d]", reply->header.content);
    }
}

static void send_latency_probe(uv_timer_t *t) {
    ziti_channel_t *ch = t->data;
    uint64_t now = htole64(uv_now(t->loop));
    hdr_t headers[] = {
            {
                    .header_id = LatencyProbeTime,
                    .length = sizeof(now),
                    .value = (uint8_t *) &now,
            }
    };

    ziti_channel_send_for_reply(ch, ContentTypeLatencyType, headers, 1, NULL, 0, latency_reply_cb, ch);
}

static void hello_reply_cb(void *ctx, message *msg) {

    assert (msg->header.content == ContentTypeResultType);

    bool success;
    bool found = message_get_bool_header(msg, ResultSuccessHeader, &success);
    assert(found);

    ziti_channel_t *ch = ctx;

    int cb_code = ZITI_OK;
    if (success) {
        uint8_t *erVersion = "<unknown>";
        size_t erVersionLen = strlen(erVersion);
        message_get_bytes_header(msg, HelloVersionHeader, &erVersion, &erVersionLen);
        ZITI_LOG(INFO, "ch[%d](%s) connected. EdgeRouter version: %.*s",
                 ch->id, ch->name, (int) erVersionLen, erVersion);
        ch->state = Connected;
        FREE(ch->version);
        ch->version = strndup(erVersion, erVersionLen);
        ch->notify_cb(ch, EdgeRouterConnected, ch->notify_ctx);
    }
    else {
        ZITI_LOG(ERROR, "channel[%d] connect rejected: %d %*s", ch->id, success, msg->header.body_len, msg->body);
        ch->state = Closed;
        cb_code = ZITI_GATEWAY_UNAVAILABLE;
        ch->notify_cb(ch, EdgeRouterUnavailable, ch->notify_ctx);
    }

    for (int i = 0; i < ch->conn_reqs_n; i++) {
        struct ch_conn_req *r = ch->conn_reqs[i];
        r->cb(ch, r->ctx, cb_code);
        free(r);
    }
    ch->conn_reqs_n = 0;

    if (success) {
        // initial latency
        ch->latency = uv_now(ch->loop) - ch->latency;
        uv_timer_init(ch->loop, &ch->latency_timer);
        ch->latency_timer.data = ch;
        uv_unref((uv_handle_t *) &ch->latency_timer);
        uv_timer_start(&ch->latency_timer, send_latency_probe, 0, 60 * 1000);
    }
    else {
        reconnect_channel(ch);
    }
}

static void send_hello(ziti_channel_t *ch) {
    hdr_t headers[] = {
            {
                    .header_id = SessionTokenHeader,
                    .length = strlen(ch->ctx->session->token),
                    .value = ch->ctx->session->token
            }
    };
    ch->latency = uv_now(ch->loop);
    ziti_channel_send_for_reply(ch, ContentTypeHelloType, headers, 1, ch->token, strlen(ch->token), hello_reply_cb, ch);
}

static void async_write(uv_async_t *ar) {

    struct async_write_req *wr = ar->data;

    NEWP(req, uv_write_t);
    req->data = wr;
    uv_mbed_write(req, &wr->ch->connection, &wr->buf, on_write);

    uv_close((uv_handle_t *) ar, (uv_close_cb) free);
}

static void reconnect_cb(uv_timer_t *t) {
    ziti_channel_t *ch = t->data;

    ch->msg_seq = 0;

    uv_connect_t *req = calloc(1, sizeof(uv_connect_t));
    req->data = ch;

    ch->state = Connecting;

    uv_mbed_init(ch->loop, &ch->connection, ch->connection.tls);
    ch->connection._stream.data = ch;
    uv_mbed_connect(req, &ch->connection, ch->host, ch->port, on_channel_connect_internal);
    uv_close((uv_handle_t *) t, (uv_close_cb) free);
}

static void reconnect_channel(ziti_channel_t *ch) {
    ch->reconnect_count++;
    uv_timer_t *t = malloc(sizeof(uv_timer_t));
    uv_timer_init(ch->loop, t);
    t->data = ch;

    int count = ch->reconnect_count;
    if (count > MAX_BACKOFF) {
        count = MAX_BACKOFF;
    }
    unsigned int backoff = rand() % count;

    uint64_t timeout = (1U << backoff) * BACKOFF_TIME;
    ZITI_LOG(INFO, "ch[%d] reconnecting in %ld ms (attempt = %d)", ch->id, timeout, ch->reconnect_count);
    uv_timer_start(t, reconnect_cb, timeout, 0);
    uv_unref((uv_handle_t *) t);
}

static void on_channel_close(ziti_channel_t *ch, ssize_t code) {
    if (ch->state != Closed) {
        ch->state = Disconnected;
        ch->notify_cb(ch, EdgeRouterDisconnected, ch->notify_ctx);
    }

    ch->latency = UINT64_MAX;
    if (uv_is_active((const uv_handle_t *) &ch->latency_timer)) {
        uv_timer_stop(&ch->latency_timer);
    }

    while (!LIST_EMPTY(&ch->receivers)) {
        struct msg_receiver *con = LIST_FIRST(&ch->receivers);
        LIST_REMOVE(con, _next);
        con->receive(con->receiver, NULL, (int) code);
        free(con);
    }

    if (ch->state != Closed) {
        reconnect_channel(ch);
    }
}

static void on_write(uv_write_t *req, int status) {
    struct async_write_req *wr = req->data;

    if (status < 0) {
        ZITI_LOG(ERROR, "ch[%d] write failed [status=%d] %s", wr->ch->id, status, uv_strerror(status));
        uv_mbed_t *mbed = (uv_mbed_t *) req->handle;
        ziti_channel_t *ch = uv_handle_get_data((const uv_handle_t *) mbed);
        on_channel_close(ch, status);

    }

    if (wr != NULL) {
        FREE(wr->buf.base);
        FREE(wr);
    }
    FREE(req);
}

static void on_channel_data(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    uv_mbed_t *mbed = (uv_mbed_t *) s;
    ziti_channel_t *ch = mbed->_stream.data;

    if (len < 0) {
        free(buf->base);
        switch (len) {
            case UV_EOF:
            case UV_ECONNRESET:
            case UV_ECONNABORTED:
            case UV_ECONNREFUSED:
            case UV_EPIPE:
                ZITI_LOG(INFO, "channel was closed: %d(%s)", (int) len, uv_strerror((int) len));
                // propagate close
                on_channel_close(ch, ZITI_CONNABORT);
                break;

            default:
                ZITI_LOG(ERROR, "unhandled error on_data rc=%zd (%s)", len, uv_strerror(len));
                on_channel_close(ch, len);

        }
    }
    else if (len == 0) {
        // sometimes SSL message has no payload
        free(buf->base);
    }
    else {
        ZITI_LOG(TRACE, "ch[%d] on_data [len=%zd]", ch->id, len);
        if (len > 0) {
            buffer_append(ch->incoming, buf->base, (uint32_t) len);
            process_inbound(ch);
        }
    }
}

static void on_channel_connect_internal(uv_connect_t *req, int status) {
    ziti_channel_t *ch = req->data;

    if (status == 0) {
        ZITI_LOG(DEBUG, "ch[%d] connected", ch->id);
        ch->reconnect_count = 0;
        uv_mbed_t *mbed = (uv_mbed_t *) req->handle;
        uv_mbed_read(mbed, ziti_alloc_cb, on_channel_data);
        if (ch->ctx->opts->router_keepalive != 0) {
            uv_mbed_keepalive(mbed, 1, ch->ctx->opts->router_keepalive);
        }
        send_hello(ch);
    }
    else {
        ZITI_LOG(ERROR, "ch[%d] failed to connect[%s] [status=%d]", ch->id, ch->name, status);

        for (int i = 0; i < ch->conn_reqs_n; i++) {
            struct ch_conn_req *r = ch->conn_reqs[i];
            r->cb(ch, r->ctx, status);
            free(r);
            ch->conn_reqs[i] = NULL;
        }
        ch->conn_reqs_n = 0;
        ch->state = Disconnected;
        reconnect_channel(ch);
    }
    free(req);
}