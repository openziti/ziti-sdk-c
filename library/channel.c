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

#define CONNECT_TIMEOUT (20*1000)
#define LATENCY_TIMEOUT (10*1000)
#define LATENCY_INTERVAL (60*1000) /* 1 minute */
#define BACKOFF_TIME 5000 /* 5 seconds */
#define MAX_BACKOFF 5 /* max reconnection timeout: (1 << MAX_BACKOFF) * BACKOFF_TIME = 160 seconds */

#define CH_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "ch[%d] " fmt, ch->id, ##__VA_ARGS__)

enum ChannelState {
    Initial,
    Connecting,
    Connected,
    Disconnected,
    Closed,
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

static void reconnect_cb(uv_timer_t *t);

static void on_channel_connect_internal(uv_connect_t *req, int status);

static void on_write(uv_write_t *req, int status);

static struct msg_receiver *find_receiver(ziti_channel_t *ch, uint32_t conn_id);

static void on_channel_close(ziti_channel_t *ch, int ziti_err, ssize_t uv_err);

static void send_latency_probe(uv_timer_t *t);

static void ch_connect_timeout(uv_timer_t *t);

static void hello_reply_cb(void *ctx, message *msg, int err);

// global channel sequence
static uint32_t channel_counter = 0;

struct ch_write_req {
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
    LIST_ENTRY(ch_conn_req) next;
};

struct msg_receiver {
    int id;
    void *receiver;

    void (*receive)(void *receiver, message *m, int code);
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
    LIST_INIT(&ch->conn_reqs);

    ch->name = NULL;
    ch->in_next = NULL;
    ch->in_body_offset = 0;
    ch->incoming = new_buffer();
    ch->in_msg_pool = pool_new(sizeof(message), 32, (void (*)(void *)) message_free);

    LIST_INIT(&ch->waiters);

    uv_mbed_init(ch->loop, &ch->connection, tls);
    uv_mbed_keepalive(&ch->connection, true, ctx->opts->router_keepalive);
    uv_mbed_nodelay(&ch->connection, true);
    ch->connection.data = ch;

    ch->timer = calloc(1, sizeof(uv_timer_t));
    uv_timer_init(ch->loop, ch->timer);
    ch->timer->data = ch;
    uv_unref((uv_handle_t *) ch->timer);

    ch->notify_cb = (ch_notify_state) ziti_on_channel_event;
    ch->notify_ctx = ctx;
    return 0;
}

void ziti_channel_free(ziti_channel_t *ch) {
    free_buffer(ch->incoming);
    pool_destroy(ch->in_msg_pool);
    FREE(ch->name);
    FREE(ch->version);
    FREE(ch->host);
}

int ziti_close_channels(struct ziti_ctx *ztx, int err) {
    ziti_channel_t *ch;
    const char *url;
    MODEL_MAP_FOREACH(url, ch, &ztx->channels) {
        ZTX_LOG(DEBUG, "closing channel[%s]: %s", url, ziti_errorstr(err));
        ziti_channel_close(ch, err);
    }
    return ZITI_OK;
}

static void close_handle_cb(uv_handle_t *h) {
    uv_mbed_t *mbed = (uv_mbed_t *) h;
    ziti_channel_t *ch = mbed->data;

    ziti_on_channel_event(ch, EdgeRouterRemoved, ch->ctx);

    uv_mbed_free(mbed);
    ziti_channel_free(ch);
    free(ch);
}

int ziti_channel_close(ziti_channel_t *ch, int err) {
    int r = 0;
    if (ch->state != Closed) {
        CH_LOG(INFO, "closing[%s]", ch->name);
        ch->state = Closed;

        on_channel_close(ch, err, 0);

        uv_close((uv_handle_t *) ch->timer, (uv_close_cb) free);
        ch->timer = NULL;
        r = uv_mbed_close(&ch->connection, close_handle_cb);
    }
    return r;
}

void ziti_channel_add_receiver(ziti_channel_t *ch, int id, void *receiver, void (*receive_f)(void *, message *, int)) {
    NEWP(r, struct msg_receiver);
    r->id = id;
    r->receiver = receiver;
    r->receive = receive_f;

    model_map_setl(&ch->receivers, r->id, r);
    CH_LOG(DEBUG, "added receiver[%d]", id);
}

void ziti_channel_rem_receiver(ziti_channel_t *ch, int id) {
    struct msg_receiver *r = model_map_removel(&ch->receivers, id);

    if (r) {
        CH_LOG(DEBUG, "removed receiver[%d]", id);
        free(r);
    }
}

bool ziti_channel_is_connected(ziti_channel_t *ch) {
    return ch->state == Connected;
}

static ziti_channel_t *new_ziti_channel(ziti_context ztx, const char *ch_name, const char *url) {
    ziti_channel_t *ch = calloc(1, sizeof(ziti_channel_t));
    ziti_channel_init(ztx, ch, channel_counter++, ztx->tlsCtx);
    ch->name = strdup(ch_name);
    CH_LOG(INFO, "(%s) new channel for ztx[%d] identity[%s]", ch->name, ztx->id, ztx->api_session->identity->name);

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
    return ch;
}

static void check_connecting_state(ziti_channel_t *ch) {
    // verify channel state
    bool reset = false;
    if (!uv_is_active((const uv_handle_t *) &ch->timer)) {
        CH_LOG(ERROR, "state check: timer not active!");
        reset = true;
    }

    if (ch->timer->timer_cb != ch_connect_timeout) {
        CH_LOG(ERROR, "state check: unexpected callback(%s)!", get_timeout_cb(ch));
        reset = true;
    }

    if (ch->timer->timeout < uv_now(ch->loop)) {
        CH_LOG(ERROR, "state check: timer is in the past!");
        reset = true;
    }

    if (ch->timer->timeout - uv_now(ch->loop) > CONNECT_TIMEOUT) {
        CH_LOG(ERROR, "state check: timer is too far into the future!");
        reset = true;
    }
}

int ziti_channel_connect(ziti_context ztx, const char *ch_name, const char *url, ch_connect_cb cb, void *cb_ctx) {
    ziti_channel_t *ch = model_map_get(&ztx->channels, ch_name);

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

    switch (ch->state) {
        case Connected:
            if (cb) {
                cb(ch, cb_ctx, ZITI_OK);
            }
            break;

        case Initial:
        case Connecting:
        case Disconnected:
            if (cb != NULL) {
                NEWP(r, struct ch_conn_req);
                r->cb = cb;
                r->ctx = cb_ctx;
                LIST_INSERT_HEAD(&ch->conn_reqs, r, next);
            }

            break;
        default:
            CH_LOG(ERROR, "should not be here: %s", ziti_errorstr(ZITI_WTF));
            return ZITI_WTF;
    }

    if (ch->state == Initial || ch->state == Disconnected) {
        reconnect_channel(ch, true);
    }
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

    CH_LOG(TRACE, "=> ct[%04X] seq[%d] len[%d]", content, header.seq, body_len);
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
    if (ziti_write == NULL) {
        ziti_write = calloc(1, sizeof(struct ziti_write_req_s));
    }
    req->data = ziti_write;
    ziti_write->payload = msg_buf;
    int rc = uv_mbed_write(req, &ch->connection, &buf, on_channel_send);
    if (rc != 0) {
        on_channel_send(req, rc);
    }
    return 0;
}

void ziti_channel_remove_waiter(ziti_channel_t *ch, struct waiter_s *waiter) {
    if (waiter) {
        LIST_REMOVE(waiter, next);
        free(waiter);
    }
}

struct waiter_s *
ziti_channel_send_for_reply(ziti_channel_t *ch, uint32_t content, const hdr_t *hdrs, int nhdrs, const uint8_t *body,
                            uint32_t body_len,
                            reply_cb rep_cb, void *reply_ctx) {
    struct waiter_s *result = NULL;
    header_t header;
    header_init(&header, ch->msg_seq++);

    CH_LOG(TRACE, "=> ct[%04X] seq[%d] len[%d]", content, header.seq, body_len);
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

    NEWP(wr, struct ch_write_req);
    wr->buf = uv_buf_init(msg_buf, msg_size);
    wr->ch = ch;

    NEWP(req, uv_write_t);
    req->data = wr;
    int rc = uv_mbed_write(req, &wr->ch->connection, &wr->buf, on_write);
    if (rc != 0) {
        on_write(req, rc);
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
            w->cb(w->reply_ctx, m, 0);
            free(w);
            pool_return_obj(m);
            return;
        }

        CH_LOG(ERROR, "could not find waiter for reply_to = %d", reply_to);
    }

    if (ch->state == Connecting) {
        if (m->header.content == ContentTypeResultType) {
            CH_LOG(WARN, "lost hello reply waiter");
            hello_reply_cb(ch, m, ZITI_OK);
            pool_return_obj(m);
            return;
        }

        CH_LOG(ERROR, "received unexpected message ct[%04X] in Connecting state", m->header.content);
    }

    if (is_edge(m->header.content)) {
        int32_t conn_id = 0;
        bool has_conn_id = message_get_int32_header(m, ConnIdHeader, &conn_id);
        struct msg_receiver *conn = has_conn_id ? find_receiver(ch, conn_id) : NULL;

        if (conn) {
            conn->receive(conn->receiver, m, ZITI_OK);
        } else {
            CH_LOG(ERROR, "received message without conn_id or for unknown connection ct[%04X] conn_id[%d]", m->header.content, conn_id);
            pool_return_obj(m);
        }
    } else {
        CH_LOG(WARN, "unsupported content type [%04X]", m->header.content);
        pool_return_obj(m);
    }
}

static void process_inbound(ziti_channel_t *ch) {
    uint8_t *ptr;
    ssize_t len;
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

            ch->in_next = pool_alloc_obj(ch->in_msg_pool);
            message_init(ch->in_next);

            header_from_buffer(&ch->in_next->header, header_buf);

            // allocate single memory block for both headers and body
            // body ptr will point to inside the block
            ch->in_next->headers = malloc(ch->in_next->header.headers_len + ch->in_next->header.body_len);
            ch->in_next->body = ch->in_next->headers + ch->in_next->header.headers_len;

            ch->in_body_offset = 0;

            CH_LOG(TRACE, "<= ct[%04X] seq[%d] len[%d] hdrs[%d]", ch->in_next->header.content,
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
                CH_LOG(TRACE, "message is complete seq[%d] ct[%04X]", ch->in_next->header.seq,
                       ch->in_next->header.content);

                dispatch_message(ch, ch->in_next);

                ch->in_next = NULL;
            }
        }
    } while (1);

    buffer_cleanup(ch->incoming);
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
        CH_LOG(VERBOSE, "latency is now %ld", ch->latency);
    }
    else {
        CH_LOG(WARN, "invalid latency probe result ct[%04X]", reply->header.content);
    }
    uv_timer_start(ch->timer, send_latency_probe, LATENCY_INTERVAL, 0);
}

static void latency_timeout(uv_timer_t *t) {
    ziti_channel_t *ch = t->data;
    ziti_channel_remove_waiter(ch, ch->latency_waiter);
    ch->latency_waiter = NULL;
    ch->latency = UINT64_MAX;

    uv_mbed_close(&ch->connection, NULL);
    on_channel_close(ch, ZITI_TIMEOUT, UV_ETIMEDOUT);
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

    uv_timer_start(t, latency_timeout, LATENCY_TIMEOUT, 0);
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
        CH_LOG(ERROR, "unexpected Hello response ct[%04X]", msg->header.content);
        cb_code = ZITI_GATEWAY_UNAVAILABLE;
    }
    else {
        CH_LOG(ERROR, "failed to receive Hello response due to %d(%s)", err, ziti_errorstr(err));
        cb_code = ZITI_GATEWAY_UNAVAILABLE;
    }

    if (success) {
        uint8_t *erVersion = "<unknown>";
        size_t erVersionLen = strlen(erVersion);
        message_get_bytes_header(msg, HelloVersionHeader, &erVersion, &erVersionLen);
        CH_LOG(INFO, "connected. EdgeRouter version: %.*s", (int) erVersionLen, erVersion);
        ch->state = Connected;
        FREE(ch->version);
        ch->version = strndup(erVersion, erVersionLen);
        ch->notify_cb(ch, EdgeRouterConnected, ch->notify_ctx);
        ch->latency = uv_now(ch->loop) - ch->latency;
        uv_timer_start(ch->timer, send_latency_probe, LATENCY_INTERVAL, 0);
    }
    else {
        if (msg)
            CH_LOG(ERROR, "connect rejected: %d %*s", success, msg->header.body_len, msg->body);

        ch->state = Disconnected;
        ch->notify_cb(ch, EdgeRouterUnavailable, ch->notify_ctx);
        uv_mbed_close(&ch->connection, NULL);
        reconnect_channel(ch, false);
    }

    while (!LIST_EMPTY(&ch->conn_reqs)) {
        struct ch_conn_req *r = LIST_FIRST(&ch->conn_reqs);
        LIST_REMOVE(r, next);
        r->cb(ch, r->ctx, cb_code);
        free(r);
    }
}

static void send_hello(ziti_channel_t *ch, ziti_api_session *session) {
    hdr_t headers[] = {
            {
                    .header_id = SessionTokenHeader,
                    .length = strlen(session->token),
                    .value = (uint8_t *)session->token
            }
    };
    ch->latency = uv_now(ch->loop);
    ziti_channel_send_for_reply(ch, ContentTypeHelloType, headers, 1, ch->token, strlen(ch->token), hello_reply_cb, ch);
}


static void ch_connect_timeout(uv_timer_t *t) {
    ziti_channel_t *ch = t->data;
    CH_LOG(ERROR, "connect timeout");

    if (ch->state == Closed) {
        return;
    }

    ch->state = Disconnected;
    if (ch->connection.conn_req == NULL) {
        // diagnostics
        CH_LOG(WARN, "diagnostics: no conn_req in connect timeout");
    }
    reconnect_channel(ch, false);
    uv_mbed_close(&ch->connection, NULL);
}

static void reconnect_cb(uv_timer_t *t) {
    ziti_channel_t *ch = t->data;
    ziti_context ztx = ch->ctx;

    if (ztx->api_session == NULL || ztx->api_session->token == NULL || ztx->api_session_state != ZitiApiSessionStateFullyAuthenticated) {
        CH_LOG(ERROR, "ziti context is not fully authenticated (api_session_state[%d]), delaying re-connect", ztx->api_session_state);
        reconnect_channel(ch, false);
    }
    else {
        ch->msg_seq = 0;

        uv_connect_t *req = calloc(1, sizeof(uv_connect_t));
        req->data = ch;

        ch->state = Connecting;

        uv_mbed_free(&ch->connection);
        uv_mbed_init(ch->loop, &ch->connection, ch->connection.tls);
        ch->connection.data = ch;
        CH_LOG(DEBUG, "connecting to %s:%d", ch->host, ch->port);
        int rc = uv_mbed_connect(req, &ch->connection, ch->host, ch->port, on_channel_connect_internal);
        if (rc != 0) {
            on_channel_connect_internal(req, rc);
        }
        else {
            uv_timer_start(ch->timer, ch_connect_timeout, CONNECT_TIMEOUT, 0);
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
        ch->reconnect_count++;
        int backoff = MIN(ch->reconnect_count, MAX_BACKOFF);

        uint32_t random;
        uv_random(ch->loop, NULL, &random, sizeof(random), 0, NULL);

        timeout = random % ((1U << backoff) * BACKOFF_TIME);
        CH_LOG(INFO, "reconnecting in %ld ms (attempt = %d)", timeout, ch->reconnect_count);
    }
    else {
        CH_LOG(INFO, "reconnecting NOW");
    }
    uv_timer_start(ch->timer, reconnect_cb, timeout, 0);
}

static void on_channel_close(ziti_channel_t *ch, int ziti_err, ssize_t uv_err) {
    ziti_context ztx = ch->ctx;

    if (ch->state != Closed) {
        if (ch->state == Connected) {
            ch->notify_cb(ch, EdgeRouterDisconnected, ch->notify_ctx);
        }
        ch->state = Disconnected;
    }

    ch->latency = UINT64_MAX;
    if (uv_is_active((const uv_handle_t *) &ch->timer)) {
        uv_timer_stop(ch->timer);
    }

    while (!LIST_EMPTY(&ch->waiters)) {
        struct waiter_s *w = LIST_FIRST(&ch->waiters);
        LIST_REMOVE(w, next);
        w->cb(w->reply_ctx, NULL, ziti_err);
        free(w);
    }

    model_map_iter it = model_map_iterator(&ch->receivers);
    while (it != NULL) {
        struct msg_receiver *con = model_map_it_value(it);
        it = model_map_it_remove(it);
        con->receive(con->receiver, NULL, (int) ziti_err);
        free(con);
    }

    if (ch->state != Closed) {
        if (uv_err == UV_EOF) {
            ZTX_LOG(VERBOSE, "edge router closed connection, trying to refresh api session");
            ziti_force_api_session_refresh(ch->ctx);
        }
        reconnect_channel(ch, false);
    }
}

static void on_write(uv_write_t *req, int status) {
    ZITI_LOG(TRACE, "on_write(%p,%d)", req, status);
    struct ch_write_req *wr = req->data;

    if (status < 0) {
        ziti_channel_t *ch = wr->ch;
        CH_LOG(ERROR, "write failed [%d/%s]", status, uv_strerror(status));
        on_channel_close(ch, ZITI_CONN_CLOSED, status);
    }

    if (wr != NULL) {
        FREE(wr->buf.base);
        FREE(wr);
    }
    FREE(req);
}

static void channel_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    uv_mbed_t *mbed = (uv_mbed_t *) handle;
    ziti_channel_t *ch = mbed->data;
    if (ch->in_next || pool_has_available(ch->in_msg_pool)) {
        buf->base = (char *) malloc(suggested_size);
        if (buf->base == NULL) {
            ZITI_LOG(ERROR, "failed to allocate %zd bytes. Prepare for crash", suggested_size);
            buf->len = 0;
        } else {
            buf->len = suggested_size;
        }
    } else {
        ZITI_LOG(WARN, "can't alloc message");

        buf->len = 0;
        buf->base = NULL;
    }
}

static void on_channel_data(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    uv_mbed_t *mbed = (uv_mbed_t *) s;
    ziti_channel_t *ch = mbed->data;

    if (len < 0) {
        free(buf->base);
        switch (len) {
            case UV_ENOBUFS:
                CH_LOG(VERBOSE, "blocked until messages are processed");
                return;
            case UV_EOF:
            case UV_ECONNRESET:
            case UV_ECONNABORTED:
            case UV_ECONNREFUSED:
            case UV_EPIPE:
                CH_LOG(INFO, "channel was closed [%zd/%s]", len, uv_strerror(len));
                // propagate close
                on_channel_close(ch, ZITI_CONNABORT, len);
                break;

            default:
                CH_LOG(ERROR, "unhandled error on_data [%zd/%s]", len, uv_strerror(len));
                on_channel_close(ch, ZITI_CONNABORT, len);
        }
    } else if (len == 0) {
        // sometimes SSL message has no payload
        free(buf->base);
    } else {
        CH_LOG(TRACE, "on_data [len=%zd]", len);
        if (len > 0) {
            buffer_append(ch->incoming, buf->base, (uint32_t) len);
            process_inbound(ch);
        }
    }
}

static void on_channel_connect_internal(uv_connect_t *req, int status) {
    ziti_channel_t *ch = req->data;

    if (status == 0) {
        if (ch->ctx->api_session != NULL && ch->ctx->api_session->token != NULL) {
            CH_LOG(DEBUG, "connected");
            uv_mbed_t *mbed = (uv_mbed_t *) req->handle;
            uv_mbed_read(mbed, channel_alloc_cb, on_channel_data);
            ch->reconnect_count = 0;
            send_hello(ch, ch->ctx->api_session);
        } else {
            CH_LOG(WARN, "api session invalidated, while connecting");
            uv_mbed_close(&ch->connection, close_handle_cb);
            reconnect_channel(ch, false);
        }
    } else {
        CH_LOG(ERROR, "failed to connect [%d/%s]", status, uv_strerror(status));

        while (!LIST_EMPTY(&ch->conn_reqs)) {
            struct ch_conn_req *r = LIST_FIRST(&ch->conn_reqs);
            LIST_REMOVE(r, next);
            r->cb(ch, r->ctx, status);
            free(r);
        }

        if (ch->state != Closed) {
            ch->state = Disconnected;
            reconnect_channel(ch, false);
        }
    }
    free(req);
}

#define TIMEOUT_CALLBACKS(XX) \
XX(latency_timeout) \
XX(ch_connect_timeout) \
XX(reconnect_cb)    \
XX(send_latency_probe)

static const char *get_timeout_cb(ziti_channel_t *ch) {
#define to_lbl(n) if (ch->timer->timer_cb == (n)) return #n;

    TIMEOUT_CALLBACKS(to_lbl)

    return "unknown";
}
