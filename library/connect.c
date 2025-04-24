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

#include <stdlib.h>
#include <posture.h>
#include <assert.h>

#include "message.h"
#include "endian_internal.h"
#include "win32_compat.h"
#include "connect.h"

static const char *INVALID_SESSION = "Invalid Session";
static const int MAX_CONNECT_RETRY = 3;

#define CONN_CAP_MASK (EDGE_MULTIPART | EDGE_TRACE_UUID | EDGE_STREAM)
#define BOOL_STR(v) ((v) ? "Y" : "N")

#define CONN_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "conn[%u.%u/%.*s/%s](%s) " fmt, \
conn->ziti_ctx->id, conn->conn_id, (int)sizeof(conn->marker),                 \
conn->marker, conn_state_str[conn->state], conn->service,                     \
##__VA_ARGS__)


#define DEFAULT_DIAL_OPTS (ziti_dial_opts){ \
                 .connect_timeout_seconds = ZITI_DEFAULT_TIMEOUT/1000, \
    }

static const char *conn_state_str[] = {
#define state_str(ST) #ST ,
        conn_states(state_str)
};

struct msg_uuid {
    union {
        uint8_t raw[16];
        struct {
            uint32_t slug;
            uint32_t seq;
            uint64_t ts;
        };
    };
};

struct local_hash {
    union {
        uint8_t hash[32];
        uint32_t i32[8];
    };
};

#define UUID_FMT "%08x:%08x:%llx"
#define UUID_FMT_ARG(u) ((u)->slug),((u)->seq),(long long)((u)->ts)
#define HASH_FMT "%08x:%08x:%08x:%08x:%08x:%08x:%08x:%08x"
#define HASH_FMT_ARG(lh) (lh).i32[0],(lh).i32[1],(lh).i32[2],(lh).i32[3], \
                         (lh).i32[4],(lh).i32[5],(lh).i32[6],(lh).i32[7]

struct ziti_conn_req {
    ziti_session_type session_type;
    char *service_id;
    ziti_conn_cb cb;
    ziti_dial_opts dial_opts;

    int retry_count;
    struct waiter_s *waiter;
    bool failed;

    deadline_t deadline;
};

static void flush_connection(ziti_connection conn);

static bool flush_to_service(ziti_connection conn);

static bool flush_to_client(ziti_connection conn);

static int send_fin_message(ziti_connection conn, struct ziti_write_req_s *wr);

static void queue_edge_message(struct ziti_conn *conn, message *msg, int code);

static void process_edge_message(struct ziti_conn *conn, message *msg);

static bool ziti_connect(struct ziti_ctx *ztx, ziti_session *session, struct ziti_conn *conn);
static int ziti_channel_start_connection(struct ziti_conn *conn, ziti_channel_t *ch, ziti_session *session);

static int ziti_disconnect(ziti_connection conn);

static void restart_connect(struct ziti_conn *conn);

static void free_handle(uv_handle_t *h) {
    free(h);
}

const char *ziti_conn_state(ziti_connection conn) {
    return conn ? conn_state_str[conn->state] : "<NULL>";
}

int ziti_conn_set_data_cb(ziti_connection conn, ziti_data_cb cb) {
    if (conn == NULL) return ZITI_INVALID_STATE;

    if (conn->state == Disconnected || conn->state == Closed) {
        return ZITI_CONN_CLOSED;
    }

    // app already received EOF
    if (conn->fin_recv == 2) {
        return ZITI_EOF;
    }

    conn->data_cb = cb;
    if (!TAILQ_EMPTY(&conn->in_q) || buffer_available(conn->inbound) > 0) {
        flush_connection(conn);
    }
    return ZITI_OK;
}

static void conn_set_state(struct ziti_conn *conn, enum conn_state state) {
    CONN_LOG(VERBOSE, "transitioning %s => %s", conn_state_str[conn->state], conn_state_str[state]);
    conn->state = state;
    if (state == Connected) {
        conn->connect_time = uv_now(conn->ziti_ctx->loop) - conn->start;
    }
}

static void clone_ziti_dial_opts(ziti_dial_opts *dest, const ziti_dial_opts *dial_opts) {
    *dest = DEFAULT_DIAL_OPTS;

    dest->stream = dial_opts->stream;
    dest->connect_timeout_seconds = dial_opts->connect_timeout_seconds;
    if (dial_opts->identity != NULL && dial_opts->identity[0] != '\0') {
        dest->identity = strdup(dial_opts->identity);
    }

    if (dial_opts->app_data != NULL && dial_opts->app_data_sz > 0) {
        dest->app_data = malloc(dial_opts->app_data_sz);
        dest->app_data_sz = dial_opts->app_data_sz;
        memcpy(dest->app_data, dial_opts->app_data, dial_opts->app_data_sz);
    }
}

static void free_ziti_dial_opts(ziti_dial_opts *dial_opts) {
    FREE(dial_opts->identity);
    FREE(dial_opts->app_data);
}

static void free_conn_req(struct ziti_conn_req *r) {
    clear_deadline(&r->deadline);

    free_ziti_dial_opts(&r->dial_opts);
    FREE(r->service_id);
    free(r);
}

static int close_conn_internal(struct ziti_conn *conn) {
    assert(conn->type == Transport);

    if (conn->state == Closed) {

        while (!TAILQ_EMPTY(&conn->wreqs)) {
            struct ziti_write_req_s *req = TAILQ_FIRST(&conn->wreqs);
            TAILQ_REMOVE(&conn->wreqs, req, _next);
            if (req->cb) {
                req->cb(conn, ZITI_INVALID_STATE, req->ctx);
            }
            free(req);
        }

        if (!TAILQ_EMPTY(&conn->pending_wreqs)) {
            CONN_LOG(DEBUG, "waiting for pending write requests");
            return 0;
        }

        CONN_LOG(DEBUG, "removing");
        if (conn->close_cb) {
            conn->close_cb(conn);
        }

        if (conn->channel) {
            ziti_channel_rem_receiver(conn->channel, conn->rt_conn_id);
        }

        if (conn->conn_req) {
            ziti_channel_remove_waiter(conn->channel, conn->conn_req->waiter);
            free_conn_req(conn->conn_req);
        }

        if (conn->parent) {
            model_map_removel(&conn->parent->server.children, conn->conn_id);
        }

        free_key_exchange(&conn->key_ex);

        if (conn->flusher) {
            conn->flusher->data = NULL;
            uv_close((uv_handle_t *) conn->flusher, free_handle);
            conn->flusher = NULL;
        }

        int count = 0;
        while (!TAILQ_EMPTY(&conn->in_q)) {
            message *m = TAILQ_FIRST(&conn->in_q);
            TAILQ_REMOVE(&conn->in_q, m, _next);
            pool_return_obj(m);
            count++;
        }
        if (count > 0) {
            CONN_LOG(WARN, "closing with %d unprocessed messaged", count);
        }

        if (buffer_available(conn->inbound) > 0) {
            CONN_LOG(WARN, "dumping %zd bytes of undelivered data", buffer_available(conn->inbound));
        }
        free_buffer(conn->inbound);
        CONN_LOG(TRACE, "is being free()'d");
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
    CONN_LOG(TRACE, "status %d", status);

    if (status < 0) {
        conn_set_state(conn, Disconnected);
        CONN_LOG(DEBUG, "is now Disconnected due to write failure: %d", status);
    }

    TAILQ_REMOVE(&conn->pending_wreqs, req, _next);

    struct ziti_write_req_s *r = req;
    model_list_iter it = model_list_iterator(&req->chain);
    do {
        if (r->cb != NULL) {
            r->cb(conn, status ? status : (ssize_t) r->len, r->ctx);
        }
        r = model_list_it_element(it);
        it = model_list_it_next(it);
    } while(r);
    model_list_clear(&req->chain, free);
    free(req);
}

#define mk_hdr(idx, hid, l, v) headers[(idx)++] = (hdr_t){ .header_id = (hid), .length = (l), .value = (uint8_t*)(v) }

message *create_message(struct ziti_conn *conn, uint32_t content, uint32_t flags, size_t body_len) {

    if (conn->edge_msg_seq == 0) {
        flags |= EDGE_TRACE_UUID;
        if (conn->flags & EDGE_STREAM)
            flags |= EDGE_STREAM;
        else
            flags |= EDGE_MULTIPART;
    }

    int32_t conn_id = htole32(conn->rt_conn_id);
    int32_t msg_seq = htole32(conn->edge_msg_seq++);
    uint32_t msg_flags = htole32(flags);
    struct msg_uuid uuid = {
            .ts = uv_now(conn->ziti_ctx->loop),
            .seq = msg_seq,
    };
    int hcount = 0;
    hdr_t headers[5] = {};

    mk_hdr(hcount, ConnIdHeader, sizeof(conn_id), &conn_id);
    mk_hdr(hcount, SeqHeader, sizeof(msg_seq), &msg_seq);
    if (content == ContentTypeData && body_len > 0) {
        mk_hdr(hcount, UUIDHeader, sizeof(uuid.raw), uuid.raw);
    }
    if (flags != 0) {
        mk_hdr(hcount, FlagsHeader, sizeof(msg_flags), &msg_flags);
    }

    return message_new(NULL, content, headers, hcount, body_len);
}

static int send_message(struct ziti_conn *conn, message *m, struct ziti_write_req_s *wr) {
    ziti_channel_t *ch = conn->channel;
    if (m->header.content == ContentTypeData) {
        struct msg_uuid *uuid = NULL;
        size_t len;
        message_get_bytes_header(m, UUIDHeader, (const uint8_t **) &uuid, &len);

        if (uuid) {
            assert(len == sizeof(*uuid));
            struct local_hash h = {0};
            crypto_hash_sha256(h.hash, m->body, m->header.body_len);
            int32_t seq;
            message_get_int32_header(m, SeqHeader, &seq);

            uuid->slug = htole32(h.i32[0]);
            CONN_LOG(TRACE, "=> ct[%s] uuid[" UUID_FMT "] edge_seq[%d] len[%d] hash[" HASH_FMT "]",
                     content_type_id(m->header.content), UUID_FMT_ARG(uuid), seq,
                     m->header.body_len, HASH_FMT_ARG(h));
        }
    }
    return ziti_channel_send_message(ch, m, wr);
}

static void complete_conn_req(struct ziti_conn *conn, int code) {
    struct ziti_conn_req *cr = conn->conn_req;
    if (cr && cr->cb) {
        if (code != ZITI_OK) {
            CONN_LOG(DEBUG, "%s failed: %s", ziti_conn_state(conn), ziti_errorstr(code));
            conn_set_state(conn, code == ZITI_TIMEOUT ? Timedout : Disconnected);
            cr->failed = true;
            conn->data_cb = NULL;
            if (code != ZITI_GATEWAY_UNAVAILABLE && conn->channel) {
                ch_send_conn_closed(conn->channel, conn->conn_id);
            }
        }
        clear_deadline(&cr->deadline);
        if (cr->waiter) {
            ziti_channel_remove_waiter(conn->channel, cr->waiter);
            cr->waiter = NULL;
        }

        cr->cb(conn, code);
        cr->cb = NULL;

        if (code != ZITI_OK) {
            while (!TAILQ_EMPTY(&conn->wreqs)) {
                struct ziti_write_req_s *req = TAILQ_FIRST(&conn->wreqs);
                TAILQ_REMOVE(&conn->wreqs, req, _next);

                if (req->cb) {
                    req->cb(conn, code, req->ctx);
                }
                free(req);
            }
        }

        flush_connection(conn);
        model_map_removel(&conn->ziti_ctx->waiting_connections, (long)conn->conn_id);
    } else {
        CONN_LOG(WARN, "connection attempt was already completed");
    }
}

static void connect_timeout(void *data) {
    struct ziti_conn *conn = data;
    ziti_channel_t *ch = conn->channel;

    if (conn->state == Connecting || conn->state == Accepting) {
        if (ch == NULL) {
            CONN_LOG(WARN, "connect timeout: no suitable edge router for service[%s]", conn->service);
        } else {
            CONN_LOG(WARN, "failed to establish connection to service[%s] in %ds on ch[%d]",
                     conn->service, conn->conn_req->dial_opts.connect_timeout_seconds, ch->id);
        }
        complete_conn_req(conn, ZITI_TIMEOUT);
        ziti_disconnect(conn);
    } else {
        CONN_LOG(ERROR, "timeout in unexpected state[%s]", ziti_conn_state(conn));
    }
}

static bool ziti_connect(struct ziti_ctx *ztx, ziti_session *session, struct ziti_conn *conn) {
    bool result = false;

    ziti_edge_router *er;
    ziti_channel_t *ch;
    ziti_channel_t *best_ch = NULL;
    uint64_t best_latency = UINT64_MAX;

    model_list disconnected = {0};

    conn->channel = NULL;


    MODEL_LIST_FOREACH(er, session->edge_routers) {
        const char *tls = er->protocols.tls;

        if (tls) {
            ch = model_map_get(&ztx->channels, tls);
            if (ch == NULL) continue;

            if (ch->state == Connected) {
                uint64_t latency = ziti_channel_latency(ch);
                if (latency < best_latency) {
                    best_ch = ch;
                    best_latency = latency;
                }
            }

            if (ch->state == Disconnected) {
                model_list_append(&disconnected, ch);
            }
        }
    }

    if (best_ch) {
        CONN_LOG(DEBUG, "selected ch[%s@%s] for best latency(%llu ms)", best_ch->name, best_ch->url,
                 (unsigned long long) best_latency);
        ziti_channel_start_connection(conn, best_ch, session);
        result = true;
    } else {
        // if no channels are currently connected
        // force them to connect
        MODEL_LIST_FOREACH(ch, disconnected) {
            ziti_channel_force_connect(ch);
        }

        CONN_LOG(DEBUG, "waiting for suitable channel");
        model_map_setl(&ztx->waiting_connections, (long)conn->conn_id, (void*)(uintptr_t)conn->conn_id);
    }
    model_list_clear(&disconnected, NULL);
    return result;
}

static void connect_get_service_cb(ziti_context ztx, const ziti_service *s, int status, void *ctx) {
    struct ziti_conn *conn = ctx;
    struct ziti_conn_req *req = conn->conn_req;

    if (status == ZITI_OK) {
        CONN_LOG(DEBUG, "got service[%s] id[%s]", s->name, s->id);

        if (!ziti_service_has_permission(s, req->session_type)) {
            CONN_LOG(WARN, "not authorized to %s", ziti_session_types.name(req->session_type));
            complete_conn_req(conn, ZITI_SERVICE_UNAVAILABLE);
            return;
        }

        req->service_id = strdup(s->id);
        conn->encrypted = s->encryption;
        process_connect(conn, NULL);
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        CONN_LOG(ERROR, "service[%s] is not available for ztx[%s]", conn->service, ziti_get_identity(ztx)->name);
        complete_conn_req(conn, ZITI_SERVICE_UNAVAILABLE);
    } else {
        CONN_LOG(WARN, "failed to load service[%s]: %d/%s", conn->service, status, ziti_errorstr(status));
        complete_conn_req(conn, status);
    }
}

static void refresh_session_cb(ziti_session *s, const ziti_error *err, void *ctx) {
    struct ziti_ctx *ztx = ctx;
    if (err) {
        ZITI_LOG(WARN, "failed to refresh session");
    } else if (s != NULL) {
        ZITI_LOG(DEBUG, "ztx[%d] refreshed session[%s]", ztx->id, s->id);
        ziti_session *existing = model_map_set(&ztx->sessions, s->service_id, s);
        free_ziti_session_ptr(existing);
    }
}

static void connect_get_net_session_cb(ziti_session *s, const ziti_error *err, void *ctx) {
    struct ziti_conn *conn = ctx;
    struct ziti_conn_req *req = conn->conn_req;
    struct ziti_ctx *ztx = conn->ziti_ctx;

    if (err != NULL) {
        int e = err->err == ZITI_NOT_FOUND ? ZITI_SERVICE_UNAVAILABLE : (int)err->err;
        CONN_LOG(WARN, "failed to get '%s' session for service[%s]: %s(%s)",
                 ziti_session_types.name(req->session_type), conn->service, err->code, err->message);

        if (err->err == ZITI_NOT_AUTHORIZED) {
            ziti_force_api_session_refresh(ztx);
            restart_connect(conn);
        } else {
            complete_conn_req(conn, e);
        }
    } else {
        ziti_session *existing = model_map_set(&ztx->sessions, req->service_id, s);
        // this happens with concurrent connection requests for the same service (common with browsers)
        if (existing) {
            CONN_LOG(DEBUG, "discarding existing session[%s] for service[%s]", existing->id, conn->service);
            free_ziti_session(existing);
            free(existing);
        } else {
            CONN_LOG(DEBUG, "got session[%s] for service[%s]", s->id, conn->service);
            model_map_set(&ztx->sessions, s->service_id, s);
        }
        process_connect(conn, s);
    }
}

void process_connect(struct ziti_conn *conn, ziti_session *session) {
    assert(conn->conn_req);
    assert(conn->ziti_ctx);

    struct ziti_conn_req *req = conn->conn_req;
    struct ziti_ctx *ztx = conn->ziti_ctx;

    assert(req->session_type == ziti_session_types.Dial);

    // verify ziti context is still authorized
    if (ztx->auth_state != ZitiAuthStateFullyAuthenticated) {
        CONN_LOG(ERROR, "ziti context is not authenticated, cannot connect to service[%s]", conn->service);
        complete_conn_req(conn, ZITI_INVALID_STATE);
        return;
    }

    uv_loop_t *loop = ztx->loop;

    // find service
    if (req->service_id == NULL) {
        // connect_get_service_cb will re-enter process_connect() if service is already cached in the context
        int rc = ziti_service_available(ztx, conn->service, connect_get_service_cb, conn);
        if (rc != ZITI_OK) {
            complete_conn_req(conn, rc);
        }
        return;
    }

    ziti_send_posture_data(ztx);
    if (session == NULL) {
        session = model_map_get(&ztx->sessions, req->service_id);
    }

    if (session == NULL) {
        CONN_LOG(DEBUG, "requesting 'Dial' session for service[%s]", conn->service);
        // this will re-enter with session if create succeeds
        ziti_ctrl_create_session(ztx_get_controller(ztx), req->service_id, ziti_session_types.Dial,
                                 connect_get_net_session_cb, conn);
        return;
    }

    if (model_list_size(&session->edge_routers) == 0) {
        if (session->refresh) {
            ziti_ctrl_get_session(ztx_get_controller(ztx), session->id, connect_get_net_session_cb, conn);
            return;
        } else {
            CONN_LOG(ERROR, "no edge routers available for service[%s] session[%s]", conn->service, session->id);
            complete_conn_req(conn, ZITI_GATEWAY_UNAVAILABLE);
            return;
        }
    }

    if (req->dial_opts.connect_timeout_seconds > 0) {
        ztx_set_deadline(ztx, req->dial_opts.connect_timeout_seconds * 1000,
                         &req->deadline, connect_timeout, conn);
    }

    CONN_LOG(DEBUG, "starting Dial connection for service[%s] with session[%s]", conn->service, session->id);
    if (!ziti_connect(ztx, session, conn)) {
        CONN_LOG(DEBUG, "no active edge routers, pending ER connection");
        // TODO deal with pending connect
    }

    if (session->refresh) {
        CONN_LOG(DEBUG, "refreshing session[%s]", session->id);
        ziti_ctrl_get_session(ztx_get_controller(ztx), session->id, refresh_session_cb, ztx);
        session->refresh = false;
    }
}

static int do_ziti_dial(ziti_connection conn, const char *service, ziti_dial_opts *dial_opts, ziti_conn_cb conn_cb, ziti_data_cb data_cb) {
    if (!conn->ziti_ctx->enabled) { return ZITI_DISABLED; }

    assert(conn->type == None);
    init_transport_conn(conn);

    if (conn->state != Initial) {
        CONN_LOG(ERROR, "can not dial in state[%s]", ziti_conn_state(conn));
        return ZITI_INVALID_STATE;
    }

    if (conn_cb == NULL) {
        CONN_LOG(ERROR, "connect_cb is NULL");
        return ZITI_INVALID_STATE;
    }

    uint8_t marker[MARKER_BIN_LEN];
    uv_random(NULL, NULL, marker, sizeof(marker), 0, NULL);
    sodium_bin2base64(conn->marker, sizeof(conn->marker), marker, sizeof(marker),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    NEWP(req, struct ziti_conn_req);
    conn->service = strdup(service);
    conn->conn_req = req;

    req->session_type = ziti_session_types.Dial;
    req->cb = conn_cb;

    req->dial_opts = DEFAULT_DIAL_OPTS;
    if (dial_opts != NULL) {
        // clone dial_opts to survive the async request
        clone_ziti_dial_opts(&req->dial_opts, dial_opts);

        if (dial_opts->stream) {
            conn->flags |= EDGE_STREAM;
        }
    }

    conn->data_cb = data_cb;
    conn_set_state(conn, Connecting);

    conn->flusher = calloc(1, sizeof(uv_idle_t));
    uv_idle_init(conn->ziti_ctx->loop, conn->flusher);
    conn->flusher->data = conn;

    conn->start = uv_now(conn->ziti_ctx->loop);

    process_connect(conn, NULL);
    return ZITI_OK;
}

extern ziti_context ziti_conn_context(ziti_connection conn) {
    return conn->ziti_ctx;
}

int ziti_dial(ziti_connection conn, const char *service, ziti_conn_cb conn_cb, ziti_data_cb data_cb) {
    return ziti_dial_with_options(conn, service, NULL, conn_cb, data_cb);
}

int ziti_dial_with_options(ziti_connection conn, const char *service, ziti_dial_opts *dial_opts, ziti_conn_cb conn_cb,
                           ziti_data_cb data_cb) {
    return do_ziti_dial(conn, service, dial_opts, conn_cb, data_cb);
}

static void ziti_write_req(struct ziti_write_req_s *req) {
    struct ziti_conn *conn = req->conn;

    if (req->eof) {
        conn_set_state(conn, CloseWrite);
        send_fin_message(conn, req);
    } else if (req->close) {
        // conn->state will be set on_disconnect callback
        message *m = create_message(conn, ContentTypeStateClosed, 0, 0);
        send_message(conn, m, req);
    } else {
        message *m = req->message;
        if (m == NULL) {
            bool multipart = model_list_size(&req->chain) > 0;
            bool stream = conn->flags & EDGE_STREAM;

            uint32_t flags = multipart && !stream ? EDGE_MULTIPART_MSG : 0;
            size_t total_len = conn->encrypted ? crypto_secretstream_xchacha20poly1305_abytes() : 0;
            total_len += (multipart ? req->chain_len : req->len);
            m = create_message(conn, ContentTypeData, flags, total_len);

            if (multipart) {
                uint8_t *p = m->body + conn->encrypted;
                string_buf_t buf;
                string_buf_init_fixed(&buf, (char*)p, total_len);
                struct ziti_write_req_s *r = req;
                model_list_iter it = model_list_iterator(&req->chain);
                int count = 0;
                size_t tot = 0;
                do {
                    if (!stream) {
                        uint16_t part_len = (uint16_t) r->len;
                        part_len = htole16(part_len);
                        string_buf_appendn(&buf, (char *) &part_len, sizeof(part_len));
                    }
                    string_buf_appendn(&buf, (char*)r->buf, r->len);
                    count++;
                    tot += r->len;

                    r = model_list_it_element(it);
                    it = model_list_it_next(it);
                } while(r != NULL);
                CONN_LOG(DEBUG, "consolidated %d payloads total_len[%zd]", count, tot);
                conn->sent += tot;

                if (conn->encrypted) {
                    crypto_secretstream_xchacha20poly1305_push(&conn->crypt_o, m->body, NULL,
                                                               p, req->chain_len, NULL, 0, 0);
                }
                string_buf_free(&buf);
            } else {
                if (conn->encrypted) {
                    crypto_secretstream_xchacha20poly1305_push(&conn->crypt_o, m->body, NULL,
                                                               req->buf, req->len, NULL, 0, 0);
                } else {
                    memcpy(m->body, req->buf, req->len);
                }
                conn->sent += req->len;
            }
        }
        send_message(conn, m, req);
    }
}

static void on_disconnect(ziti_connection conn, ssize_t status, void *ctx) {
    conn_set_state(conn, conn->close ? Closed : Disconnected);
    ziti_channel_t *ch = conn->channel;
    if (ch) {
        ziti_channel_rem_receiver(ch, conn->rt_conn_id);
        conn->channel = NULL;
    }
}

static void ziti_disconnect_async(struct ziti_conn *conn) {
    if (conn->channel == NULL) {
        CONN_LOG(DEBUG, "no channel -- no disconnect");
        on_disconnect(conn, 0, NULL);
    }

    switch (conn->state) {
        case Accepting:
        case Connecting:
        case Connected:
        case CloseWrite:
        case Timedout: {
            NEWP(wr, struct ziti_write_req_s);
            wr->conn = conn;
            wr->close = true;
            wr->cb = on_disconnect;
            TAILQ_INSERT_TAIL(&conn->wreqs, wr, _next);
            flush_connection(conn);
            break;
        }

        default:
            CONN_LOG(DEBUG, "can't send StateClosed in state[%s]", conn_state_str[conn->state]);
            on_disconnect(conn, 0, NULL);
    }
}

static int ziti_disconnect(struct ziti_conn *conn) {
    if (conn->disconnecting) {
        CONN_LOG(DEBUG, "already disconnecting");
        return ZITI_OK;
    }

    if (conn->state == Accepting) {
        reject_dial_request(conn->conn_id, conn->channel, conn->dial_req_seq, "rejected by application");
        conn_set_state(conn, conn->close ? Closed : Disconnected);
        return ZITI_OK;
    }

    if (conn->state <= Timedout) {
        conn->disconnecting = true;
        ziti_disconnect_async(conn);
        return ZITI_OK;
    } else {
        conn_set_state(conn, conn->close ? Closed : Disconnected);
    }
    return ZITI_OK;
}

int establish_crypto(ziti_connection conn, message *msg) {
    if (!conn->encrypted) {
        return ZITI_OK;
    }

    if (conn->state != Connecting && conn->state != Accepting) {
        CONN_LOG(ERROR, "cannot establish crypto in state[%s]", ziti_conn_state(conn));
        return ZITI_INVALID_STATE;
    }

    size_t peer_key_len;
    const uint8_t *peer_key;
    bool peer_key_sent = message_get_bytes_header(msg, PublicKeyHeader, &peer_key, &peer_key_len);
    if (!peer_key_sent) {
        CONN_LOG(ERROR, "failed to establish crypto for encrypted service: did not receive peer key");
        return ZITI_CRYPTO_FAIL;
    }

    int rc = init_crypto(&conn->key_ex, &conn->key_pair, peer_key, conn->state == Accepting);

    if (rc != 0) {
        CONN_LOG(ERROR, "failed to establish encryption: crypto error");
        free_key_exchange(&conn->key_ex);
        return ZITI_CRYPTO_FAIL;
    }
    return ZITI_OK;
}

static int send_crypto_header(ziti_connection conn) {
    if (conn->encrypted) {
        size_t crypto_header_len = crypto_secretstream_xchacha20poly1305_headerbytes();
        message *m = create_message(conn, ContentTypeData, 0, crypto_header_len);
        crypto_secretstream_xchacha20poly1305_init_push(&conn->crypt_o, m->body, conn->key_ex.tx);
        NEWP(wr, struct ziti_write_req_s);
        wr->conn = conn;
        wr->message = m;

        TAILQ_INSERT_HEAD(&conn->wreqs, wr, _next);
        flush_connection(conn);
    }
    return ZITI_OK;
}

static void on_flush(uv_idle_t *fl) {
    ziti_connection conn = fl->data;
    if (conn == NULL) {
        uv_close((uv_handle_t *) fl, (uv_close_cb) free);
        return;
    }

    bool more_to_client = flush_to_client(conn);
    bool more_to_service = flush_to_service(conn);

    if (!more_to_client && !more_to_service) {
        CONN_LOG(TRACE, "stopping flusher");
        uv_idle_stop(fl);
    }
}

static void flush_connection(ziti_connection conn) {
    if (conn->flusher && !uv_is_active((const uv_handle_t *) conn->flusher)) {
        CONN_LOG(TRACE, "starting flusher");
        uv_idle_start(conn->flusher, on_flush);
    }
    conn->last_activity = uv_now(conn->ziti_ctx->loop);
}

void chain_data_requests(ziti_connection conn, struct ziti_write_req_s *req) {
    if (req->message)
        return;

    int boundary_len = (conn->flags & EDGE_STREAM) ? 0 : 2;
#define MAX_CHAIN_LEN (31 * 1024)
    size_t chain_len = 0;
    if (req->len + boundary_len >= MAX_CHAIN_LEN)
        return;

    chain_len += (req->len + boundary_len);

    while(!TAILQ_EMPTY(&conn->wreqs)) {
        struct ziti_write_req_s *next = TAILQ_FIRST(&conn->wreqs);
        if (next->message || next->close || next->eof)
            break;

        if (chain_len + next->len + boundary_len > MAX_CHAIN_LEN)
            break;

        TAILQ_REMOVE(&conn->wreqs, next, _next);
        model_list_append(&req->chain, next);
        chain_len += (next->len + boundary_len);
    }

    if (model_list_size(&req->chain) > 0) {
        req->chain_len = chain_len;
    }
}

static bool flush_to_service(ziti_connection conn) {

    // still connecting
    if (conn->channel == NULL) { return false; }
    if (conn->state < Connected || conn->state == Accepting) { return false; }

    int count = 0;
    while (!TAILQ_EMPTY(&conn->wreqs)) {
        struct ziti_write_req_s *req = TAILQ_FIRST(&conn->wreqs);
        TAILQ_REMOVE(&conn->wreqs, req, _next);

        if (conn->state == Connected || req->close) {
            if ((conn->flags & (EDGE_MULTIPART | EDGE_STREAM)) &&
                !req->close && !req->eof) {
                chain_data_requests(conn, req);
            }

            if (req->conn) {
                TAILQ_INSERT_TAIL(&conn->pending_wreqs, req, _next);
            }
            ziti_write_req(req);
            count++;
        } else {
            CONN_LOG(DEBUG, "got write msg[%s] in invalid state[%s]",
                     req->message ? content_type_id(req->message->header.content) : "null",
                     conn_state_str[conn->state]);

            if (req->cb) {
                req->cb(conn, ZITI_INVALID_STATE, req->ctx);
            }
            free(req);
        }
    }
    CONN_LOG(TRACE, "flushed %d messages", count);

    return !TAILQ_EMPTY(&conn->wreqs);
}

static bool flush_to_client(ziti_connection conn) {
    while (!TAILQ_EMPTY(&conn->in_q)) {
        message *m = TAILQ_FIRST(&conn->in_q);
        TAILQ_REMOVE(&conn->in_q, m, _next);
        process_edge_message(conn, m);
        pool_return_obj(m);
    }

    if (conn->data_cb == NULL) {
        CONN_LOG(DEBUG, "no data_cb: can't flush, %zu bytes available", buffer_available(conn->inbound));
        return false;
    }

    CONN_LOG(VERBOSE, "%zu bytes available", buffer_available(conn->inbound));
    int flushes = 128;
    while (conn->data_cb && buffer_available(conn->inbound) > 0 && (flushes--) > 0) {
        uint8_t *chunk;
        ssize_t chunk_len = buffer_get_next(conn->inbound, 16 * 1024, &chunk);
        ssize_t consumed = conn->data_cb(conn, chunk, chunk_len);
        CONN_LOG(TRACE, "client consumed %zd out of %zd bytes", consumed, chunk_len);

        if (consumed < 0) {
            CONN_LOG(WARN, "client indicated error[%zd] accepting data (%zd bytes buffered)",
                     consumed, buffer_available(conn->inbound));
            break;
        } else if (consumed < chunk_len) {
            buffer_push_back(conn->inbound, (chunk_len - consumed));
            CONN_LOG(VERBOSE, "client stalled: %zd bytes buffered", buffer_available(conn->inbound));
            break;
        }
    }

    if (buffer_available(conn->inbound) > 0) {
        CONN_LOG(VERBOSE, "%zu bytes still available", buffer_available(conn->inbound));
        // no need to schedule flush if client closed or paused receiving
        return conn->data_cb != NULL;
    }

    if (conn->fin_recv == 1 && conn->data_cb) { // if fin was received and all data is flushed, signal EOF
        conn->fin_recv = 2;
        conn->data_cb(conn, NULL, ZITI_EOF);
    }

    if (conn->state == Disconnected) {
        if (conn->data_cb) {
            conn->data_cb(conn, NULL, ZITI_CONN_CLOSED);
        }
    }
    return false;
}

void conn_inbound_data_msg(ziti_connection conn, message *msg) {
    if (conn->state >= Disconnected || conn->fin_recv) {
        CONN_LOG(WARN, "inbound data on closed connection");
        return;
    }

    uint8_t *plain_text = NULL;
    unsigned long long plain_len = 0;
    int32_t flags = 0;
    message_get_int32_header(msg, FlagsHeader, &flags);

    if (conn->encrypted) {
        PREP(crypto);
        // first message is expected to be peer crypto header
        if (conn->key_ex.rx != NULL) {
            CONN_LOG(VERBOSE, "processing crypto header(%d bytes)", msg->header.body_len);
            TRY(crypto, msg->header.body_len != crypto_secretstream_xchacha20poly1305_HEADERBYTES);
            TRY(crypto, crypto_secretstream_xchacha20poly1305_init_pull(&conn->crypt_i, msg->body, conn->key_ex.rx));
            CONN_LOG(VERBOSE, "processed crypto header");
            FREE(conn->key_ex.rx);
        } else {
            unsigned char tag;
            if (msg->header.body_len > 0) {
                plain_text = malloc(msg->header.body_len - crypto_secretstream_xchacha20poly1305_ABYTES);
                assert(plain_text != NULL);
                CONN_LOG(VERBOSE, "decrypting %d bytes", msg->header.body_len);
                int crypto_rc = crypto_secretstream_xchacha20poly1305_pull(&conn->crypt_i,
                                                                           plain_text, &plain_len, &tag,
                                                                           msg->body, msg->header.body_len, NULL, 0);
                if (crypto_rc != 0 && (conn->flags & EDGE_TRACE_UUID)) {
                    // try to figure out the cause of crypto error
                    struct msg_uuid *uuid;
                    size_t uuid_len;
                    struct local_hash h;
                    crypto_hash_sha256(h.hash, msg->body, msg->header.body_len);

                    if (message_get_bytes_header(msg, UUIDHeader, (const uint8_t **) &uuid, &uuid_len)) {
                        CONN_LOG(ERROR, "uuid[" UUID_FMT "] %s corruption hash[" HASH_FMT "]",
                                 UUID_FMT_ARG(uuid),
                                 uuid->slug != htole32(h.i32[0]) ? "payload" : "crypto state",
                                 HASH_FMT_ARG(h));
                    } else {
                        CONN_LOG(ERROR, "message/state corruption hash[" HASH_FMT "]",
                                 HASH_FMT_ARG(h));
                    }
                }

                TRY(crypto, crypto_rc);
                CONN_LOG(VERBOSE, "decrypted %lld bytes tag[%x]", plain_len, (int)tag);
            }
        }

        CATCH(crypto) {
            FREE(plain_text);
            conn_set_state(conn, Disconnected);
            conn->data_cb(conn, NULL, ZITI_CRYPTO_FAIL);
            return;
        }
    } else if (msg->header.body_len > 0) {
        plain_text = malloc(msg->header.body_len);
        plain_len = msg->header.body_len;
        memcpy(plain_text, msg->body, msg->header.body_len);
    }

    if (plain_text) {
        if (flags & EDGE_MULTIPART_MSG) {
            CONN_LOG(TRACE, "chunking multipart[%llu] message", plain_len);
            uint8_t *end = plain_text + plain_len;
            uint8_t *p = plain_text;

            do {
                uint16_t partlen;
                memcpy(&partlen, p, sizeof(partlen));
                p += sizeof(partlen);
                partlen = le32toh(partlen);
                buffer_append_copy(conn->inbound, p, partlen);
                p += partlen;
                CONN_LOG(TRACE, "chunk[%d]", partlen);
            } while (p < end);
            free(plain_text);
        } else {
            buffer_append(conn->inbound, plain_text, plain_len);
            metrics_rate_update(&conn->ziti_ctx->down_rate, (int64_t) plain_len);
            conn->received += plain_len;
        }
    }

    if (flags & EDGE_FIN) {
        conn->fin_recv = true;
    }
}

static void restart_connect(struct ziti_conn *conn) {
    if (!conn->conn_req || conn->state != Connecting) {
        CONN_LOG(ERROR, "connect retry in invalid state");
        return;
    }

    if (++conn->conn_req->retry_count >= MAX_CONNECT_RETRY) {
        CONN_LOG(ERROR, "failed to connect after %d retries", conn->conn_req->retry_count);
        complete_conn_req(conn, ZITI_SERVICE_UNAVAILABLE);
        return;
    }

    CONN_LOG(DEBUG, "restarting connect sequence");
    conn->channel = NULL;

    process_connect(conn, NULL);
}

void connect_reply_cb(void *ctx, message *msg, int err) {
    struct ziti_conn *conn = ctx;
    struct ziti_conn_req *req = conn->conn_req;

    clear_deadline(&req->deadline);

    req->waiter = NULL;
    if (err != 0 && msg == NULL) {
        CONN_LOG(ERROR, "failed to %s [%d/%s]", "connect", err, ziti_errorstr(err));
        conn_set_state(conn, Disconnected);
        complete_conn_req(conn, ZITI_CONN_CLOSED);
        return;
    }

    switch (msg->header.content) {
        case ContentTypeStateClosed:
            if (strncmp(INVALID_SESSION, (const char *) msg->body, msg->header.body_len) == 0) {
                CONN_LOG(WARN, "session for service[%s] became invalid", conn->service);
                ziti_invalidate_session(conn->ziti_ctx, conn->conn_req->service_id, ziti_session_types.Dial);
                ziti_channel_rem_receiver(conn->channel, conn->rt_conn_id);
                conn->channel = NULL;
                restart_connect(conn);
            } else {
                CONN_LOG(ERROR, "failed to %s, reason=%*.*s",
                         "connect",
                         msg->header.body_len, msg->header.body_len, msg->body);
                conn_set_state(conn, Disconnected);
                complete_conn_req(conn, ZITI_CONN_CLOSED);
            }
            break;

        case ContentTypeStateConnected:
            if (conn->state == Connecting) {
                CONN_LOG(TRACE, "connected");
                int rc = ZITI_OK;
                if (conn->encrypted) {
                    rc = establish_crypto(conn, msg);
                    if (rc == ZITI_OK) {
                        send_crypto_header(conn);
                    }
                }
                conn_set_state(conn, rc == ZITI_OK ? Connected : Disconnected);
                complete_conn_req(conn, rc);
            } else if (conn->state == Accepting) {
                CONN_LOG(TRACE, "accepted");
                if (conn->encrypted) {
                    send_crypto_header(conn);
                }
                conn_set_state(conn, Connected);
                complete_conn_req(conn, ZITI_OK);
            } else if (conn->state >= Timedout) {
                CONN_LOG(WARN, "received connect reply for closed/timedout");
                ziti_disconnect(conn);
            }
            break;

        default:
            CONN_LOG(WARN, "unexpected content_type[%s]", content_type_id(msg->header.content));
            ziti_disconnect(conn);
    }
}

static int ziti_channel_start_connection(struct ziti_conn *conn, ziti_channel_t *ch, ziti_session *session) {
    struct ziti_conn_req *req = conn->conn_req;

    uint32_t content_type;
    switch (conn->state) {
        case Connecting:
            content_type = ContentTypeConnect;
            break;
        case Disconnected:
            CONN_LOG(WARN, "channel did not connect in time");
            return ZITI_OK;
        default:
            CONN_LOG(ERROR, "in unexpected state[%d]", conn->state);
            return ZITI_WTF;
    }

    CONN_LOG(TRACE, "ch[%d] => Edge Connect request token[%s]", ch->id, session->token);
    conn->channel = ch;
    ziti_channel_add_receiver(ch, conn->rt_conn_id, conn,
                              (void (*)(void *, message *, int)) queue_edge_message);

    int32_t conn_id = htole32(conn->rt_conn_id);
    int32_t msg_seq = htole32(0);

    const ziti_identity *identity = ziti_get_identity(conn->ziti_ctx);
    hdr_t headers[] = {
            {
                    .header_id = ConnIdHeader,
                    .length = sizeof(conn_id),
                    .value = (uint8_t *) &conn_id
            },
            {
                    .header_id = ConnectionMarkerHeader,
                    .length = sizeof(conn->marker),
                    .value = (uint8_t *) conn->marker,
            },
            {
                    .header_id = SeqHeader,
                    .length = sizeof(msg_seq),
                    .value = (uint8_t *) &msg_seq
            },
            {
                    .header_id = CallerIdHeader,
                    .length = strlen(identity->name),
                    .value = (uint8_t *) identity->name,
            },
            {
                    .header_id = PublicKeyHeader,
                    .length = sizeof(conn->key_pair.pk),
                    .value = conn->key_pair.pk,
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
    int nheaders = 4;
    if (conn->encrypted) {
        init_key_pair(&conn->key_pair);
        nheaders++;
    }

    if (req->dial_opts.identity != NULL) {
        headers[nheaders].header_id = TerminatorIdentityHeader;
        headers[nheaders].value = (uint8_t *) req->dial_opts.identity;
        headers[nheaders].length = strlen(req->dial_opts.identity);
        nheaders++;
    }

    if (req->dial_opts.app_data != NULL) {
        headers[nheaders].header_id = AppDataHeader;
        headers[nheaders].value = req->dial_opts.app_data;
        headers[nheaders].length = req->dial_opts.app_data_sz;
        nheaders++;
    }

    req->waiter = ziti_channel_send_for_reply(ch, content_type, headers, nheaders,
                                              session->token, strlen(session->token),
                                              connect_reply_cb, conn);

    return ZITI_OK;
}

static void accept_cb(ziti_connection conn, ssize_t i, void *data) {
    ziti_conn_cb cb = data;
    if (i < 0) {
        CONN_LOG(ERROR, "accept failed: %zd[%s]", i, ziti_errorstr(i));
        conn_set_state(conn, Disconnected);
        if (cb) {
            cb(conn, (int)i);
        }
        return;
    }
    conn_set_state(conn, Connected);
    if (conn->encrypted) {
        send_crypto_header(conn);
    }

    if (cb) {
        CONN_LOG(TRACE, "accept succeeded");
        cb(conn, ZITI_OK);
    }
}

int ziti_accept(ziti_connection conn, ziti_conn_cb cb, ziti_data_cb data_cb) {

    if (conn->state == Disconnected) {
        return ZITI_CONN_CLOSED;
    }

    if (conn->state != Accepting) {
        return ZITI_INVALID_STATE;
    }

    CONN_LOG(DEBUG, "accepting");
    ziti_channel_t *ch = conn->channel;
    conn->data_cb = data_cb;

    TAILQ_INIT(&conn->in_q);
    conn->flusher = calloc(1, sizeof(uv_idle_t));
    uv_idle_init(conn->ziti_ctx->loop, conn->flusher);
    conn->flusher->data = conn;
    uv_unref((uv_handle_t *) &conn->flusher);

    ziti_channel_add_receiver(ch, conn->rt_conn_id, conn, (void (*)(void *, message *, int)) queue_edge_message);

    CONN_LOG(TRACE, "ch[%d] => Edge Accept parent_conn_id[%d]", ch->id, conn->parent->conn_id);

    uint32_t content_type = ContentTypeDialSuccess;

    int32_t conn_id = htole32(conn->parent->conn_id);
    int32_t msg_seq = htole32(0);
    int32_t reply_id = htole32(conn->dial_req_seq);
    int32_t clt_conn_id = htole32(conn->rt_conn_id);
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

    struct ziti_write_req_s *ar = calloc(1, sizeof(*ar));
    ar->conn = conn;
    ar->cb = accept_cb;
    ar->ctx = cb;

    TAILQ_INSERT_TAIL(&conn->pending_wreqs, ar, _next);
    int rc = ziti_channel_send(ch, content_type, headers, 3,
                               (const uint8_t *) &clt_conn_id, sizeof(clt_conn_id),
                               ar);
    return rc;
}

int ziti_write(ziti_connection conn, uint8_t *data, size_t length, ziti_write_cb write_cb, void *write_ctx) {
    if (conn->fin_sent) {
        CONN_LOG(ERROR, "attempted write after ziti_close_write()");
        return ZITI_INVALID_STATE;
    }

    if (conn->state != Connected && conn->state != Connecting) {
        CONN_LOG(ERROR, "attempted write in invalid state[%s]", ziti_conn_state(conn));
        return ZITI_INVALID_STATE;
    }

    NEWP(req, struct ziti_write_req_s);
    req->conn = conn;
    req->buf = data;
    req->len = length;
    req->cb = write_cb;
    req->ctx = write_ctx;
    CONN_LOG(TRACE, "write %zd bytes", length);
    metrics_rate_update(&conn->ziti_ctx->up_rate, (long)length);

    TAILQ_INSERT_TAIL(&conn->wreqs, req, _next);
    flush_connection(conn);

    return 0;
}

static int send_fin_message(ziti_connection conn, struct ziti_write_req_s *wr) {
    CONN_LOG(DEBUG, "sending FIN");
    message *m = create_message(conn, ContentTypeData, EDGE_FIN, 0);
    return send_message(conn, m, wr);
}

int ziti_close(ziti_connection conn, ziti_close_cb close_cb) {

    if (conn == NULL) return ZITI_INVALID_STATE;
    if (conn->close) return ZITI_CONN_CLOSED;

    conn->close = true;
    conn->close_cb = close_cb;

    if (conn->type == Server) {
        return ziti_close_server(conn);
    }

    conn->data_cb = NULL;
    return ziti_disconnect(conn);
}


int ziti_close_write(ziti_connection conn) {
    if (conn->fin_sent || conn->state >= CloseWrite) {
        return ZITI_OK;
    }

    NEWP(req, struct ziti_write_req_s);
    req->conn = conn;
    req->eof = true;

    TAILQ_INSERT_TAIL(&conn->wreqs, req, _next);
    conn->fin_sent = true;

    flush_connection(conn);
    return ZITI_OK;
}

void reject_dial_request(uint32_t conn_id, ziti_channel_t *ch, uint32_t req_id, const char *reason) {

    ZITI_LOG(TRACE, "ch[%d] => rejecting Dial request: %s", ch->id, reason);

    conn_id = htole32(conn_id);
    int32_t msg_seq = htole32(0);
    int32_t reply_id = htole32(req_id);
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

    message *m = message_new(NULL, ContentTypeDialFailed, headers, 3, strlen(reason));
    memcpy(m->body, reason, strlen(reason));

    ziti_channel_send_message(ch, m, NULL);
}

static void queue_edge_message(struct ziti_conn *conn, message *msg, int code) {
    if (msg == NULL) {
        CONN_LOG(DEBUG, "closed due to err[%d](%s)", code, ziti_errorstr(code));
        conn_state st = conn->state;
        on_disconnect(conn, code, NULL);

        switch (st) {
            case Connecting:
            case Accepting:
                complete_conn_req(conn, code);
                break;
            case Connected:
            case CloseWrite:
                if (conn->data_cb) conn->data_cb(conn, NULL, code);
                break;
            default:
                CONN_LOG(WARN, "disconnecting from state[%d]", st);
        }
        return;
    }

    if (msg->header.content == ContentTypeConnInspectRequest) {
        char conn_info[256];
        size_t ci_len = snprintf(conn_info, sizeof(conn_info),
                                 "id[%d/%s] serviceName[%s] closed[%s] encrypted[%s] "
                                 "recvFIN[%s] sentFIN[%s]",
                                 conn->conn_id, conn->marker, conn->service, BOOL_STR(conn->close), BOOL_STR(conn->encrypted),
                                 BOOL_STR(conn->fin_recv), BOOL_STR(conn->fin_sent));
        message *reply = new_inspect_result(msg->header.seq, conn->conn_id, ConnTypeDial, conn_info, ci_len);
        send_message(conn, reply, NULL);
        pool_return_obj(msg);
        return;
    }

    TAILQ_INSERT_TAIL(&conn->in_q, msg, _next);
    flush_connection(conn);
}

static void process_edge_message(struct ziti_conn *conn, message *msg) {
    int rc;
    int32_t seq;
    int32_t conn_id;
    uint32_t flags = 0;
    struct msg_uuid *uuid;
    size_t uuid_len;
    bool has_seq = message_get_int32_header(msg, SeqHeader, &seq);
    bool has_conn_id = message_get_int32_header(msg, ConnIdHeader, &conn_id);
    assert(has_conn_id && conn_id == conn->rt_conn_id);

    message_get_int32_header(msg, FlagsHeader, (int32_t*)&flags);
    uint32_t caps = flags & CONN_CAP_MASK;
    if (caps != 0) {
        CONN_LOG(DEBUG, "peer capability: stream[%s] multipart[%s] trace[%s]",
                 BOOL_STR(caps & EDGE_STREAM), BOOL_STR(caps & EDGE_MULTIPART), BOOL_STR(caps & EDGE_TRACE_UUID)
        );
        conn->flags |= caps;
    }

    if ((conn->flags & EDGE_TRACE_UUID) &&
        message_get_bytes_header(msg, UUIDHeader, (const uint8_t **) &uuid, &uuid_len)) {
        struct local_hash h;
        crypto_hash_sha256(h.hash, msg->body, msg->header.body_len);
        CONN_LOG(TRACE, "<= ct[%s] uuid[" UUID_FMT "] edge_seq[%d] len[%d] ",
                 content_type_id(msg->header.content), UUID_FMT_ARG(uuid), seq, msg->header.body_len);

        if (uuid->seq != conn->in_msg_seq) {
            CONN_LOG(WARN, "unexpected msg_seq[%d] previous[%d]", uuid->seq, conn->in_msg_seq);
        }
        conn->in_msg_seq = uuid->seq + 1;
    } else {
        CONN_LOG(TRACE, "<= ct[%s] edge_seq[%d] len[%d]", content_type_id(msg->header.content), seq, msg->header.body_len);
    }


    switch (msg->header.content) {
        case ContentTypeStateClosed:
            CONN_LOG(DEBUG, "connection status[%s] seq[%d] err[%.*s]", content_type_id(msg->header.content), seq,
                     msg->header.body_len, msg->body);
            bool retry_connect = false;

            switch (conn->state) {
                case Connecting:
                case Accepting: {
                    if (strncmp(INVALID_SESSION, (const char *) msg->body, msg->header.body_len) == 0) {
                        CONN_LOG(WARN, "session for service[%s] became invalid", conn->service);
                        ziti_invalidate_session(conn->ziti_ctx, conn->conn_req->service_id, conn->conn_req->session_type);
                        retry_connect = true;
                    }
                    if (retry_connect) {
                        ziti_channel_rem_receiver(conn->channel, conn->rt_conn_id);
                        conn->channel = NULL;
                        conn_set_state(conn, Connecting);
                        restart_connect(conn);
                    } else {
                        CONN_LOG(ERROR, "failed to connect, reason=%.*s",
                                 msg->header.body_len, msg->body);
                        conn_set_state(conn, Disconnected);
                        complete_conn_req(conn, ZITI_CONN_CLOSED);
                    }
                    break;
                }

                case Connected:
                case CloseWrite:
                    conn_set_state(conn, Disconnected);
                    break;

                case Disconnected:
                case Closed:
                    // no more data_cb is expected
                    break;

                default:
                    CONN_LOG(ERROR, "unexpected msg for in state[%s]: %s",
                             ziti_conn_state(conn), ziti_errorstr(ZITI_WTF));
                    break;
            }
            break;

        case ContentTypeData:
            switch (conn->state) {
                case Connected:
                case CloseWrite:
                    conn_inbound_data_msg(conn, msg);
                    break;
                default:
                    if (msg->header.body_len > 0) {
                        CONN_LOG(WARN, "data[%d bytes] received in state[%s]", msg->header.body_len, ziti_conn_state(conn));
                    }
            }
            break;

        case ContentTypeStateConnected:
            if (conn->state == Connecting) {
                CONN_LOG(TRACE, "connected");
                rc = establish_crypto(conn, msg);
                if (rc == ZITI_OK && conn->encrypted) {
                    send_crypto_header(conn);
                }
                conn_set_state(conn, rc == ZITI_OK ? Connected : Disconnected);
                complete_conn_req(conn, rc);
            } else if (conn->state == Accepting) {
                CONN_LOG(TRACE, "accepted");
                if (conn->encrypted) {
                    send_crypto_header(conn);
                }
                conn_set_state(conn, Connected);
                complete_conn_req(conn, ZITI_OK);
            } else if (conn->state >= Timedout) {
                CONN_LOG(WARN, "received connect reply in closed/timedout state");
                ziti_disconnect(conn);
            }
            break;

        default:
            CONN_LOG(ERROR, "received unexpected content_type[%s]", content_type_id(msg->header.content));
    }
}

void init_transport_conn(struct ziti_conn *c) {
    c->type = Transport;
    c->disposer = close_conn_internal;

    TAILQ_INIT(&c->in_q);
    TAILQ_INIT(&c->wreqs);
    TAILQ_INIT(&c->pending_wreqs);
    c->inbound = new_buffer();
}
