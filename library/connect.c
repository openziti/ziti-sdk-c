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

#include <stdlib.h>
#include <posture.h>
#include <assert.h>

#include "endian_internal.h"
#include "win32_compat.h"
#include "connect.h"

static const char *INVALID_SESSION = "Invalid Session";
static const int MAX_CONNECT_RETRY = 3;

#define CONN_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "conn[%u.%u/%s] " fmt, conn->ziti_ctx->id, conn->conn_id, conn_state_str[conn->state], ##__VA_ARGS__)



static const char *conn_state_str[] = {
#define state_str(ST) #ST ,
        conn_states(state_str)
};


struct ziti_conn_req {
    ziti_session_type session_type;
    char *service_id;
    ziti_net_session *session;
    ziti_conn_cb cb;
    ziti_dial_opts *dial_opts;
    ziti_listen_opts *listen_opts;

    int retry_count;
    uv_timer_t *conn_timeout;
    struct waiter_s *waiter;
    bool failed;
};

static void flush_connection(ziti_connection conn);

static bool flush_to_service(ziti_connection conn);

static bool flush_to_client(ziti_connection conn);

static void process_connect(struct ziti_conn *conn);

static int send_fin_message(ziti_connection conn);

static void queue_edge_message(struct ziti_conn *conn, message *msg, int code);

static void process_edge_message(struct ziti_conn *conn, message *msg);

static int ziti_channel_start_connection(struct ziti_conn *conn, ziti_channel_t *ch);

static int ziti_disconnect(ziti_connection conn);

static void restart_connect(struct ziti_conn *conn);

static void free_handle(uv_handle_t *h) {
    free(h);
}

const char *ziti_conn_state(ziti_connection conn) {
    return conn ? conn_state_str[conn->state] : "<NULL>";
}

static void conn_set_state(struct ziti_conn *conn, enum conn_state state) {
    CONN_LOG(VERBOSE, "transitioning %s => %s", conn_state_str[conn->state], conn_state_str[state]);
    conn->state = state;
}

static ziti_dial_opts *clone_ziti_dial_opts(const ziti_dial_opts *dial_opts) {
    if (dial_opts == NULL) {
        ZITI_LOG(TRACE, "refuse to clone NULL dial_opts");
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
        ZITI_LOG(TRACE, "refuse to free NULL dial_opts");
        return;
    }
    FREE(dial_opts->identity);
    FREE(dial_opts->app_data);
    free(dial_opts);
}

static ziti_listen_opts *clone_ziti_listen_opts(const ziti_listen_opts *ln_opts) {
    if (ln_opts == NULL) {
        ZITI_LOG(TRACE, "refuse to clone NULL listen_opts");
        return NULL;
    }
    ziti_listen_opts *c = calloc(1, sizeof(ziti_listen_opts));
    memcpy(c, ln_opts, sizeof(ziti_listen_opts));
    if (ln_opts->identity != NULL) c->identity = strdup(ln_opts->identity);
    return c;
}

static void free_ziti_listen_opts(ziti_listen_opts *ln_opts) {
    if (ln_opts == NULL) {
        ZITI_LOG(TRACE, "refuse to free NULL listen_opts");
        return;
    }
    FREE(ln_opts->identity);
    free(ln_opts);
}

static void free_conn_req(struct ziti_conn_req *r) {
    if (r->conn_timeout != NULL) {
        uv_close((uv_handle_t *) r->conn_timeout, free_handle);
    }

    if (r->session_type == ziti_session_types.Bind && r->session) {
        free_ziti_net_session(r->session);
        FREE(r->session);
    }

    free_ziti_dial_opts(r->dial_opts);
    free_ziti_listen_opts(r->listen_opts);
    FREE(r->service_id);
    free(r);
}

static int close_conn_internal(struct ziti_conn *conn) {
    assert(conn->type == Transport);

    if (conn->state == Closed && conn->write_reqs <= 0) {
        CONN_LOG(DEBUG, "removing");

        while (!TAILQ_EMPTY(&conn->wreqs)) {
            struct ziti_write_req_s *req = TAILQ_FIRST(&conn->wreqs);
            TAILQ_REMOVE(&conn->wreqs, req, _next);
            if (req->cb) {
                req->cb(conn, ZITI_INVALID_STATE, req->ctx);
            }
            free(req);
        }

        if (conn->close_cb) {
            conn->close_cb(conn);
        }

        if (conn->channel) {
            ziti_channel_rem_receiver(conn->channel, conn->conn_id);
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
    conn->write_reqs--;

    if (req->timeout != NULL) {
        uv_timer_stop(req->timeout);
        uv_close((uv_handle_t *) req->timeout, free_handle);
        req->timeout = NULL;
    }

    if (status < 0) {
        conn_set_state(conn, Disconnected);
        CONN_LOG(DEBUG, "is now Disconnected due to write failure: %d", status);
    }

    if (req->cb != NULL) {
        if (status == 0) {
            status = req->len;
        }

        req->cb(conn, status, req->ctx);
    }

    free(req);
}

message *create_message(struct ziti_conn *conn, uint32_t content, size_t body_len) {
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
    return message_new(NULL, content, headers, 2, body_len);
}

static int send_message(struct ziti_conn *conn, message *m, struct ziti_write_req_s *wr) {
    ziti_channel_t *ch = conn->channel;
    return ziti_channel_send_message(ch, m, wr);
}

static void on_channel_connected(ziti_channel_t *ch, void *ctx, int status) {
    uintptr_t cid = (uintptr_t) ctx;
    uint32_t conn_id = (uint32_t) cid;
    ziti_context ztx = ch->ctx;

    // check if it is still a valid connection;
    // connection may be completed and gone by the time this channel gets connected
    struct ziti_conn *conn = model_map_getl(&ztx->connections, (long) conn_id);
    if (conn == NULL) {
        ZTX_LOG(VERBOSE, "ch[%d] connection(id = %d) is gone", ch->id, conn_id);
        return;
    }

    // if channel was already selected
    if (conn->channel != NULL) {
        CONN_LOG(TRACE, "is already using another channel");
    } else {
        if (status < 0) {
            ZTX_LOG(ERROR, "ch[%d] failed to connect [%d/%s]", ch->id, status, uv_strerror(status));
        } else if (conn->conn_req && conn->conn_req->failed) {
            CONN_LOG(DEBUG, "request already timed out or closed");
        } else { // first channel to connect
            CONN_LOG(DEBUG, "selected ch[%s] status[%d]", ch->name, status);

            ziti_channel_start_connection(conn, ch);
        }
    }
}

static void complete_conn_req(struct ziti_conn *conn, int code) {
    if (conn->conn_req && conn->conn_req->cb) {
        if (code != ZITI_OK) {
            conn_set_state(conn, code == ZITI_TIMEOUT ? Timedout : Disconnected);
            conn->conn_req->failed = true;
            conn->data_cb = NULL;
        }
        if (conn->conn_req->conn_timeout != NULL) {
            uv_timer_stop(conn->conn_req->conn_timeout);
        }
        conn->conn_req->cb(conn, code);
        conn->conn_req->cb = NULL;

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
    } else {
        CONN_LOG(WARN, "connection attempt was already completed");
    }
}

static void connect_timeout(uv_timer_t *timer) {
    struct ziti_conn *conn = timer->data;

    ziti_channel_t *ch = conn->channel;
    uv_close((uv_handle_t *) timer, free_handle);
    conn->conn_req->conn_timeout = NULL;

    if (conn->state == Connecting) {
        if (ch == NULL) {
            CONN_LOG(WARN, "connect timeout: no suitable edge router");
        } else {
            CONN_LOG(WARN, "failed to establish connection in %dms on ch[%d]", conn->timeout, ch->id);
        }
        complete_conn_req(conn, ZITI_TIMEOUT);
        ziti_disconnect(conn);
    } else {
        CONN_LOG(ERROR, "timeout in unexpected state[%s]", ziti_conn_state(conn));
    }
}

static int ziti_connect(struct ziti_ctx *ztx, const ziti_net_session *session, struct ziti_conn *conn) {
    // verify ziti context is still authorized
    if (ztx->api_session == NULL) {
        CONN_LOG(ERROR, "ziti context is not authenticated, cannot connect to service[%s]", conn->service);
        complete_conn_req(conn, ZITI_INVALID_STATE);
        return ZITI_INVALID_STATE;
    }

    if (model_list_size(&session->edge_routers) == 0) {
        CONN_LOG(ERROR, "no edge routers available for service[%s] session[%s]", conn->service, session->id);
        complete_conn_req(conn, ZITI_GATEWAY_UNAVAILABLE);
        return ZITI_GATEWAY_UNAVAILABLE;
    }

    conn->channel = NULL;

    ziti_edge_router *er;
    ziti_channel_t *best_ch = NULL;
    uint64_t best_latency = UINT64_MAX;
    uintptr_t conn_id = conn->conn_id;

    MODEL_LIST_FOREACH(er, session->edge_routers) {
        const char *tls = model_map_get(&er->protocols, "tls");
        if (tls == NULL) {
            tls = model_map_get(&er->ingress, "tls");
        }

        if (tls) {
            ziti_channel_t *ch = model_map_get(&ztx->channels, tls);

            if (ch != NULL && ch->state == Connected) {
                if (ch->latency < best_latency) {
                    best_ch = ch;
                    best_latency = ch->latency;
                }
            } else {
                CONN_LOG(TRACE, "connecting to %s(%s) for session[%s]", er->name, tls, session->id);
                ziti_channel_connect(ztx, er->name, tls, on_channel_connected, (void *) conn_id);
            }
        }
    }

    if (best_ch) {
        CONN_LOG(DEBUG, "selected ch[%s@%s] for best latency(%llu ms)", best_ch->name, best_ch->url,
                 (unsigned long long) best_ch->latency);
        on_channel_connected(best_ch, (void *) conn_id, ZITI_OK);
    }

    return 0;
}

static void connect_get_service_cb(ziti_context ztx, ziti_service *s, int status, void *ctx) {
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
        process_connect(conn);
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        CONN_LOG(ERROR, "service[%s] is not available for ztx[%s]", conn->service, ztx->api_session->identity->name);
        complete_conn_req(conn, ZITI_SERVICE_UNAVAILABLE);
    } else {
        CONN_LOG(WARN, "failed to load service[%s]: %d/%s", conn->service, status, ziti_errorstr(status));
        complete_conn_req(conn, status);
    }
}

static void connect_get_net_session_cb(ziti_net_session *s, const ziti_error *err, void *ctx) {
    struct ziti_conn *conn = ctx;
    struct ziti_conn_req *req = conn->conn_req;
    struct ziti_ctx *ztx = conn->ziti_ctx;

    if (err != NULL) {
        int e = err->err == ZITI_NOT_FOUND ? ZITI_SERVICE_UNAVAILABLE : err->err;
        CONN_LOG(WARN, "failed to get '%s' session for service[%s]: %s(%s)",
                 ziti_session_types.name(req->session_type), conn->service, err->code, err->message);

        if (err->err == ZITI_NOT_AUTHORIZED) {
            ziti_force_api_session_refresh(ztx);
            restart_connect(conn);
        } else {
            complete_conn_req(conn, e);
        }
    } else {
        req->session = s;
        s->service_id = strdup(req->service_id);
        if (req->session_type == ziti_session_types.Dial) {
            ziti_net_session *existing = model_map_get(&ztx->sessions, req->service_id);
            // this happens with concurrent connection requests for the same service (common with browsers)
            if (existing) {
                CONN_LOG(DEBUG, "found session[%s] for service[%s]", existing->id, conn->service);
                free_ziti_net_session(s);
                free(s);
                req->session = existing;
            } else {
                CONN_LOG(DEBUG, "got session[%s] for service[%s]", s->id, conn->service);
                model_map_set(&ztx->sessions, s->service_id, s);
            }
        }
        process_connect(conn);
    }
}

static void process_connect(struct ziti_conn *conn) {
    struct ziti_conn_req *req = conn->conn_req;
    struct ziti_ctx *ztx = conn->ziti_ctx;
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
    if (req->session == NULL && req->session_type == ziti_session_types.Dial) {
        req->session = model_map_get(&ztx->sessions, req->service_id);
    }

    if (req->session == NULL) {
        CONN_LOG(DEBUG, "requesting '%s' session for service[%s]", ziti_session_types.name(req->session_type),
                 conn->service);
        ziti_ctrl_create_session(&ztx->controller, req->service_id, req->session_type, connect_get_net_session_cb,
                                 conn);
        return;
    } else {
        req->conn_timeout = calloc(1, sizeof(uv_timer_t));
        uv_timer_init(loop, req->conn_timeout);
        req->conn_timeout->data = conn;
        uv_timer_start(req->conn_timeout, connect_timeout, conn->timeout, 0);

        CONN_LOG(DEBUG, "starting %s connection for service[%s] with session[%s]",
                 ziti_session_types.name(req->session_type), conn->service, req->session->id);
        ziti_connect(ztx, req->session, conn);
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

    NEWP(req, struct ziti_conn_req);
    conn->service = strdup(service);
    conn->conn_req = req;

    req->session_type = ziti_session_types.Dial;
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
    conn_set_state(conn, Connecting);

    conn->flusher = calloc(1, sizeof(uv_idle_t));
    uv_idle_init(conn->ziti_ctx->loop, conn->flusher);
    conn->flusher->data = conn;

    process_connect(conn);
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

static void ziti_write_timeout(uv_timer_t *t) {
    struct ziti_write_req_s *req = t->data;
    struct ziti_conn *conn = req->conn;

    conn->write_reqs--;
    req->timeout = NULL;
    req->conn = NULL;

    if (conn->state < Disconnected) {
        conn_set_state(conn, Disconnected);
        req->cb(conn, ZITI_TIMEOUT, req->ctx);
    }

    uv_close((uv_handle_t *) t, free_handle);
}

static void ziti_write_req(struct ziti_write_req_s *req) {
    struct ziti_conn *conn = req->conn;

    if (req->eof) {
        conn_set_state(conn, CloseWrite);
        send_fin_message(conn);
        conn->write_reqs--;
        free(req);
        return;
    }

    if (req->cb) {
        req->timeout = calloc(1, sizeof(uv_timer_t));
        uv_timer_init(conn->ziti_ctx->loop, req->timeout);
        req->timeout->data = req;
        uv_timer_start(req->timeout, ziti_write_timeout, conn->timeout, 0);
    }

    size_t total_len = req->len + (conn->encrypted ? crypto_secretstream_xchacha20poly1305_abytes() : 0);
    message *m = create_message(conn, ContentTypeData, total_len);

    if (conn->encrypted) {
        crypto_secretstream_xchacha20poly1305_push(&conn->crypt_o, m->body, NULL, req->buf, req->len, NULL, 0, 0);
    } else {
        memcpy(m->body, req->buf, req->len);
    }

    send_message(conn, m, req);
}

static void on_disconnect(ziti_connection conn, ssize_t status, void *ctx) {
    conn_set_state(conn, conn->close ? Closed : Disconnected);
    ziti_channel_t *ch = conn->channel;
    if (ch) {
        ziti_channel_rem_receiver(ch, conn->conn_id);
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
            message *m = create_message(conn, ContentTypeStateClosed, 0);
            NEWP(wr, struct ziti_write_req_s);
            wr->conn = conn;
            wr->cb = on_disconnect;
            conn->write_reqs++;
            send_message(conn, m, wr);
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

static void crypto_wr_cb(ziti_connection conn, ssize_t status, void *ctx) {
    if (status < 0) {
        CONN_LOG(ERROR, "crypto header write failed with status[%zd]", status);
        conn_set_state(conn, Disconnected);
        conn->data_cb(conn, NULL, status);
    }
}

int establish_crypto(ziti_connection conn, message *msg) {

    if (conn->state != Connecting && conn->state != Accepting) {
        CONN_LOG(ERROR, "cannot establish crypto in state[%s]", ziti_conn_state(conn));
        return ZITI_INVALID_STATE;
    }

    size_t peer_key_len;
    uint8_t *peer_key;
    bool peer_key_sent = message_get_bytes_header(msg, PublicKeyHeader, &peer_key, &peer_key_len);
    if (!peer_key_sent) {
        if (conn->encrypted) {
            CONN_LOG(ERROR, "failed to establish crypto for encrypted service: did not receive peer key");
            return ZITI_CRYPTO_FAIL;
        } else {
            CONN_LOG(VERBOSE, "encryption not set up: peer_key_sent[%d] conn->encrypted[%d]", (int) peer_key_sent,
                     (int) conn->encrypted);
            // service is not required to be encrypted and hosting side did not send the key
            return ZITI_OK;
        }
    }
    conn->encrypted = true;

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
        message *m = create_message(conn, ContentTypeData, crypto_header_len);
        crypto_secretstream_xchacha20poly1305_init_push(&conn->crypt_o, m->body, conn->key_ex.tx);
        NEWP(wr, struct ziti_write_req_s);
        wr->conn = conn;
        wr->cb = crypto_wr_cb;
        conn->write_reqs++;
        send_message(conn, m, wr);
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
    if (conn->flusher) {
        CONN_LOG(TRACE, "starting flusher");
        uv_idle_start(conn->flusher, on_flush);
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

        if (conn->state == Connected) {
            conn->write_reqs++;
            ziti_write_req(req);
            count++;
        } else {
            CONN_LOG(DEBUG, "got write req in invalid state[%s]", conn_state_str[conn->state]);
            conn->write_reqs--;

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

    CONN_LOG(VERBOSE, "%zu bytes available", buffer_available(conn->inbound));
    int flushes = 128;
    while (buffer_available(conn->inbound) > 0 && (flushes--) > 0) {
        uint8_t *chunk;
        ssize_t chunk_len = buffer_get_next(conn->inbound, 16 * 1024, &chunk);
        ssize_t consumed = conn->data_cb(conn, chunk, chunk_len);
        CONN_LOG(TRACE, "client consumed %zd out of %zd bytes", consumed, chunk_len);

        if (consumed < 0) {
            CONN_LOG(WARN, "client indicated error[%zd] accepting data (%zd bytes buffered)",
                     consumed, buffer_available(conn->inbound));
        } else if (consumed < chunk_len) {
            buffer_push_back(conn->inbound, (chunk_len - consumed));
            CONN_LOG(VERBOSE, "client stalled: %zd bytes buffered", buffer_available(conn->inbound));
            break;
        }
    }

    if (buffer_available(conn->inbound) > 0) {
        CONN_LOG(VERBOSE, "%zu bytes still available", buffer_available(conn->inbound));

        return true;
    }

    if (conn->fin_recv == 1) { // if fin was received and all data is flushed, signal EOF
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
    uint8_t *plain_text = NULL;
    if (conn->state >= Disconnected || conn->fin_recv) {
        CONN_LOG(WARN, "inbound data on closed connection");
        return;
    }

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
            unsigned long long plain_len;
            unsigned char tag;
            if (msg->header.body_len > 0) {
                plain_text = malloc(msg->header.body_len - crypto_secretstream_xchacha20poly1305_ABYTES);
                CONN_LOG(VERBOSE, "decrypting %d bytes", msg->header.body_len);
                TRY(crypto, crypto_secretstream_xchacha20poly1305_pull(&conn->crypt_i,
                                                                       plain_text, &plain_len, &tag,
                                                                       msg->body, msg->header.body_len, NULL, 0));
                CONN_LOG(VERBOSE, "decrypted %lld bytes", plain_len);
                buffer_append(conn->inbound, plain_text, plain_len);
                metrics_rate_update(&conn->ziti_ctx->down_rate, (int64_t) plain_len);
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
        memcpy(plain_text, msg->body, msg->header.body_len);
        buffer_append(conn->inbound, plain_text, msg->header.body_len);
        metrics_rate_update(&conn->ziti_ctx->down_rate, msg->header.body_len);
    }

    int32_t flags;
    if (message_get_int32_header(msg, FlagsHeader, &flags) && (flags & EDGE_FIN)) {
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

    process_connect(conn);
}

void connect_reply_cb(void *ctx, message *msg, int err) {
    struct ziti_conn *conn = ctx;
    struct ziti_conn_req *req = conn->conn_req;

    if (req->conn_timeout) {
        uv_timer_stop(req->conn_timeout);
    }

    req->waiter = NULL;
    if (err != 0 && msg == NULL) {
        CONN_LOG(ERROR, "failed to %s [%d/%s]", "connect", err, uv_strerror(err));
        conn_set_state(conn, Disconnected);
        complete_conn_req(conn, ZITI_CONN_CLOSED);
        return;
    }

    switch (msg->header.content) {
        case ContentTypeStateClosed:
            if (strncmp(INVALID_SESSION, (const char *) msg->body, msg->header.body_len) == 0) {
                CONN_LOG(WARN, "session for service[%s] became invalid", conn->service);
                if (conn->conn_req->session_type == ziti_session_types.Dial) {
                    ziti_net_session *s = model_map_get(&conn->ziti_ctx->sessions, req->service_id);
                    if (s != req->session) {
                        // already removed or different one
                        // req reference is no longer valid
                        req->session = NULL;
                    } else if (s == req->session) {
                        model_map_remove(&conn->ziti_ctx->sessions, req->service_id);
                    }
                }
                free_ziti_net_session(req->session);
                FREE(req->session);

                ziti_channel_rem_receiver(conn->channel, conn->conn_id);
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
                int rc = establish_crypto(conn, msg);
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
                CONN_LOG(WARN, "received connect reply for closed/timedout");
                ziti_disconnect(conn);
            }
            break;

        default:
            CONN_LOG(WARN, "unexpected content_type[%d]", msg->header.content);
            ziti_disconnect(conn);
    }
}

static int ziti_channel_start_connection(struct ziti_conn *conn, ziti_channel_t *ch) {
    struct ziti_conn_req *req = conn->conn_req;
    ziti_net_session *s = req->session;

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

    if (!ziti_is_session_valid(conn->ziti_ctx, s, req->service_id, req->session_type)) {
        CONN_LOG(DEBUG, "session is no longer valid");
        if (req->session_type == ziti_session_types.Bind) {
            free_ziti_net_session(req->session);
            FREE(req->session);
        }
        req->session = NULL;
        restart_connect(conn);
        return ZITI_OK;
    }

    CONN_LOG(TRACE, "ch[%d] => Edge Connect request token[%s]", ch->id, s->token);
    conn->channel = ch;
    ziti_channel_add_receiver(ch, conn->conn_id, conn,
                              (void (*)(void *, message *, int)) queue_edge_message);

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
                    .length = strlen(conn->ziti_ctx->api_session->identity->name),
                    .value = conn->ziti_ctx->api_session->identity->name,
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
    int nheaders = 3;
    if (conn->encrypted) {
        init_key_pair(&conn->key_pair);
        nheaders++;
    }
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

    req->waiter = ziti_channel_send_for_reply(ch, content_type, headers, nheaders,
                                              s->token, strlen(s->token), connect_reply_cb, conn);

    return ZITI_OK;
}



int ziti_accept(ziti_connection conn, ziti_conn_cb cb, ziti_data_cb data_cb) {

    if (conn->state == Disconnected) {
        return ZITI_CONN_CLOSED;
    }

    if (conn->state != Accepting) {
        return ZITI_INVALID_STATE;
    }

    ziti_channel_t *ch = conn->channel;
    conn->data_cb = data_cb;

    TAILQ_INIT(&conn->in_q);
    conn->flusher = calloc(1, sizeof(uv_idle_t));
    uv_idle_init(conn->ziti_ctx->loop, conn->flusher);
    conn->flusher->data = conn;
    uv_unref((uv_handle_t *) &conn->flusher);

    ziti_channel_add_receiver(ch, conn->conn_id, conn, (void (*)(void *, message *, int)) queue_edge_message);

    CONN_LOG(TRACE, "ch[%d] => Edge Accept parent_conn_id[%d]", ch->id, conn->parent->conn_id);

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

    req->waiter = ziti_channel_send_for_reply(
            ch, content_type, headers, 3,
            (const uint8_t *) &clt_conn_id, sizeof(clt_conn_id),
            connect_reply_cb, conn);

    return ZITI_OK;
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
    metrics_rate_update(&conn->ziti_ctx->up_rate, length);

    TAILQ_INSERT_TAIL(&conn->wreqs, req, _next);
    flush_connection(conn);

    return 0;
}

static int send_fin_message(ziti_connection conn) {
    CONN_LOG(DEBUG, "sending FIN");
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
    message *m = message_new(NULL, ContentTypeData, headers, 3, 0);
    return ziti_channel_send_message(ch, m, wr);
}

int ziti_close(ziti_connection conn, ziti_close_cb close_cb) {

    if (conn == NULL) return ZITI_INVALID_STATE;
    if (conn->close) return ZITI_CONN_CLOSED;

    conn->close = true;
    conn->close_cb = close_cb;

    if (conn->type == Server) {
        return ziti_close_server(conn);
    }
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

void reject_dial_request(uint32_t conn_id, ziti_channel_t *ch, int32_t req_id, const char *reason) {

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
                conn->data_cb(conn, NULL, code);
                break;
            default:
                CONN_LOG(WARN, "disconnecting from state[%d]", st);
        }
        return;
    }

    TAILQ_INSERT_TAIL(&conn->in_q, msg, _next);
    flush_connection(conn);
}

static void process_edge_message(struct ziti_conn *conn, message *msg) {

    int rc;
    int32_t seq;
    int32_t conn_id;
    bool has_seq = message_get_int32_header(msg, SeqHeader, &seq);
    bool has_conn_id = message_get_int32_header(msg, ConnIdHeader, &conn_id);

    CONN_LOG(TRACE, "<= ct[%04X] edge_seq[%d] body[%d]", msg->header.content, seq, msg->header.body_len);

    switch (msg->header.content) {
        case ContentTypeStateClosed:
            CONN_LOG(DEBUG, "connection status[%X] conn_id[%d] seq[%d] err[%.*s]", msg->header.content, conn_id, seq,
                     msg->header.body_len, msg->body);
            bool retry_connect = false;

            switch (conn->state) {
                case Connecting:
                case Accepting: {
                    if (strncmp(INVALID_SESSION, (const char *) msg->body, msg->header.body_len) == 0) {
                        CONN_LOG(WARN, "session for service[%s] became invalid", conn->service);
                        ziti_invalidate_session(conn->ziti_ctx, conn->conn_req->session,
                                                conn->conn_req->service_id, conn->conn_req->session_type);
                        conn->conn_req->session = NULL;
                        retry_connect = true;
                    }
                    if (retry_connect) {
                        ziti_channel_rem_receiver(conn->channel, conn->conn_id);
                        conn->channel = NULL;
                        conn_set_state(conn, Connecting);
                        restart_connect(conn);
                    } else {
                        CONN_LOG(ERROR, "failed to %s, reason=%*.*s",
                                 "connect",
                                 msg->header.body_len, msg->header.body_len, msg->body);
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
            CONN_LOG(ERROR, "received unexpected content_type[%d]", msg->header.content);
    }
}

void init_transport_conn(struct ziti_conn *c) {
    c->type = Transport;
    c->disposer = close_conn_internal;

    TAILQ_INIT(&c->in_q);
    TAILQ_INIT(&c->wreqs);
    c->inbound = new_buffer();
}
