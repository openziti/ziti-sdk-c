// Copyright (c) 2023.  NetFoundry Inc.
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


#include <assert.h>
#include "ziti/ziti.h"
#include "endian_internal.h"
#include "win32_compat.h"
#include "utils.h"
#include "zt_internal.h"

#include "connect.h"

#define DEFAULT_MAX_BINDINGS 3
#define REBIND_DELAY 1000
#define REFRESH_DELAY (60 * 5 * 1000)

#define CONN_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "server[%u.%u] " fmt, conn->ziti_ctx->id, conn->conn_id, ##__VA_ARGS__)

struct binding_s {
    struct ziti_conn *conn;
    ziti_channel_t *ch;
    struct key_pair key_pair;
};


static uint16_t get_terminator_cost(const ziti_listen_opts *opts, const char *service, ziti_context ztx);

static uint8_t get_terminator_precedence(const ziti_listen_opts *opts, const char *service, ziti_context ztx);

static void get_service_cb(ziti_context, ziti_service *service, int status, void *ctx);

static int dispose(ziti_connection server);

static void start_binding(struct binding_s *b);

static void stop_binding(struct binding_s *b);

static void remove_binding(struct binding_s *b);

static void schedule_rebind(struct ziti_conn *conn, bool now);

static void session_cb(ziti_net_session *session, const ziti_error *err, void *ctx);

static void notify_status(struct ziti_conn *conn, int err);

int ziti_bind(ziti_connection conn, const char *service, const ziti_listen_opts *listen_opts,
              ziti_listen_cb listen_cb, ziti_client_cb on_clt_cb) {

    assert(conn->type == None);
    assert(conn->ziti_ctx != NULL);

    if (!conn->ziti_ctx->enabled) return ZITI_DISABLED;

    conn->type = Server;
    conn->disposer = dispose;
    conn->service = strdup(service);
    conn->server.cost = get_terminator_cost(listen_opts, service, conn->ziti_ctx);
    conn->server.precedence = get_terminator_precedence(listen_opts, service, conn->ziti_ctx);
    conn->server.max_bindings = listen_opts && listen_opts->max_connections > 0 ?
                                listen_opts->max_connections : DEFAULT_MAX_BINDINGS;
    conn->server.timer = calloc(1, sizeof(uv_timer_t));
    conn->server.timer->data = conn;
    uv_timer_init(conn->ziti_ctx->loop, conn->server.timer);

    if (listen_opts) {
        if (listen_opts->bind_using_edge_identity) {
            conn->server.identity = strdup(conn->ziti_ctx->identity_data->name);
        } else if (listen_opts->identity) {
            conn->server.identity = strdup(listen_opts->identity);
        }
    }
    conn->server.listen_cb = listen_cb;
    conn->server.client_cb = on_clt_cb;

    ziti_service_available(conn->ziti_ctx, conn->service, get_service_cb, conn);

    return 0;
}

static void rebind_delay_cb(uv_timer_t *t) {
    ziti_connection conn = t->data;

    if (conn->server.session) {
        ziti_ctrl_get_session(&conn->ziti_ctx->controller, conn->server.session->id, session_cb, conn);
    } else {
        ziti_service_available(conn->ziti_ctx, conn->service, get_service_cb, conn);
    }
}

static void process_bindings(struct ziti_conn *conn) {
    ziti_net_session *ns = conn->server.session;
    struct ziti_ctx *ztx = conn->ziti_ctx;

    size_t target = MIN(conn->server.max_bindings, model_map_size(&ztx->channels));
    size_t bind_count = model_map_size(&conn->server.bindings);
    if (bind_count >= target) {
        return;
    }

    ziti_edge_router *er;
    const char *proto;
    const char *url;
    MODEL_LIST_FOREACH(er, ns->edge_routers) {
        MODEL_MAP_FOREACH(proto, url, &er->protocols) {
            CONN_LOG(DEBUG, "checking %s[%s]", er->name, url);
            if (model_map_get(&conn->server.bindings, url) == NULL) {
                ziti_channel_t *ch = model_map_get(&ztx->channels, url);
                if (ch && ziti_channel_is_connected(ch)) {
                    NEWP(b, struct binding_s);
                    b->conn = conn;
                    b->ch = ch;
                    model_map_set(&conn->server.bindings, url, b);
                    start_binding(b);
                }
            }
        }
    }

    schedule_rebind(conn, model_map_size(&conn->server.bindings) < target);
}

static void schedule_rebind(struct ziti_conn *conn, bool now) {
    uint64_t delay = REFRESH_DELAY;

    if (now) {
        int backoff = 1 << MIN(conn->server.attempt, 5);
        uint32_t random;
        uv_random(conn->ziti_ctx->loop, NULL, &random, sizeof(random), 0, NULL);
        delay = (uint64_t) (random % (backoff * REBIND_DELAY));
        conn->server.attempt++;
        CONN_LOG(DEBUG, "scheduling re-bind(attempt=%d) in %ld.%lds", conn->server.attempt, delay / 1000, delay % 1000);

    } else {
        conn->server.attempt = 0;
        CONN_LOG(DEBUG, "scheduling re-bind in %ld.%lds", delay / 1000, delay % 1000);
    }

    uv_timer_start(conn->server.timer, rebind_delay_cb, delay, 0);
}


static void session_cb(ziti_net_session *session, const ziti_error *err, void *ctx) {
    struct ziti_conn *conn = ctx;
    int e = err ? err->err : ZITI_OK;
    switch (e) {
        case ZITI_OK: {
            ziti_net_session *old = conn->server.session;
            conn->server.session = session;
            notify_status(conn, ZITI_OK);

            free_ziti_net_session(old);

            process_bindings(conn);
            break;
        }
        case ZITI_NOT_FOUND:
        case ZITI_NOT_AUTHORIZED:
            CONN_LOG(WARN, "failed to get session for service[%s]: %d/%s", conn->service, err->err, err->code);
            const char *id;
            struct binding_s *b;
            MODEL_MAP_FOREACH(id, b, &conn->server.bindings) {
        stop_binding(b);
    }

            // our session is stale
            if (conn->server.session) {
                free_ziti_net_session_ptr(conn->server.session);
                conn->server.session = NULL;
                schedule_rebind(conn, true);
            } else {
                // here if we could not create Bind session
                notify_status(conn, ZITI_SERVICE_UNAVAILABLE);
            }
            break;

        default:
            CONN_LOG(WARN, "failed to get session for service[%s]: %d/%s", conn->service, err->err, err->code);
            schedule_rebind(conn, true);
    }
}

static void get_service_cb(ziti_context ztx, ziti_service *service, int status, void *ctx) {
    struct ziti_conn *conn = ctx;
    if (status == ZITI_OK) {
        if (ziti_service_has_permission(service, ziti_session_types.Bind)) {
            ziti_ctrl_create_session(&ztx->controller, service->id, ziti_session_types.Bind, session_cb, conn);
        } else {
            CONN_LOG(WARN, "not authorized to Bind service[%s]", service->name);
            notify_status(conn, ZITI_SERVICE_UNAVAILABLE);
        }
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        CONN_LOG(WARN, "service[%s] is not available", service->name);
        notify_status(conn, ZITI_SERVICE_UNAVAILABLE);
    } else {
        CONN_LOG(WARN, "failed to get service[%s] details, scheduling re-try", conn->service);
        schedule_rebind(conn, true);
    }
}

static uint16_t get_terminator_cost(const ziti_listen_opts *opts, const char *service, ziti_context ztx) {
    if (opts && opts->terminator_cost > 0) return opts->terminator_cost;

    if (ztx->identity_data) {
        int *cp = model_map_get(&ztx->identity_data->service_hosting_costs, service);
        if (cp) return (uint16_t) *cp;

        return (uint16_t) ztx->identity_data->default_hosting_cost;
    }

    return 0;
}

static uint8_t get_terminator_precedence(const ziti_listen_opts *opts, const char *service, ziti_context ztx) {
    if (opts && opts->terminator_precedence > 0) return opts->terminator_precedence;

    if (ztx->identity_data) {
        const char *precedence = model_map_get(&ztx->identity_data->service_hosting_precendences, service);
        precedence = precedence ? precedence : ztx->identity_data->default_hosting_precendence;

        if (precedence) {
            if (strcmp("failed", precedence) == 0) return PRECEDENCE_FAILED;
            if (strcmp("required", precedence) == 0) return PRECEDENCE_REQUIRED;
        }
    }

    return PRECEDENCE_DEFAULT;
}

static int dispose(ziti_connection server) {
    assert(server->type == Server);

    if (model_map_size(&server->server.bindings)) {
        ZITI_LOG(VERBOSE, "waiting for bindings to clear");
        return 0;
    }

    if (model_map_size(&server->server.children) > 0) {
        ZITI_LOG(VERBOSE, "waiting for children to terminate");
        return 0;
    }

    server->server.timer->data = NULL;
    uv_close((uv_handle_t *) server->server.timer, (uv_close_cb) free);
    server->server.timer = NULL;

    free_ziti_net_session_ptr(server->server.session);
    free(server->service);
    free(server);
    return 1;
}

static void process_dial(struct binding_s *b, message *msg) {
    struct ziti_conn *conn = b->conn;

    size_t peer_key_len;
    uint8_t *peer_key;
    bool peer_key_sent = message_get_bytes_header(msg, PublicKeyHeader, &peer_key, &peer_key_len);

    if (!peer_key_sent && conn->encrypted) {
        ZITI_LOG(ERROR, "failed to establish crypto for encrypted service: did not receive peer key");
        reject_dial_request(0, b->ch, msg->header.seq, "did not receive peer crypto key");
        return;
    }

    ziti_connection client;
    ziti_conn_init(conn->ziti_ctx, &client, NULL);
    init_transport_conn(client);

    if (peer_key_sent) {
        client->encrypted = true;
        if (init_crypto(&client->key_ex, &b->key_pair, peer_key, true) != 0) {
            reject_dial_request(0, b->ch, msg->header.seq, "failed to establish crypto");
            ziti_close(client, NULL);
            return;
        }
    }
    client->state = Accepting;
    client->channel = b->ch;
    client->parent = conn;
    model_map_setl(&conn->server.children, (long) client->conn_id, client);

    client->dial_req_seq = msg->header.seq;
    uint8_t *source_identity = NULL;
    size_t source_identity_sz = 0;
    bool caller_id_sent = message_get_bytes_header(msg, CallerIdHeader, &source_identity, &source_identity_sz);

    ziti_client_ctx clt_ctx = {0};
    message_get_bytes_header(msg, AppDataHeader, (uint8_t **) &clt_ctx.app_data, &clt_ctx.app_data_sz);
    if (caller_id_sent) {
        client->source_identity = strndup((char *) source_identity, source_identity_sz);
        clt_ctx.caller_id = client->source_identity;
    }
    conn->server.client_cb(conn, client, ZITI_OK, &clt_ctx);

}

static void on_message(struct binding_s *b, message *msg, int code) {
    struct ziti_conn *conn = b->conn;
    if (code != ZITI_OK) {
        ZITI_LOG(WARN, "binding failed: %d/%s", code, ziti_errorstr(code));
        remove_binding(b);
    } else {
        ZITI_LOG(DEBUG, "received msg ct[%x] code[%d] from %s", msg->header.content, code, b->ch->name);
        switch (msg->header.content) {
            case ContentTypeStateClosed:
                CONN_LOG(DEBUG, "binding[%s] was closed: %.*s", b->ch->url, msg->header.body_len, msg->body);
                remove_binding(b);
                break;
            case ContentTypeDial:
                process_dial(b, msg);
                break;
            default:
                ZITI_LOG(ERROR, "unexpected msg[%X] for bound conn[%d]", msg->header.content, conn->conn_id);
        }
    }

    pool_return_obj(msg);
}

static void bind_reply_cb(void *ctx, message *msg, int code) {
    struct binding_s *b = ctx;
    struct ziti_conn *conn = b->conn;
    CONN_LOG(TRACE, "received msg ct[%X] code[%d]", msg->header.content, code);
    if (code == ZITI_OK && msg->header.content == ContentTypeStateConnected) {
        CONN_LOG(DEBUG, "bound successfully over ch[%s]", b->ch->url);
    } else {
        CONN_LOG(DEBUG, "failed to bind over ch[%s]", b->ch->url);
        remove_binding(b);
    }
}

void start_binding(struct binding_s *b) {
    struct ziti_conn *conn = b->conn;
    ziti_net_session *s = conn->server.session;
    CONN_LOG(TRACE, "ch[%d] => Edge Connect request token[%s]", b->ch->id, s->token);
    init_key_pair(&b->key_pair);
    ziti_channel_add_receiver(b->ch, conn->conn_id, b,
                              (void (*)(void *, message *, int)) on_message);

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
                    .header_id = PublicKeyHeader,
                    .length = sizeof(b->key_pair.pk),
                    .value = b->key_pair.pk,
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
    if (conn->server.identity != NULL) {
        headers[nheaders].header_id = TerminatorIdentityHeader;
        headers[nheaders].value = (uint8_t *) conn->server.identity;
        headers[nheaders].length = strlen(conn->server.identity);
        nheaders++;
    }

    if (conn->server.cost > 0) {
        uint16_t cost = htole16(conn->server.cost);
        headers[nheaders].header_id = CostHeader;
        headers[nheaders].value = (uint8_t *) &cost;
        headers[nheaders].length = sizeof(cost);
        nheaders++;
    }

    if (conn->server.precedence != PRECEDENCE_DEFAULT) {
        headers[nheaders].header_id = PrecedenceHeader;
        headers[nheaders].value = &conn->server.precedence;
        headers[nheaders].length = sizeof(conn->server.precedence);
        nheaders++;
    }

    ziti_channel_send_for_reply(b->ch, ContentTypeBind, headers, nheaders, s->token, strlen(s->token), bind_reply_cb,
                                b);
}

static void remove_binding(struct binding_s *b) {
    struct ziti_conn *conn = b->conn;
    ziti_channel_rem_receiver(b->ch, conn->conn_id);
    model_map_remove(&conn->server.bindings, b->ch->url);
    CONN_LOG(DEBUG, "binding[%s] removed", b->ch->url);
    free(b);

    schedule_rebind(conn, true);
}

void on_unbind(void *ctx, message *m, int code) {
    struct binding_s *b = ctx;
    struct ziti_conn *conn = b->conn;

    CONN_LOG(TRACE, "binding[%s] unbind resp: ct[%X] %.*s", b->ch->url, m->header.content, m->header.body_len, m->body);
    int32_t conn_id = htole32(b->conn->conn_id);
    hdr_t headers[] = {
            {
                    .header_id = ConnIdHeader,
                    .length = sizeof(conn_id),
                    .value = (uint8_t *) &conn_id
            },
    };
    ziti_channel_send(b->ch, ContentTypeStateClosed, headers, 1, NULL, 0, NULL);
    remove_binding(ctx);
}

static void stop_binding(struct binding_s *b) {
    ziti_net_session *s = b->conn->server.session;
    int32_t conn_id = htole32(b->conn->conn_id);
    hdr_t headers[] = {
            {
                    .header_id = ConnIdHeader,
                    .length = sizeof(conn_id),
                    .value = (uint8_t *) &conn_id
            },
    };
    ziti_channel_send_for_reply(b->ch, ContentTypeUnbind, headers, 1,
                                s->token, strlen(s->token), on_unbind, b);
}

int ziti_close_server(struct ziti_conn *conn) {
    const char *id;
    struct binding_s *b;
    uv_timer_stop(conn->server.timer);
    MODEL_MAP_FOREACH(id, b, &conn->server.bindings) {
        CONN_LOG(VERBOSE, "stopping binding[%s]", id);
        stop_binding(b);
    }
    return ZITI_OK;
}

static void notify_status(struct ziti_conn *conn, int err) {
    assert(conn->type == Server);

    // first notification
    if (conn->server.listen_cb) {
        conn->server.listen_cb(conn, err);
        conn->server.listen_cb = NULL;
    } else if (err != ZITI_OK) {
        conn->server.client_cb(conn, NULL, err, NULL);
    }
}
