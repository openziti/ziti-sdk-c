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
#include "utils.h"
#include "zt_internal.h"

#include "connect.h"

#define DEFAULT_MAX_BINDINGS 3

struct binding_s {
    struct ziti_conn *conn;
    ziti_channel_t *ch;
    struct key_pair key_pair;
};


static uint16_t get_terminator_cost(const ziti_listen_opts *opts, const char *service, ziti_context ztx);

static uint8_t get_terminator_precedence(const ziti_listen_opts *opts, const char *service, ziti_context ztx);

static void get_service_cb(ziti_context, ziti_service *service, int status, void *ctx);

static int close_server(ziti_connection server);

static void start_binding(struct binding_s *b);

static void remove_binding(struct binding_s *b);

static void session_cb(ziti_net_session *session, const ziti_error *err, void *ctx);


int ziti_bind(ziti_connection conn, const char *service, const ziti_listen_opts *listen_opts,
              ziti_listen_cb listen_cb, ziti_client_cb on_clt_cb) {

    assert(conn->type == None);
    assert(conn->ziti_ctx != NULL);

    if (!conn->ziti_ctx->enabled) return ZITI_DISABLED;

    conn->type = Server;
    conn->closer = close_server;
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
        ziti_ctrl_create_session(&conn->ziti_ctx->controller, conn->service,
                                 ziti_session_types.Bind, session_cb, conn);
    }
}

static void process_bindings(struct ziti_conn *conn) {
    ziti_net_session *ns = conn->server.session;

    size_t target = MIN(conn->server.max_bindings, model_list_size(&ns->edge_routers));
    size_t bind_count = model_map_size(&conn->server.bindings);
    if (bind_count >= target) {
        return;
    }

    ziti_edge_router *er;
    const char *proto;
    const char *url;
    MODEL_LIST_FOREACH(er, ns->edge_routers) {
        MODEL_MAP_FOREACH(proto, url, &er->protocols) {

            if (model_map_get(&conn->server.bindings, url) == NULL) {
                ziti_channel_t *ch = model_map_get(&conn->ziti_ctx->channels, url);
                if (ziti_channel_is_connected(ch)) {
                    NEWP(b, struct binding_s);
                    b->conn = conn;
                    b->ch = ch;
                    model_map_set(&conn->server.bindings, url, b);
                    start_binding(b);
                }
            }
        }
    }

    if (model_map_size(&conn->server.bindings) < target) {
        uv_timer_start(conn->server.timer, rebind_delay_cb, 5000, 0);
    }
}

static void session_cb(ziti_net_session *session, const ziti_error *err, void *ctx) {
    struct ziti_conn *conn = ctx;
    if (err) {
        ZITI_LOG(WARN, "failed to get session for service[%s]: %d/%s", conn->service, err->err, err->code);
    } else {
        ziti_net_session *old = conn->server.session;
        conn->server.session = session;
        if (conn->server.listen_cb) {
            conn->server.listen_cb(conn, ZITI_OK);
        }

        free_ziti_net_session(old);

        process_bindings(conn);
    }
}

static void get_service_cb(ziti_context ztx, ziti_service *service, int status, void *ctx) {
    struct ziti_conn *conn = ctx;
    if (status == ZITI_OK) {
        if (ziti_service_has_permission(service, ziti_session_types.Bind)) {
            ziti_ctrl_create_session(&ztx->controller, service->id, ziti_session_types.Bind, session_cb, conn);
        } else {
            ZITI_LOG(WARN, "not authorized to Bind service[%s]", service->name);
            conn->server.listen_cb(conn, ZITI_SERVICE_UNAVAILABLE);
        }
    } else if (status == ZITI_SERVICE_UNAVAILABLE) {
        ZITI_LOG(WARN, "service[%s] is not available", service->name);
        conn->server.listen_cb(conn, ZITI_SERVICE_UNAVAILABLE);
    } else {

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

static int close_server(ziti_connection server) {
    assert(server->type == Server);
    // TODO
    return 0;
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
        ZITI_LOG(INFO, "received msg ct[%x] code[%d] from %s", msg->header.content, code, b->ch->name);
        switch (msg->header.content) {
            case ContentTypeStateClosed:
                ZITI_LOG(INFO, "binding[%d/%s] was closed: %.*s", conn->conn_id, b->ch->name, msg->header.body_len,
                         msg->body);
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
    ZITI_LOG(INFO, "received msg ct[%X] code[%d]", msg->header.content, code);
    if (code == ZITI_OK && msg->header.content == ContentTypeStateConnected) {
        ZITI_LOG(DEBUG, "conn[%d] bound successfully over ch[%s]", b->conn->conn_id, b->ch->name);
    } else {
        ZITI_LOG(DEBUG, "conn[%d] failed to bind over ch[%s]", b->conn->conn_id, b->ch->name);
        remove_binding(b);
    }
    pool_return_obj(msg);
}

void start_binding(struct binding_s *b) {
    ziti_net_session *s = b->conn->server.session;
    ZITI_LOG(TRACE, "ch[%d] => Edge Connect request token[%s]", b->ch->id, s->token);
    init_key_pair(&b->key_pair);
    ziti_channel_add_receiver(b->ch, b->conn->conn_id, b,
                              (void (*)(void *, message *, int)) on_message);

    int32_t conn_id = htole32(b->conn->conn_id);
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
    if (b->conn->server.identity != NULL) {
        headers[nheaders].header_id = TerminatorIdentityHeader;
        headers[nheaders].value = (uint8_t *) b->conn->server.identity;
        headers[nheaders].length = strlen(b->conn->server.identity);
        nheaders++;
    }

    if (b->conn->server.cost > 0) {
        uint16_t cost = htole16(b->conn->server.cost);
        headers[nheaders].header_id = CostHeader;
        headers[nheaders].value = (uint8_t *) &cost;
        headers[nheaders].length = sizeof(cost);
        nheaders++;
    }

    if (b->conn->server.precedence != PRECEDENCE_DEFAULT) {
        headers[nheaders].header_id = PrecedenceHeader;
        headers[nheaders].value = &b->conn->server.precedence;
        headers[nheaders].length = sizeof(b->conn->server.precedence);
        nheaders++;
    }

    ziti_channel_send_for_reply(b->ch, ContentTypeBind, headers, nheaders, s->token, strlen(s->token), bind_reply_cb,
                                b);
}

static void remove_binding(struct binding_s *b) {
    ziti_channel_rem_receiver(b->ch, b->conn->conn_id);
    model_map_remove(&b->conn->server.bindings, b->ch->url);
    free(b);
}
