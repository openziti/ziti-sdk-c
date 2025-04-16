// Copyright (c) 2023-2024. NetFoundry Inc.
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


#include <assert.h>
#include <inttypes.h>

#include "message.h"
#include "ziti/ziti.h"
#include "endian_internal.h"
#include "win32_compat.h"
#include "utils.h"
#include "zt_internal.h"

#include "connect.h"

#define DEFAULT_MAX_BINDINGS 3
#define REBIND_DELAY 1000

#define CONN_LOG(lvl, fmt, ...) \
ZITI_LOG(lvl, "server[%u.%u](%s) " fmt, \
conn->ziti_ctx->id, conn->conn_id, conn->service, ##__VA_ARGS__)

enum bind_state {
    st_unbound,
    st_binding,
    st_bound,
    st_unbinding,
};

struct binding_s {
    struct ziti_conn *conn;
    uint32_t conn_id;
    ziti_channel_t *ch;
    struct key_pair key_pair;
    enum bind_state state;
    struct waiter_s *waiter;
};


static uint16_t get_terminator_cost(const ziti_listen_opts *opts, const char *service, ziti_context ztx);

static uint8_t get_terminator_precedence(const ziti_listen_opts *opts, const char *service, ziti_context ztx);

static void get_service_cb(ziti_context, const ziti_service *service, int status, void *ctx);

static int dispose(ziti_connection server);

static int start_binding(struct binding_s *b, ziti_channel_t *ch);

static void stop_binding(struct binding_s *b);

static void schedule_rebind(struct ziti_conn *conn);

static void session_cb(ziti_session *session, const ziti_error *err, void *ctx);

static void notify_status(struct ziti_conn *conn, int err);

static void free_binding(struct binding_s *b) {
    free(b);
}

int ziti_bind(ziti_connection conn, const char *service, const ziti_listen_opts *listen_opts,
              ziti_listen_cb listen_cb, ziti_client_cb on_clt_cb) {

    assert(conn->type == None);
    assert(conn->ziti_ctx != NULL);

    if (!conn->ziti_ctx->enabled) return ZITI_DISABLED;

    conn->type = Server;
    conn->disposer = dispose;
    conn->service = strdup(service);
    uv_random(NULL, NULL, conn->server.listener_id, sizeof(conn->server.listener_id), 0 , NULL);
    conn->server.cost = get_terminator_cost(listen_opts, service, conn->ziti_ctx);
    conn->server.precedence = get_terminator_precedence(listen_opts, service, conn->ziti_ctx);
    conn->server.max_bindings = listen_opts && listen_opts->max_connections > 0 ?
                                listen_opts->max_connections : DEFAULT_MAX_BINDINGS;

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

static void rebind_delay_cb(void *data) {
    ziti_connection conn = data;
    CONN_LOG(DEBUG, "staring re-bind");

    ziti_service_available(conn->ziti_ctx, conn->service, get_service_cb, conn);
}

static struct binding_s* new_binding(struct ziti_conn *conn) {
    NEWP(b, struct binding_s);
    b->conn_id = conn->conn_id;
    b->conn = conn;
    b->state = st_unbound;
    init_key_pair(&b->key_pair);
    return b;
}

// return number of active(bound or binding) bindings
int process_bindings(struct ziti_conn *conn) {
    if (conn->server.token == NULL) {
        return 0;
    }

    int active = 0;
    struct ziti_ctx *ztx = conn->ziti_ctx;

    size_t target = MIN(conn->server.max_bindings,
                        model_list_size(&conn->server.routers));

    ziti_edge_router *er;
    MODEL_LIST_FOREACH(er, conn->server.routers) {
        CONN_LOG(DEBUG, "checking router[%s]", er->name);
        ziti_channel_t *ch = ztx_get_channel(ztx, er);
        if (ch == NULL || !ziti_channel_is_connected(ch)) {
            CONN_LOG(DEBUG, "router[%s] is not connected", er->name);
            continue;
        }

        struct binding_s *b = model_map_get(&conn->server.bindings, er->name);
        if (b == NULL) {
            b = new_binding(conn);
            model_map_set(&conn->server.bindings, er->name, b);
        }
        active += start_binding(b, ch);
        if (active >= target) break;
    }
    return active;
}

void update_bindings(ziti_connection conn) {
    if (conn->type != Server) return;

    int target = MIN(conn->server.max_bindings,
                     model_list_size(&conn->server.routers));

    int active = 0;
    const char *n;
    struct binding_s *b;
    MODEL_MAP_FOREACH(n, b, &conn->server.bindings) {
        if (b->state == st_bound || b->state == st_binding) active++;
    }

    if (target > active) {
        active = process_bindings(conn);
    }

    CONN_LOG(DEBUG, "bindings: active[%d] target[%d]", active, target);
    // if we're still below target we may need to refresh service.routers
    if (target > active) {
        schedule_rebind(conn);
    } else {
        // target bindings achieved, reset backoff
        conn->server.attempt = 0;
        clear_deadline(&conn->server.rebinder);
    }
}

static void schedule_rebind(struct ziti_conn *conn) {
    if (!ziti_is_enabled(conn->ziti_ctx)) {
        return;
    }

    int backoff = 1 << MIN(conn->server.attempt, 5);
    uint32_t random;
    uv_random(conn->ziti_ctx->loop, NULL, &random, sizeof(random), 0, NULL);
    uint64_t delay = (uint64_t) (random % (backoff * REBIND_DELAY));
    conn->server.attempt++;
    CONN_LOG(DEBUG, "scheduling re-bind(attempt=%d) in %" PRIu64 ".%" PRIu64 "s",
             conn->server.attempt, delay / 1000, delay % 1000);

    ztx_set_deadline(conn->ziti_ctx, delay, &conn->server.rebinder, rebind_delay_cb, conn);
}

static void session_cb(ziti_session *session, const ziti_error *err, void *ctx) {
    struct ziti_conn *conn = ctx;
    int e = err ? (int)err->err : ZITI_OK;
    switch (e) {
        case ZITI_OK: {
            FREE(conn->server.token);
            conn->server.token = (char*)session->token;
            session->token = NULL;

            free_ziti_session_ptr(conn->server.session);
            conn->server.session = session;

            if (conn->server.srv_routers_api_missing) {
                model_list_clear(&conn->server.routers, (void (*)(void *)) free_ziti_edge_router_ptr);
                ziti_edge_router *er;
                MODEL_LIST_FOREACH(er, session->edge_routers) {
                    model_list_append(&conn->server.routers, er);
                }
                model_list_clear(&session->edge_routers, NULL);
            }
            process_bindings(conn);

            notify_status(conn, ZITI_OK);
            break;
        }
        case ZITI_NOT_FOUND:
        case ZITI_NOT_AUTHORIZED:
            CONN_LOG(WARN, "failed to get session for service[%s]: %d/%s",
                     conn->service, (int)err->err, err->code);
            const char *id;
            struct binding_s *b;
            MODEL_MAP_FOREACH(id, b, &conn->server.bindings) {
                CONN_LOG(DEBUG, "stopping binding[%s]", id);
                stop_binding(b);
            }

            // our session is stale
            if (conn->server.token) {
                FREE(conn->server.token);
                free_ziti_session_ptr(conn->server.session);
                conn->server.session = NULL;
                schedule_rebind(conn);
            } else {
                // here if we could not create Bind session
                notify_status(conn, ZITI_SERVICE_UNAVAILABLE);
            }
            break;

        default:
            CONN_LOG(WARN, "failed to get session for service[%s]: %d/%s", conn->service, (int)err->err, err->code);
            schedule_rebind(conn);
    }
}

static void list_routers_cb(ziti_service_routers *srv_routers, const ziti_error *err, void *ctx) {
    struct ziti_conn *conn = ctx;
    if (err) {
        CONN_LOG(WARN, "failed to list routers: %s", err->message);
        // older network
        // /edge/client/v1/service/{id}/edge-routers API not implemented yet
        if (err->http_code == 404) {
            conn->server.srv_routers_api_missing = true;
        }
    }

    if (srv_routers) {
        model_list_clear(&conn->server.routers, (void (*)(void *)) free_ziti_edge_router_ptr);

        ziti_edge_router *er;
        FOR(er, srv_routers->routers) {
            CONN_LOG(DEBUG, "%s/%s", er->name, er->protocols.tls);
            model_list_append(&conn->server.routers, er);
        }
        FREE(srv_routers->routers); // router objects moved to the list
    }
    free_ziti_service_routers_ptr(srv_routers);

    if (conn->server.token != NULL) {
        process_bindings(conn);
    }
}

static void get_service_cb(ziti_context ztx, const ziti_service *service, int status, void *ctx) {
    struct ziti_conn *conn = ctx;

    if (status == ZITI_SERVICE_UNAVAILABLE) {
        CONN_LOG(WARN, "service[%s] is not available", conn->service);
        notify_status(conn, ZITI_SERVICE_UNAVAILABLE);
        return;
    }

    if (status != ZITI_OK) {
        CONN_LOG(WARN, "failed to get service[%s] details, scheduling re-try", conn->service);
        schedule_rebind(conn);
        return;
    }

    if (!ziti_service_has_permission(service, ziti_session_types.Bind)) {
        CONN_LOG(WARN, "not authorized to Bind service[%s]", service->name);
        notify_status(conn, ZITI_SERVICE_UNAVAILABLE);
        return;
    }

    // NB: handle network upgrade
    // if our session became stale maybe controller was upgraded
    if (conn->server.token == NULL) {
        conn->server.srv_routers_api_missing = false;
    }

    if (!conn->server.srv_routers_api_missing) {
        ziti_ctrl_list_service_routers(ztx_get_controller(ztx), service, list_routers_cb, conn);
    }

    conn->encrypted = service->encryption;
    if (conn->server.token == NULL) {
        ziti_ctrl_create_session(ztx_get_controller(ztx), service->id, ziti_session_types.Bind, session_cb, conn);
    } else if (conn->server.srv_routers_api_missing) {
        ziti_ctrl_get_session(ztx_get_controller(ztx), conn->server.session->id, session_cb, conn);
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
            if (strcasecmp("failed", precedence) == 0) return PRECEDENCE.FAILED;
            if (strcasecmp("required", precedence) == 0) return PRECEDENCE.REQUIRED;
        }
    }

    return PRECEDENCE.DEFAULT;
}

static int dispose(ziti_connection server) {
    assert(server->type == Server);

    model_map_iter it = model_map_iterator(&server->server.bindings);
    while(it) {
        struct binding_s *b = model_map_it_value(it);
        if (b->state == st_unbound) {
            it = model_map_it_remove(it);
            free_binding(b);
        } else {
            it = model_map_it_next(it);
        }
    }

    if (model_map_size(&server->server.bindings)) {
        ZITI_LOG(VERBOSE, "waiting for bindings to clear");
        return 0;
    }

    if (model_map_size(&server->server.children) > 0) {
        ZITI_LOG(VERBOSE, "waiting for children to terminate");
        return 0;
    }

    clear_deadline(&server->server.rebinder);

    FREE(server->server.token);
    free_ziti_session_ptr(server->server.session);
    model_list_clear(&server->server.routers, (void (*)(void *)) free_ziti_edge_router_ptr);
    free(server->service);
    free(server);
    return 1;
}

#define BOOL_STR(v) ((v) ? "Y" : "N")

static void process_inspect(struct binding_s *b, message *msg) {
    struct ziti_conn *conn = b->conn;
    char conn_info[256];
    char listener_id[sodium_base64_ENCODED_LEN(sizeof(conn->server.listener_id), sodium_base64_VARIANT_URLSAFE)];
    sodium_bin2base64(listener_id, sizeof(listener_id),
                      conn->server.listener_id, sizeof(conn->server.listener_id), sodium_base64_VARIANT_URLSAFE);
    size_t ci_len = snprintf(conn_info, sizeof(conn_info),
                             "id[%d] serviceName[%s] listenerId[%s] "
                             "closed[%s] encrypted[%s]",
                             conn->conn_id, conn->service, listener_id,
                             BOOL_STR(conn->close), BOOL_STR(conn->encrypted));
    CONN_LOG(DEBUG, "processing inspect: %.*s", (int)ci_len, conn_info);
    message *reply = new_inspect_result(msg->header.seq, conn->conn_id, ConnTypeBind, conn_info, ci_len);
    ziti_channel_send_message(b->ch, reply, NULL);
}

static void process_dial(struct binding_s *b, message *msg) {
    struct ziti_conn *conn = b->conn;

    size_t peer_key_len, marker_len;
    const uint8_t *peer_key;
    const uint8_t *marker;
    uint32_t rt_conn_id;
    bool peer_key_sent = message_get_bytes_header(msg, PublicKeyHeader, &peer_key, &peer_key_len);
    bool marker_sent = message_get_bytes_header(msg, ConnectionMarkerHeader, &marker, &marker_len);
    bool rt_conn_id_sent = message_get_int32_header(msg, RouterProvidedConnId, (int32_t*)&rt_conn_id);

    if (!peer_key_sent && conn->encrypted) {
        ZITI_LOG(ERROR, "failed to establish crypto for encrypted service: did not receive peer key");
        reject_dial_request(conn->conn_id, b->ch, msg->header.seq, "did not receive peer crypto key");
        return;
    }

    ziti_connection client;
    ziti_conn_init(conn->ziti_ctx, &client, NULL);
    if (rt_conn_id_sent) {
        ZITI_LOG(DEBUG, "conn[%u] using router provided conn_id[%u]", client->conn_id, rt_conn_id);
        client->rt_conn_id = rt_conn_id;
    }
    init_transport_conn(client);
    if (marker_sent) {
        snprintf(client->marker, sizeof(client->marker), "%.*s", (int) marker_len, marker);
    } else {
        snprintf(client->marker, sizeof(client->marker), "-");
    }
    client->start = uv_now(conn->ziti_ctx->loop);

    if (conn->encrypted) {
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
    const uint8_t *source_identity = NULL;
    size_t source_identity_sz = 0;
    bool caller_id_sent = message_get_bytes_header(msg, CallerIdHeader, &source_identity, &source_identity_sz);

    ziti_client_ctx clt_ctx = {0};
    message_get_bytes_header(msg, AppDataHeader, (const uint8_t **) &clt_ctx.app_data, &clt_ctx.app_data_sz);
    if (caller_id_sent) {
        client->source_identity = calloc(1, source_identity_sz + 1);
        memcpy(client->source_identity, source_identity, source_identity_sz);
        clt_ctx.caller_id = client->source_identity;
    }
    conn->server.client_cb(conn, client, ZITI_OK, &clt_ctx);

}

static void on_message(struct binding_s *b, message *msg, int code) {
    struct ziti_conn *conn = b->conn;
    if (code != ZITI_OK) {
        ZITI_LOG(WARN, "binding failed: %d/%s", code, ziti_errorstr(code));
        b->ch = NULL;
        stop_binding(b);
        if (code == ZITI_DISABLED) {
            clear_deadline(&conn->server.rebinder);
            notify_status(conn, code);
        } else {
            schedule_rebind(conn);
        }
    } else {
        ZITI_LOG(DEBUG, "received msg ct[%s] code[%d] from %s", content_type_id(msg->header.content), code, b->ch->name);
        switch (msg->header.content) {
            case ContentTypeStateClosed:
                CONN_LOG(DEBUG, "binding[%s] was closed: %.*s", b->ch->url, msg->header.body_len, msg->body);
                FREE(conn->server.token);
                stop_binding(b);
                schedule_rebind(conn);
                break;
            case ContentTypeDial:
                process_dial(b, msg);
                break;
            case ContentTypeConnInspectRequest:
                process_inspect(b, msg);
                break;
            default:
                ZITI_LOG(ERROR, "unexpected msg[%s] for bound conn[%d]",
                         content_type_id(msg->header.content), conn->conn_id);
        }
    }

    pool_return_obj(msg);
}

static void bind_reply_cb(void *ctx, message *msg, int code) {
    struct binding_s *b = ctx;
    struct ziti_conn *conn = b->conn;

    b->waiter = NULL;
    if (code == ZITI_OK && msg->header.content == ContentTypeStateConnected) {
        CONN_LOG(TRACE, "received msg ct[%s] code[%d]", content_type_id(msg->header.content), code);
        CONN_LOG(DEBUG, "bound successfully on router[%s]", b->ch->name);
        ziti_channel_add_receiver(b->ch, b->conn_id, b,
                                  (void (*)(void *, message *, int)) on_message);
        b->state = st_bound;
    } else {
        CONN_LOG(DEBUG, "failed to bind on router[%s]", b->ch->name);
        ziti_channel_rem_receiver(b->ch, b->conn_id);
        b->ch = NULL;
        b->state = st_unbound;
    }
}

int start_binding(struct binding_s *b, ziti_channel_t *ch) {
    switch(b->state) {
        case st_unbound:
            break;

        case st_binding: // already active
        case st_bound:
            return 1;

        case st_unbinding: // let it complete unbind
            return 0;
    }

    struct ziti_conn *conn = b->conn;
    char *token = conn->server.token;
    CONN_LOG(DEBUG, "requesting BIND on ch[%s]", ch->name);
    CONN_LOG(TRACE, "ch[%d] => Edge Bind request token[%s]", ch->id, token);

    b->ch = ch;
    b->state = st_binding;

    uint8_t true_val = 1;
    int32_t conn_id = htole32(conn->conn_id);
    int32_t msg_seq = htole32(0);
    uint16_t cost = htole16(conn->server.cost);

    hdr_t headers[9] = {
            var_header(ConnIdHeader, conn_id),
            var_header(SeqHeader, msg_seq),
            header(ListenerId, sizeof(b->conn->server.listener_id), b->conn->server.listener_id),
            var_header(SupportsInspectHeader, true_val),
            var_header(RouterProvidedConnId, true_val),
            // blank hdr_t's to be filled in if needed by options
    };
    int nheaders = 5;
    if (conn->encrypted) {
        headers[nheaders++] = header(PublicKeyHeader, sizeof(b->key_pair.pk), b->key_pair.pk);
    }

    if (conn->server.identity != NULL) {
        headers[nheaders++] = header(TerminatorIdentityHeader,
                                     strlen(conn->server.identity), conn->server.identity);
    }

    if (conn->server.cost > 0) {
        headers[nheaders++] = var_header(CostHeader, cost);
    }

    if (conn->server.precedence != PRECEDENCE.DEFAULT) {
        headers[nheaders++] = var_header(PrecedenceHeader, conn->server.precedence);
    }

    if (b->waiter) {
        ziti_channel_remove_waiter(b->ch, b->waiter);
    }

    b->waiter = ziti_channel_send_for_reply(b->ch, ContentTypeBind,
                                            headers, nheaders,
                                            token, strlen(token), bind_reply_cb,
                                            b);
    return 1;
}

void on_unbind(void *ctx, message *m, int code) {
    struct binding_s *b = ctx;
    b->waiter = NULL;

    if (m) {
        ZITI_LOG(DEBUG, "binding[%d.%s] unbind resp: ct[%s] %.*s", b->conn_id,
                 b->ch->name, content_type_id(m->header.content), m->header.body_len, m->body);
        int32_t conn_id = htole32(b->conn_id);
        hdr_t headers[] = {
                var_header(ConnIdHeader, conn_id),
        };
        message *close_msg = message_new(NULL, ContentTypeStateClosed, headers, 1, 0);
        ziti_channel_send_message(b->ch, close_msg, NULL);
    } else {
        ZITI_LOG(DEBUG, "binding[%d.%s] failed to receive unbind response because channel was disconnected: %d/%s",
                 b->conn_id, b->ch->name, code, ziti_errorstr(code));
    }
    ziti_channel_rem_receiver(b->ch, b->conn_id);
    b->state = st_unbound;
    b->ch = NULL;
}

static void stop_binding(struct binding_s *b) {
    struct ziti_conn *conn = b->conn;

    // stop accepting incoming requests
    ziti_channel_rem_receiver(b->ch, b->conn_id);
    ziti_channel_remove_waiter(b->ch, b->waiter);

    char *token = conn->server.token;
    // no need to send unbind message
    if (b->ch == NULL || !ziti_channel_is_connected(b->ch) || token == NULL) {
        b->ch = NULL;
        b->state = st_unbound;
        return;
    }

    CONN_LOG(DEBUG, "requesting UNBIND on ch[%s]", b->ch->name);
    b->state = st_unbinding;
    int32_t conn_id = htole32(b->conn_id);
    hdr_t headers[] = {
            var_header(ConnIdHeader, conn_id),
            header(ListenerId, sizeof(conn->server.listener_id), conn->server.listener_id),
    };
    b->waiter = ziti_channel_send_for_reply(b->ch, ContentTypeUnbind,
                                            headers, 2,
                                            token, strlen(token),
                                            on_unbind, b);
}

int ziti_close_server(struct ziti_conn *conn) {
    const char *id;
    struct binding_s *b;
    clear_deadline(&conn->server.rebinder);
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
        return;
    }

    if (conn->server.client_cb == NULL) return;

    if (err == ZITI_DISABLED) {
        // only notify once, app is expected to call ziti_close()
        conn->server.client_cb(conn, NULL, err, NULL);
        conn->server.client_cb = NULL;
    } else if (err != ZITI_OK) {
        conn->server.client_cb(conn, NULL, err, NULL);
    }
}
