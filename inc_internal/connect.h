// Copyright (c) 2023-2026.  NetFoundry Inc
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.


#ifndef ZITI_SDK_CONNECT_H
#define ZITI_SDK_CONNECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ziti/ziti.h>
#include "buffer.h"
#include "crypto.h"
#include "deadline.h"
#include "internal_model.h"
#include "message.h"

#define MARKER_BIN_LEN 6
#define MARKER_CHAR_LEN sodium_base64_ENCODED_LEN(MARKER_BIN_LEN, sodium_base64_VARIANT_URLSAFE_NO_PADDING)

#define conn_states(XX) \
    XX(Initial)\
    XX(Connecting)\
    XX(Connected)\
    XX(Accepting)\
    XX(CloseWrite)\
    XX(Timedout)\
    XX(Disconnected)\
    XX(Closed)

enum conn_state {
#define state_enum(ST) ST,
    conn_states(state_enum)
};

typedef struct ziti_channel ziti_channel_t;

enum ziti_conn_type {
    None,
    Transport,
    Server,
};

struct ziti_conn {
    struct ziti_ctx *ziti_ctx;
    enum ziti_conn_type type;
    char *service;
    char *source_identity;
    uint32_t conn_id;
    uint32_t rt_conn_id;
    void *data;

    int (*disposer)(struct ziti_conn *self);

    ziti_close_cb close_cb;
    bool close;
    bool encrypted;

    union {
        struct {
            char *identity;
            uint16_t cost;
            uint8_t precedence;
            int max_bindings;

            ziti_listen_cb listen_cb;
            ziti_client_cb client_cb;

            bool srv_routers_api_missing;
            model_list routers;
            char *token;
            ziti_session *session;
            model_map bindings;
            model_map children;
            deadline_t rebinder;
            unsigned int attempt;
            uint8_t listener_id[32];
        } server;

        struct {
            struct key_pair key_pair;
            struct ziti_conn_req *conn_req;

            char marker[MARKER_CHAR_LEN];

            uint32_t edge_msg_seq;
            uint32_t in_msg_seq;
            uint32_t flags;

            ziti_channel_t *channel;
            ziti_data_cb data_cb;
            enum conn_state state;
            bool fin_sent;
            int fin_recv; // 0 - not received, 1 - received, 2 - called app data cb
            bool disconnecting;

            deadline_t flusher;
            TAILQ_HEAD(, message_s) in_q;
            buffer *inbound;
            TAILQ_HEAD(, ziti_write_req_s) wreqs;
            TAILQ_HEAD(, ziti_write_req_s) pending_wreqs;

            struct ziti_conn *parent;
            uint32_t dial_req_seq;

            struct key_exchange key_ex;

            crypto_secretstream_xchacha20poly1305_state crypt_o;
            crypto_secretstream_xchacha20poly1305_state crypt_i;

            // stats
            bool bridged;
            uint64_t start;
            uint64_t connect_time;
            uint64_t last_activity;
            uint64_t sent;
            uint64_t received;
        };
    };


};

int conn_bridge_info(ziti_connection conn, char *buf, size_t buflen);

void process_connect(struct ziti_conn *conn, ziti_session *session);

int ziti_bind(ziti_connection conn, const char *service, const ziti_listen_opts *listen_opts,
              ziti_listen_cb listen_cb, ziti_client_cb on_clt_cb);

void conn_inbound_data_msg(ziti_connection conn, message *msg);

void on_write_completed(struct ziti_conn *conn, struct ziti_write_req_s *req, int status);

void update_bindings(struct ziti_conn *conn);
const char *ziti_conn_state(ziti_connection conn);

int establish_crypto(ziti_connection conn, message *msg);

void init_transport_conn(struct ziti_conn *conn);

int ziti_close_server(struct ziti_conn *conn);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_CONNECT_H
