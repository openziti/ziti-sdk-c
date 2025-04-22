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

#ifndef ZT_SDK_ZT_INTERNAL_H
#define ZT_SDK_ZT_INTERNAL_H


#include <stdbool.h>
#include <tlsuv/tlsuv.h>
#include <tlsuv/queue.h>

#include <ziti/ziti.h>
#include "buffer.h"
#include "pool.h"
#include "ziti_ctrl.h"
#include "metrics.h"
#include "posture.h"
#include "authenticators.h"
#include "auth_method.h"
#include "deadline.h"

#include <sodium.h>

#if !defined(UUID_STR_LEN)
#define UUID_STR_LEN 37
#endif

#define MARKER_BIN_LEN 6
#define MARKER_CHAR_LEN sodium_base64_ENCODED_LEN(MARKER_BIN_LEN, sodium_base64_VARIANT_URLSAFE_NO_PADDING)

#define ZTX_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "ztx[%u] " fmt, ztx->id, ##__VA_ARGS__)

#define DST_PROTOCOL "dst_protocol"
#define DST_HOSTNAME "dst_hostname"
#define DST_PORT "dst_port"

#define ZITI_LOG_ERROR(level, e, fmt, ...) do{\
const char *reason = model_map_get(&e->cause, "reason");\
ZITI_LOG(level, fmt " %s[%s] reason[%s]", ##__VA_ARGS__, e->code, e->message, reason ? reason : ""); \
} while(0)


extern const char *APP_ID;
extern const char *APP_VERSION;

typedef struct message_s message;
typedef struct hdr_s hdr_t;

typedef struct ziti_channel ziti_channel_t;

typedef void (*reply_cb)(void *ctx, message *m, int err);

typedef void (*ch_notify_state)(ziti_channel_t *ch, ziti_router_status status, void *ctx);

typedef int ch_state;
typedef int conn_state;

struct ziti_channel {
    uv_loop_t *loop;
    struct ziti_ctx *ztx;
    char *name;
    char *url;
    char *version;
    char *host;
    int port;

    uint32_t id;
    char token[UUID_STR_LEN];
    tlsuv_stream_t *connection;
    bool reconnect;

    // multipurpose timer:
    // - reconnect timeout if not connected
    // - connect timeout when connecting
    // - latency interval/timeout if connected
    deadline_t deadline;

    uint64_t latency;
    struct waiter_s *latency_waiter;
    uint64_t last_read;
    uint64_t last_write;
    uint64_t last_write_delay;
    size_t out_q;
    size_t out_q_bytes;

    ch_state state;
    uint32_t reconnect_count;

    uint32_t msg_seq;

    buffer *incoming;

    pool_t *in_msg_pool;
    message *in_next;
    size_t in_body_offset;

    // map[id->msg_receiver]
    model_map receivers;

    // map[msg_seq->waiter_s]
    model_map waiters;

    ch_notify_state notify_cb;
    void *notify_ctx;
};

struct ziti_write_req_s {
    struct ziti_conn *conn;
    struct ziti_channel *ch;
    uint8_t *buf;
    size_t len;
    bool eof;
    bool close;

    struct message_s *message;
    ziti_write_cb cb;
    uint64_t start_ts;

    void *ctx;

    TAILQ_ENTRY(ziti_write_req_s) _next;
    model_list chain;
    size_t chain_len;
};

struct key_pair {
    uint8_t sk[crypto_kx_SECRETKEYBYTES];
    uint8_t pk[crypto_kx_PUBLICKEYBYTES];
};

struct key_exchange {
    uint8_t *rx;
    uint8_t *tx;
};

int init_key_pair(struct key_pair *kp);

int init_crypto(struct key_exchange *key_ex, struct key_pair *kp, const uint8_t *peer_key, bool server);

void free_key_exchange(struct key_exchange *key_ex);

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
            char listener_id[32];
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
            conn_state state;
            bool fin_sent;
            int fin_recv; // 0 - not received, 1 - received, 2 - called app data cb
            bool disconnecting;

            TAILQ_HEAD(, message_s) in_q;
            buffer *inbound;
            uv_idle_t *flusher;
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

struct process {
    char *path;
    bool is_running;
    char *sha_512_hash;
    char **signers;
    int num_signers;
};

typedef void (*ztx_work_f)(ziti_context ztx, void *w_ctx);

struct ztx_work_s {
    ztx_work_f w;
    void *w_data;
    STAILQ_ENTRY(ztx_work_s) _next;
};

typedef STAILQ_HEAD(work_q, ztx_work_s) ztx_work_q;

struct tls_credentials {
    tlsuv_private_key_t key;
    tlsuv_certificate_t cert;
};

struct ziti_ctx {
    ziti_config config;
    ziti_options opts;
    ziti_controller ctrl;
    uint32_t id;

    model_map ctrl_details;

    tls_context *tlsCtx;
    struct tls_credentials id_creds;
    struct tls_credentials session_creds;
    char *sessionCsr;

    bool closing;
    bool enabled;
    int ctrl_status;

    ziti_auth_method_t *auth_method;
    ziti_auth_state auth_state;
    ziti_mfa_cb mfa_cb;
    void *mfa_ctx;

    model_map ext_signers;
    struct oidc_client_s *ext_auth;
    void (*ext_launch_cb)(ziti_context, const char*, void*);
    void *ext_launch_ctx;

    // HA access_token(JWT) or legacy ziti_api_session.token
    char *session_token;

    ziti_identity_data *identity_data;

    bool services_loaded;
    // map<name,ziti_service>
    model_map services;
    // map<service_id,ziti_session>
    model_map sessions;

    // map<service_id,*bool>
    model_map service_forced_updates;

    char *last_update;

    // map<erUrl,ziti_channel>
    model_map channels;
    // map<id,ziti_conn>
    model_map connections;

    // map<conn_id,conn_id> -- connections waiting for a suitable channel
    // map to make removal easier
    model_map waiting_connections;

    uint32_t conn_seq;

    /* context wide metrics */
    uint64_t start;
    rate_t up_rate;
    rate_t down_rate;

    /* posture check support */
    struct posture_checks *posture_checks;

    /* auth query (MFA) support */
    struct auth_queries *auth_queries;

    deadline_t refresh_deadline;
    deadline_list_t deadlines;

    uv_loop_t *loop;
    uv_timer_t deadline_timer;

    uv_prepare_t prepper;

    ztx_work_q w_queue;
    uv_mutex_t w_lock;
    uv_async_t w_async;
};

#ifdef __cplusplus
extern "C" {
#endif

ziti_controller *ztx_get_controller(ziti_context ztx);

void ziti_invalidate_session(ziti_context ztx, const char *service_id, ziti_session_type type);

void ziti_on_channel_event(ziti_channel_t *ch, ziti_router_status status, ziti_context ztx);

void ziti_force_api_session_refresh(ziti_context ztx);

const char* ziti_get_api_session_token(ziti_context ztx);

int ziti_close_channels(ziti_context ztx, int err);

bool ziti_channel_is_connected(ziti_channel_t *ch);

uint64_t ziti_channel_latency(ziti_channel_t *ch);

int ziti_channel_force_connect(ziti_channel_t *ch);

int ziti_channel_update_token(ziti_channel_t *ch, const char *token);

int ziti_channel_update_posture(ziti_channel_t *ch, const uint8_t *data, size_t len);

int ziti_channel_connect(ziti_context ztx, const char *name, const char *url);

int ziti_channel_prepare(ziti_channel_t *ch);

int ziti_channel_close(ziti_channel_t *ch, int err);

void ziti_channel_add_receiver(ziti_channel_t *ch, uint32_t id, void *receiver, void (*receive_f)(void *, message *, int));

void ziti_channel_rem_receiver(ziti_channel_t *ch, uint32_t id);

int ziti_channel_send_message(ziti_channel_t *ch, message *msg, struct ziti_write_req_s *ziti_write);

int ziti_channel_send(ziti_channel_t *ch, uint32_t content, const hdr_t *hdrs, int nhdrs, const uint8_t *body,
                      uint32_t body_len,
                      struct ziti_write_req_s *ziti_write);

struct waiter_s *
ziti_channel_send_for_reply(ziti_channel_t *ch, uint32_t content, const hdr_t *headers, int nhdrs, const uint8_t *body,
                            uint32_t body_len, reply_cb,
                            void *reply_ctx);

void ziti_channel_remove_waiter(ziti_channel_t *ch, struct waiter_s *waiter);

int parse_enrollment_jwt(const char *token, ziti_enrollment_jwt_header *zejh, ziti_enrollment_jwt *zej, char **sig, size_t *sig_len);

int load_tls(ziti_config *cfg, tls_context **tls, struct tls_credentials *creds);

int ziti_bind(ziti_connection conn, const char *service, const ziti_listen_opts *listen_opts,
              ziti_listen_cb listen_cb, ziti_client_cb on_clt_cb);

void conn_inbound_data_msg(ziti_connection conn, message *msg);

void on_write_completed(struct ziti_conn *conn, struct ziti_write_req_s *req, int status);

void update_bindings(struct ziti_conn *conn);
const char *ziti_conn_state(ziti_connection conn);

int establish_crypto(ziti_connection conn, message *msg);


void hexify(const uint8_t *bin, size_t bin_len, char sep, char **buf);

void ziti_re_auth_with_cb(ziti_context ztx, void(*cb)(ziti_api_session *, const ziti_error *, void *), void *ctx);

void ziti_queue_work(ziti_context ztx, ztx_work_f w, void *data);

void ziti_force_service_update(ziti_context ztx, const char *service_id);

void ziti_services_refresh(ziti_context ztx, bool now);

extern void ziti_send_event(ziti_context ztx, const ziti_event_t *e);

void reject_dial_request(uint32_t conn_id, ziti_channel_t *ch, uint32_t req_id, const char *reason);

const ziti_env_info* get_env_info();

int conn_bridge_info(ziti_connection conn, char *buf, size_t buflen);

void process_connect(struct ziti_conn *conn, ziti_session *session);

int ztx_init_external_auth(ziti_context ztx, const ziti_jwt_signer *signer);

void ztx_auth_state_cb(void *, ziti_auth_state , const void *);
ziti_channel_t * ztx_get_channel(ziti_context ztx, const ziti_edge_router *er);

void ztx_set_deadline(ziti_context ztx, uint64_t timeout, deadline_t *d, void (*cb)(void *), void *ctx);

int ch_send_conn_closed(ziti_channel_t *ch, uint32_t conn_id);

#ifdef __cplusplus
}
#endif
#endif //ZT_SDK_ZT_INTERNAL_H
