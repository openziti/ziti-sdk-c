/*
Copyright 2019 Netfoundry, Inc.

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

#ifndef ZT_SDK_ZT_INTERNAL_H
#define ZT_SDK_ZT_INTERNAL_H


#include <stdbool.h>
#include <sys/queue.h>
#include <uv_mbed/uv_mbed.h>

#include <nf/ziti.h>
#include "model.h"
#include "buffer.h"
#include "message.h"

//#define SIZEOF(arr) (sizeof(arr) / sizeof((arr)[0]))

#if !defined(UUID_STR_LEN)
#define UUID_STR_LEN 37
#endif


#if _WIN32
#define uint unsigned int
#endif

enum content_type {

    ContentTypeHelloType = 0,
    ContentTypePingType = 1,
    ContentTypeResultType = 2,
    ContentTypeLatencyType = 3,

    ContentTypeEdge = 0xED6E,
    ContentTypeConnect = 60783,
    ContentTypeStateConnected = 60784,
    ContentTypeStateClosed = 60785,
    ContentTypeData = 60786,
    ContentTypeDial = 60787,
    ContentTypeDialSuccess = 60788,
    ContentTypeDialFailed = 60789,
    ContentTypeBind = 60790,
    ContentTypeUnbind = 60791,
};

enum header_id {
    ConnectionIdHeader = 0,
    ReplyForHeader = 1,
    ResultSuccessHeader = 2,
    HelloListenerHeader = 3,

    // Headers in the range 128-255 inclusive will be reflected when creating replies
            ReflectedHeaderBitMask = 1 << 7,
    MaxReflectedHeader = (1 << 8) - 1,

    ConnIdHeader = 1000,
    SeqHeader = 1001,
    SessionTokenHeader = 1002,
};

typedef struct ziti_channel ziti_channel_t;

typedef void (*reply_cb)(void *ctx, message *m);

typedef void (*send_cb)(int status, void *ctx);

typedef void (*ch_connect_cb)(ziti_channel_t *ch, void *ctx, int status);

enum conn_state {
    Initial,
    Connecting,
    Connected,
    Binding,
    Bound,
    Accepting,
    Closed
};

typedef struct ziti_channel {
    struct nf_ctx *ctx;
    char *ingress;

    uint32_t id;
    char token[UUID_STR_LEN];
    uv_mbed_t connection;

    enum conn_state state;

    struct ch_conn_req **conn_reqs;
    int conn_reqs_n;

    uint32_t conn_seq;
    uint32_t msg_seq;

    buffer *incoming;

    message *in_next;
    int in_body_offset;

    SLIST_HEAD(con_list, nf_conn) connections;
    SLIST_HEAD(waiter, waiter_s) waiters;

    SLIST_ENTRY(ziti_channel) next;
} ziti_channel_t;

struct nf_write_req {
    struct nf_conn *conn;
    uint8_t *buf;
    size_t len;

    uint8_t *payload; // internal buffer
    nf_write_cb cb;
    uv_timer_t *timeout;

    void *ctx;
};

struct nf_conn {
    char* token;

    uint32_t edge_msg_seq;
    uint32_t conn_id;

    struct nf_ctx *nf_ctx;
    ziti_channel_t *channel;
    nf_data_cb data_cb;
    nf_client_cb client_cb;
    enum conn_state state;
    int timeout;

    int write_reqs;

    void *data;

    struct nf_conn *parent;
    uint32_t dial_req_seq;

    SLIST_ENTRY(nf_conn) next;
};


struct nf_ctx {
    char controller[128];
    uint16_t controller_port;
    tls_context *tlsCtx;

    ziti_session *session;
    ziti_service_list services;
    ziti_net_session_list net_sessions;

    uv_loop_t *loop;
    uv_thread_t loop_thread;
    uint32_t ch_counter;

    SLIST_HEAD(channels, ziti_channel) channels;

    /* options */
    int ziti_timeout;
};


int ziti_close_channels(nf_context);

int ziti_channel_connect(nf_context nf, const char *url, ch_connect_cb, void *ctx);

int ziti_channel_close(ziti_channel_t *ch);

int ziti_channel_send(ziti_channel_t *ch, uint32_t content, const hdr_t *hdrs, int nhdrs, const uint8_t *body,
                      uint32_t body_len,
                      struct nf_write_req *wr);

int
ziti_channel_send_for_reply(ziti_channel_t *ch, uint32_t content, const hdr_t *headers, int nhdrs, const uint8_t *body,
                            uint32_t body_len, reply_cb,
                            void *reply_ctx);

int load_config(const char *filename, nf_config **);

int ziti_auth(nf_context ctx);
int ziti_logout(nf_context ctx);

int ziti_bind(nf_connection conn, const char *service, nf_listen_cb listen_cb, nf_client_cb on_clt_cb);

int ziti_accept(nf_connection conn, nf_conn_cb cb, nf_data_cb data_cb);

int ziti_dial(nf_connection conn, const char *service, nf_conn_cb conn_cb, nf_data_cb data_cb);

int ziti_write(struct nf_write_req *req);
int ziti_disconnect(struct nf_conn *conn);

void on_write_completed(struct nf_conn *conn, struct nf_write_req *req, int status);
#endif //ZT_SDK_ZT_INTERNAL_H
