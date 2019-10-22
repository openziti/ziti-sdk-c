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

#ifndef NF_ZT_H
#define NF_ZT_H

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <uv.h>
#include <uv_mbed/tls_engine.h>
#include "errors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nf_ctx *nf_context;
typedef struct nf_conn *nf_connection;

typedef void (*nf_init_cb)(nf_context nf_ctx, int status, void* init_ctx);
typedef void (*nf_data_cb)(nf_connection conn, uint8_t *data, int length);
typedef void (*nf_conn_cb)(nf_connection conn, int status);

typedef void (*nf_client_cb)(nf_connection serv, nf_connection client, int status);

typedef nf_conn_cb nf_listen_cb;

typedef void (*nf_write_cb)(nf_connection conn, ssize_t status, void *write_ctx);

extern int
NF_init_with_tls(const char *ctrl_url, tls_context *tls_context, uv_loop_t *loop, nf_init_cb init_cb, void *init_ctx);
extern int NF_init(const char* config, uv_loop_t* loop, nf_init_cb cb, void* init_ctx);

/*
 * set connect and write timeouts(in millis) on all connections created in this context.
 * changing value only affects future connections initialized via NF_conn_init()
 */
extern int NF_set_timeout(nf_context nf_ctx, int timeout);

extern int NF_shutdown(nf_context nf_ctx);
extern int NF_free(nf_context *nf_ctx);
extern void NF_dump(nf_context nf_ctx);

extern int NF_conn_init(nf_context nf_ctx, nf_connection *conn, void *data);

extern void *NF_conn_data(nf_connection conn);

extern int NF_service_available(nf_context nf_ctx, const char *service);

extern int NF_dial(nf_connection conn, const char *service, nf_conn_cb cb, nf_data_cb data_cb);

extern int NF_listen(nf_connection serv_conn, const char *service, nf_listen_cb lcb, nf_client_cb cb);

extern int NF_accept(nf_connection clt, nf_conn_cb cb, nf_data_cb data_cb);

extern int NF_close(nf_connection *conn);

/*
 * data buffer passed into this function should be intact until callback is called. It is only safe to free the buffer in
 * the write callback.
 */
extern int NF_write(nf_connection conn, uint8_t *data, size_t length, nf_write_cb, void *write_ctx);

#ifdef __cplusplus
}
#endif

#endif /* NF_ZT_H */