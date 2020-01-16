/*
Copyright 2019-2020 Netfoundry, Inc.

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

/**
 * @file ziti.h
 * @brief Ziti C SDK API.
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

/**
 * Flag indicating service `Dial` permission
 */
#define ZITI_CAN_DIAL 1

/**
 * Flag indicating service `Bind` permission
 */
#define ZITI_CAN_BIND 2

/**
 * \brief Ziti edge identity context
 * \see NF_init()
 */
typedef struct nf_ctx *nf_context;

/**
 * \brief Ziti connection object.
 * \see NF_dial()
 */
typedef struct nf_conn *nf_connection;

/**
 * \brief Ziti edge context init callback.
 * @param nf_ctx edge identity context
 * @param status ZITI_OK or error code
 * @param init_ctx custom data passed to NF_init()
 */
typedef void (*nf_init_cb)(nf_context nf_ctx, int status, void* init_ctx);

/**
 * \brief Service status callback type.
 */
typedef void (*nf_service_cb)(nf_context nf_ctx, const char* service_name, int status, unsigned int flags, void *data);

/**
 * \brief Data callback.
 * @param conn Ziti connection which received data
 * @param data incoming data buffer
 * @param length size of data or error code (will receive ZITI_EOF when connection is closed)
 *
 */
typedef void (*nf_data_cb)(nf_connection conn, uint8_t *data, int length);

/**
 * \brief Connection callback.
 * @param conn connection
 * @param status ZITI_OK if NF_dial() is successful, error code if not.
 */
typedef void (*nf_conn_cb)(nf_connection conn, int status);

/**
 * \brief callback called when client connects to a service hosted by given context
 * @param serv hosting connection, initialized with NF_listen()
 * @param client client connection
 * @param status ZITI_OK or error
 */
typedef void (*nf_client_cb)(nf_connection serv, nf_connection client, int status);

typedef nf_conn_cb nf_listen_cb;

/**
 * \brief callback called after NF_write() is complete.
 */
typedef void (*nf_write_cb)(nf_connection conn, ssize_t status, void *write_ctx);

extern int
NF_init_with_tls(const char *ctrl_url, tls_context *tls_context, uv_loop_t *loop, nf_init_cb init_cb, void *init_ctx);

/**
 * Initialize Ziti Edge identity context.
 * @param config location of identity configuration
 * @param loop libuv event loop
 * @param cb callback to be called when initialization is complete
 * @param init_ctx custom data to be passed into callback
 * @return ZITI_OK or error
 */
extern int NF_init(const char* config, uv_loop_t* loop, nf_init_cb cb, void* init_ctx);

/**
 * sets connect and write timeouts(in millis) on all connections created in this context.
 * changing value only affects future connections initialized via NF_conn_init()
 */
extern int NF_set_timeout(nf_context nf_ctx, int timeout);

/**
 * \brief Shutdown ziti edge identity context.
 * @param nf_ctx
 * @return
 */
extern int NF_shutdown(nf_context nf_ctx);

/**
 * \brief release all memory associated with the context.
 *
 * @param nf_ctx
 * @return
 */
extern int NF_free(nf_context *nf_ctx);

extern void NF_dump(nf_context nf_ctx);

/**
 * \brief Initialize connection before NF_dial() or NF_listen()
 * @param nf_ctx
 * @param conn
 * @param data
 * @return
 */
extern int NF_conn_init(nf_context nf_ctx, nf_connection *conn, void *data);

/**
 * \brief Retrieve custom data associated with given connection
 * @param conn
 * @return custom data passed into NF_conn_init()
 */
extern void *NF_conn_data(nf_connection conn);

/**
 * \brief Checks availability of the service for the given edge context.
 * @param nf_ctx
 * @param service
 * @param cb callback called with ZITI_OK or ZITI_SERVICE_NOT_AVAILABLE
 * @param ctx custom data
 * @return
 */
extern int NF_service_available(nf_context nf_ctx, const char *service, nf_service_cb cb, void *ctx);

/**
 * \brief Establishes connection to a Ziti service.
 * @param conn connection object
 * @param service service name
 * @param cb
 * @param data_cb
 * @return
 */
extern int NF_dial(nf_connection conn, const char *service, nf_conn_cb cb, nf_data_cb data_cb);

/**
 * \brief Start accepting ziti client connections.
 * @param serv_conn
 * @param service service name
 * @param lcb listen callback
 * @param cb client callback, called when client is attempting to connect to advertised service.
 * @return
 */
extern int NF_listen(nf_connection serv_conn, const char *service, nf_listen_cb lcb, nf_client_cb cb);

/**
 * \brief Completes client connection.
 * @param clt client connection
 * @param cb connection callback
 * @param data_cb data callback
 * @return
 */
extern int NF_accept(nf_connection clt, nf_conn_cb cb, nf_data_cb data_cb);

/**
 * \brief Close connection.
 * @param conn
 * @return
 */
extern int NF_close(nf_connection *conn);

/**
 * \brief Send data to the connection peer.
 * data buffer passed into this function should be intact until callback is called. It is only safe to free the buffer in
 * the write callback.
 * @param conn
 * @param data
 * @param length
 * @param write_ctx
 * @return
 */
extern int NF_write(nf_connection conn, uint8_t *data, size_t length, nf_write_cb, void *write_ctx);

#ifdef __cplusplus
}
#endif

#endif /* NF_ZT_H */