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

/**
 * @file connection.h
 * @brief Ziti connections: dial, listen, accept, read and write, and bridging to IO streams.
 */

#ifndef ZITI_CONNECTION_H
#define ZITI_CONNECTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uv.h>

#include "externs.h"
#include "handles.h"
#include "ziti_model.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The default timeout in milliseconds for connection operations to succeed.
 */
#define ZITI_DEFAULT_TIMEOUT 10000

typedef struct ziti_dial_opts_s {
    /** enable stream semantics
     * this allows SDK to consolidate multiple write requests to lower overlay overhead
     */
    bool stream;
    int connect_timeout_seconds;
    const char *identity;
    /**
     * indicates that this connection is part of a group.
     * grouped connections will use the same terminator if the service allows it (`service.routingStrategy == "sticky"`)
     * this is useful when service can be more efficient when a client hits the same instance
     * (client session caching for example)
     */
    const char *group;
    void *app_data;
    size_t app_data_sz;
} ziti_dial_opts;

typedef struct ziti_client_ctx_s {
    const char *caller_id;
    const uint8_t *app_data;
    size_t app_data_sz;
} ziti_client_ctx;


typedef struct ziti_listen_opts_s {
    uint16_t terminator_cost;
    uint8_t terminator_precedence;
    int connect_timeout_seconds;
    int max_connections;
    char *identity;
    bool bind_using_edge_identity;
} ziti_listen_opts;

/**
 * @brief Data callback.
 *
 * This callback is invoked when data arrives at the Ziti C SDK. Data arrives in the Ziti C SDK
 * either as a response to a Ziti connection from an ziti_dial() or as an incoming request via
 * ziti_accept.
 * Return value should indicate how much data was consumed by the application. This callback will
 * be called again at some later time and as many times as needed for application to accept the rest.
 *
 * @param conn The Ziti connection which received the data
 * @param data incoming data buffer
 * @param length size of data or error code as defined in #ZITI_ERRORS (will receive #ZITI_EOF
 *               when connection is closed)
 *
 * @return indicate how much data was consumed
 * @see ziti_dial(), ziti_accept(), ZITI_ERRORS
 */
typedef ssize_t (*ziti_data_cb)(ziti_connection conn, const uint8_t *data, ssize_t length);

/**
 * @brief Connection callback.
 * 
 * This callback is invoked after ziti_dial() or ziti_accept() is completed.  The result of the
 * function may be an error condition so it is important to verify the status code in this callback.
 * If successful the status will be set to #ZITI_OK.
 *
 * @param conn the Ziti connection struct
 * @param status the result of the function. #ZITI_OK if successful otherwise see #ZITI_ERRORS
 *
 * @see ziti_dial(), ziti_accept(), ZITI_ERRORS
 */
typedef void (*ziti_conn_cb)(ziti_connection conn, int status);

/**
 * @brief Callback called when client connects to a service hosted by given context
 *
 * This callback is invoked after ziti_listen() is completed. The result of the function may be an
 * error condition so it is important to verify the status code in this callback. If successful
 * the status will be set to #ZITI_OK otherwise the value will be a value defined in #ZITI_ERRORS
 *
 * Generally this callback is used for any preparations necessary before accepting incoming data
 * from the Ziti network.
 *
 * @param serv hosting connection, initialized with ziti_listen()
 * @param client client connection - generally passed to ziti_accept() in this function
 * @param status #ZITI_OK or error
 * @param ctx object containing application data passed by dialing identity, \see ziti_dial_opts.
 *            the reference to this object is only valid for the duration of the callback.
 *
 * @see ziti_listen(), ZITI_ERRORS
 */
typedef void (*ziti_client_cb)(ziti_connection serv, ziti_connection client, int status, const ziti_client_ctx *ctx);

/**
 * @brief Defines the ziti_listen_cb.
 * 
 * A convenience to make the API align better when a human looks at it and as a place to change the listen
 * callback in the unlikely event it is needed.
 *
 * @see ziti_listen()
 */
typedef ziti_conn_cb ziti_listen_cb;

/**
 * @brief Callback called after ziti_write() is complete.
 *
 * This callback is triggered on the completion of ziti_write(). The result of the ziti_write() function may be
 * an error condition so it is important to verify the provided status code in this callback.
 *
 * This callback is often used to free or reinitialize the buffer associated with the ziti_write() invocation.
 * It is important to not free this memory until after data has been written to the wire else the results of
 * the write operation may be unexpected.
 *
 * @see ziti_write(), ZITI_ERRORS
 */
typedef void (*ziti_write_cb)(ziti_connection conn, ssize_t status, void *write_ctx);



/**
 * @brief Callback called after connection was closed.
 *
 * @param conn connection that was closed
 *
 * @see ziti_close()
 */
typedef void (*ziti_close_cb)(ziti_connection conn);

/**
 * @brief Initializes a connection.
 *
 * This function takes an uninitialized #ziti_connection and prepares it to be used in the Ziti C SDK
 * and allows for additional context to be carried forward.
 *
 * @param ztx the Ziti Edge identity context to initialize the connection with
 * @param conn an uninitialized #ziti_connection to be initialized
 * @param data additional context to carry forward in ziti_dial() and ziti_listen() related callbacks
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_dial(), ziti_listen(), ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_conn_init(ziti_context ztx, ziti_connection *conn, void *data);

/**
 * @brief Return Ziti context for given connection.
 *
 * @param conn ziti connection
 * @return ziti context connection belongs to
 */
ZITI_FUNC
extern ziti_context ziti_conn_context(ziti_connection conn);

/**
 * @brief Retrieves any custom data associated with the given #ziti_connection.
 * 
 * This function returns the custom data associated to the #ziti_connection supplied
 * in the ziti_conn_init() function.
 *
 * @param conn the #ziti_connection to retrieve the context from
 *
 * @return custom data passed into ziti_conn_init()
 */
ZITI_FUNC
extern void *ziti_conn_data(ziti_connection conn);

/**
 * @brief Set or clear custom data associated with the given #ziti_connection.
 *
 * This function associates the custom data to the #ziti_connection. Pass NULL to clear associated data.
 *
 * @param conn the #ziti_connection to set the context to
 * @param data custom data
 *
 * @see ziti_conn_data(), ziti_conn_init()
 */
ZITI_FUNC
extern void ziti_conn_set_data(ziti_connection conn, void *data);

/**
 * @brief Set new data callback on ziti connection.
 * This allows application to defer setting callback until connection is established (inside [ziti_conn_cb]),
 * or change processing at any time.
 *
 * @param conn
 * @param cb
 * @return ZITI_OK or error code
 */
ZITI_FUNC
extern int ziti_conn_set_data_cb(ziti_connection conn, ziti_data_cb cb);

/**
 * @brief Get the identity of the client that initiated the #ziti_connection.
 *
 * @return identity of the client that requested the connection.
 */
ZITI_FUNC
extern const char *ziti_conn_source_identity(ziti_connection conn);

/**
 * @brief Get network circuit ID.
 *
 * @param conn
 * @return overlay circuit ID for a given connection,
 *         blank for unconnected or server connection
 *         NULL if conn is NULL
 */
ZITI_FUNC
extern const char *ziti_conn_circuit_id(ziti_connection conn);

/**
 * @brief returns ziti_service and fills in ziti_dial_opts based on intercepted and source addresses.
 * This could be used to call ziti_dial_with_options().
 * Populated ziti_dial_opts should be freed with ziti_dial_opts_free().
 *
 * @code
 * ziti_connection conn;
 * ziti_conn_init(ztx, &conn, NULL);
 * ziti_dial_opts opts = {0};
 * const ziti_service *s = ziti_dial_opts_for_addr(&opts, ztx, proto, dest_host, dest_port, src_host, src_port);
 * if (s) {
 *     ziti_dial_with_options(conn, s->name, &opts, cb, data_cb);
 *     ziti_dial_opts_free(&opts);
 * } else {
 *    // handle error
 * }
 * @endcode
 *
 * @param opts structure to be filled with dial information
 * @param ztx
 * @param proto
 * @param dest_host
 * @param dest_port
 * @param src_host
 * @param src_port
 * @return the service that intercepts the destination address, or NULL if no service matches it
 *         or the matching service has no intercept config
 */
ZITI_FUNC
extern const ziti_service* ziti_dial_opts_for_addr(ziti_dial_opts *opts, ziti_context ztx, ziti_protocol proto,
                                                   const char *dest_host, int dest_port,
                                                   const char *src_host, int src_port);

/**
 * @brief Free the memory associated with the ziti_dial_opts struct.
 *
 * @param opts the ziti_dial_opts struct to free
 */
ZITI_FUNC
extern void ziti_dial_opts_free(ziti_dial_opts *opts);
/**
 * @brief Establishes connection to a Ziti service.
 *
 * Before any bytes can be sent over the Ziti Network a #ziti_connection must be dialed to a service. This
 * function will attempt to dial the service with the given name. The result of the service dial will be
 * called back using the provided #ziti_conn_cb.
 *
 * If the dial succeeds the provided #ziti_data_cb is used to handle bytes returned from the service. If the
 * dial fails only the #ziti_conn_cb will be invoked with the corresponding #ZITI_ERRORS code.
 *
 * @param conn the #ziti_connection to use in the dial operation
 * @param service the name of the service to dial
 * @param cb invoked after the dial operation completes
 * @param data_cb invoked if the dial operation succeeds with data received over the connection
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_dial(), ziti_write()
 */
ZITI_FUNC
extern int ziti_dial(ziti_connection conn, const char *service, ziti_conn_cb cb, ziti_data_cb data_cb);

ZITI_FUNC
extern int ziti_dial_with_options(ziti_connection conn, const char *service,
                                  const ziti_dial_opts *dial_opts,
                                  ziti_conn_cb cb, ziti_data_cb data_cb);

/**
 * @brief Start accepting ziti client connections.
 *
 * This function is invoked to tell the Ziti SDK to accept connections from other Ziti clients for the
 * provided service name. The identity configured in the Ziti C SDK will need to be configured to host
 * the service via the Ziti Controller.
 *
 * When this function completes the #ziti_listen_cb callback will be invoked. This callback is what will
 * verify the success or failure of the listen operation.
 *
 * Once successfully listening the #ziti_client_cb will be invoked when a Ziti client attempts to dial
 * this service name.
 *
 * @param serv_conn the #ziti_connection acting as a server which will be hosting the service
 * @param service the name of the service to be hosted
 * @param lcb invoked after the function completes
 * @param cb a callback invoked when when client is attempting to connect to advertised service
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_accept()
 */
ZITI_FUNC
extern int ziti_listen(ziti_connection serv_conn, const char *service, ziti_listen_cb lcb, ziti_client_cb cb);

ZITI_FUNC
extern int ziti_listen_with_options(ziti_connection serv_conn, const char *service,
                                    const ziti_listen_opts *listen_opts,
                                    ziti_listen_cb lcb, ziti_client_cb cb);

/**
 * @brief Updates the cost and/or precedence of a hosted service's terminator(s).
 *
 * Sends an update to the edge router(s) currently bound for `server`, which forwards it
 * to the controller. Typically used by a health-check implementation to steer traffic
 * away from (or back to) a terminator whose backend is failing or recovering.
 *
 * `cost` and `precedence` are independent: pass NULL for either to leave that value
 * unchanged. Passing NULL for both is a no-op. On success, the new value(s) also become
 * the baseline used for any future bind/rebind of this connection, so a value applied
 * here survives edge router reconnects.
 *
 * @param server a #ziti_connection previously passed to ziti_listen() or
 *               ziti_listen_with_options()
 * @param cost new terminator cost, or NULL to leave unchanged
 * @param precedence new terminator precedence (see #ziti_terminator_precedence_s), or
 *                   NULL to leave unchanged
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_listen(), ziti_listen_with_options(), ziti_send_health_event()
 */
ZITI_FUNC
extern int ziti_update_terminator(ziti_connection server, const uint16_t *cost, const uint8_t *precedence);

/**
 * @brief Reports a health-check pass/fail result for a hosted service.
 *
 * Unlike ziti_update_terminator(), this does not change cost or precedence on its own —
 * it forwards a health event for the controller/observability stack. Call
 * ziti_update_terminator() separately if the check result should also change routing.
 *
 * @param server a #ziti_connection previously passed to ziti_listen() or
 *               ziti_listen_with_options()
 * @param pass true if the health check passed, false if it failed
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_update_terminator()
 */
ZITI_FUNC
extern int ziti_send_health_event(ziti_connection server, bool pass);

/**
 * @brief Completes client connection.
 *
 * After a client connects to a hosted Ziti service this function is invoked to finish the connection
 * establishment.  This function will establish the callbacks necessary to send data to the connecting
 * client or to process data sent by the client.
 *
 * After this function completes the #ziti_conn_cb callback is invoked. The callback will contain the
 * status of the function call as well so it's important to verify the status.
 *
 * Data sent by the client is processed in the #ziti_data_cb callback. Every invocation of the callback
 * could indicate an error or that the connection is no longer usable so it is important to check the
 * status of the function each time it is invoked.
 *
 * @param clt a #ziti_connection representing the incoming client connection
 * @param cb a callback invoked when the function completes
 * @param data_cb a callback invoked each time the client sends data
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_listen()
 */
ZITI_FUNC
extern int ziti_accept(ziti_connection clt, ziti_conn_cb cb, ziti_data_cb data_cb);

/**
 * @brief Closes the given connection.
 *
 * When no longer needed a [connection](#ziti_connection) should be closed to gracefully disconnect. This
 * function should be invoked after any status is returned which indicates an error situation.
 *
 * This method initiates the disconnect(if needed) and the release all associated resources.
 * After close_cb() is called, the ziti_connection handle is no longer valid.
 *
 * @param conn the #ziti_connection to be closed
 * @param close_cb callback called after connection is closed
 *
 * @return #ZITI_OK
 *         #ZITI_CONN_CLOSED if connection was already ziti_close() was already called on the given connection
 *         other #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_close(ziti_connection conn, ziti_close_cb close_cb);

/**
 * @brief Closes the outgoing (write) side of the given ziti connection.
 *
 * Any pending write requests will be able to complete. The `conn` should refer to a initialized ziti connection.
 *
 * This notifies peer ziti connection that no more data will be sent -- peer receives EOF.
 * Any further calls to `ziti_write()` will return an error.
 *
 * This leaves incoming(read) side of ziti connection open.
 *
 * @note this is roughly equivalent to calling `uv_shutdown()` on a duplex `uv_stream`, or
 *       `shutdown(sock, SHUT_WR)` on socket fd.
 *
 * @param conn the #ziti_connection to be closed
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_close_write(ziti_connection conn);

/**
 * @brief Send data to the connection peer.
 *
 * This function is invoked to send data from the Ziti C SDK to the peer on the other side of the Ziti connection. It is
 * used to send data over the given connection and to establish the callback invoked after the data is sent. It is
 * important to not free the buffer until the #ziti_write_cb callback is invoked. It is *only* safe to free the buffer in
 * the write callback.
 *
 * @param conn the #ziti_connection used to write data to
 * @param data a buffer of data to write over the provided #ziti_connection
 * @param length the length of data in the data buffer to send. Make sure to not specify 
 * @param write_cb a callback invoked after the function completes indicating the buffer can now be reclaimed
 * @param write_ctx additional context to be passed to the #ziti_write_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_write(ziti_connection conn, const uint8_t *data, size_t length, ziti_write_cb write_cb, void *write_ctx);

/**
 * @brief Bridge [ziti_connection] to a given IO stream
 *
 * This sets up the connection bridge: all bytes read from ziti_connection are forwarded to the IO stream, and vice a versa.
 * Both ziti_connection and stream have to be established prior to this call.
 *
 * [on_close] is called after the bridge is terminated and ziti_connection was closed.
 *
 * @param conn
 * @param handle IO handle, must be a stream (UV_TCP, UV_PIPE, UV_TTY) or a UV_UDP handle
 * @param on_close
 * @return 0 on success, error code on failure
 */
ZITI_FUNC
extern int ziti_conn_bridge(ziti_connection conn, uv_handle_t *handle, uv_close_cb on_close);

/**
 * set idle timeout on bridged connection.
 * @param conn ziti_connection previously bridged with [ziti_conn_bridge] or [ziti_conn_bridge_fds]
 * @param millis timeout after which bridge will be closed absent any traffic
 * @return 0 on success, error code on failure
 */
ZITI_FUNC
extern int ziti_conn_bridge_idle_timeout(ziti_connection conn, unsigned long millis);

/**
 * @brief Bridge [ziti_connection] to given IO file descriptors.
 *
 * All bytes read from ziti_connection are written to output fd, all bytes read from input fd are sent to ziti_connection.
 *
 * @param conn
 * @param input
 * @param output
 * @param close_cb
 * @param ctx
 * @return
 */
ZITI_FUNC
extern int ziti_conn_bridge_fds(ziti_connection conn, uv_os_sock_t input, uv_os_sock_t output, void (*close_cb)(void *ctx), void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_CONNECTION_H */
