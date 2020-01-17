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
 * @brief Defines the macros, functions, typedefs and constants required to interface with a Ziti Network
 */

#ifndef NF_ZT_H
#define NF_ZT_H

#include <stdint.h>
#include <uv.h>
#include <uv_mbed/tls_engine.h>
#include "errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The default timeout in milliseconds for connections and write operations to succeed.
 */
#define NF_DEFAULT_TIMEOUT 5000

/**
 * @brief Represents the Ziti Edge identity context.
 *
 * The Ziti C SDK will use this pointer to initialize and track the memory needed during
 * normal usage. This structure is opaque to the API user but is necessary for normal Ziti
 * SDK operation. After a successful initialization via NF_init() the pointer will be
 * initialized. The context is necessary for many of the C SDK functions and is passed
 * as a parameter in many of the callbacks. NF_shutdown() should be invoked when the Ziti
 * connections are no longer needed. The Ziti C SDK will reclaim any allocated memory at this
 * time.
 *
 * @see NF_init(), NF_shutdown()
 */
typedef struct nf_ctx *nf_context;

/**
 * @brief Represents a Ziti connection.
 *
 * The heart of Ziti is around reading and writing data securely and efficiently. In order
 * to do that a connection is required which will allow a developer to do so. This pointer
 * is passed to numerous Ziti C SDK functions and is returned in many callbacks. This structure
 * is an opaque handle to the state necessary for the Ziti C SDK to function properly.
 *
 * A connection is initialized by passing a pointer to NF_conn_init(). The connection will need
 * to be freed when no longer needed.
 *
 * @see NF_conn_init(), NF_close()
 */
typedef struct nf_conn *nf_connection;

/**
 * @brief Ziti Edge identity context init callback.
 *
 * This callback is invoked on the conclusion of the NF_init() function. The result of the
 * NF_init() function may be an error condition so it is important to verify the provided
 * status code in this callback.
 *
 * This callback also has the Ziti Edge identity context supplied. This context should be
 * stored as it is required in most Ziti C SDK function invocations and when no longer needed
 * this handle will need to be passed back to the Ziti C SDK so any resources may be freed.
 *
 * @param nf_ctx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status #ZITI_OK or an error code
 * @param init_ctx custom data passed via NF_init()
 *
 * @see NF_init(), ZITI_ERRORS
 */
typedef void (*nf_init_cb)(nf_context nf_ctx, int status, void* init_ctx);

/**
 * @brief Service status callback.
 *
 * This callback is invoked on the conclusion of NF_service_available(). The result of the function
 * may be an error condition so it is important to verify the status code in this callback. In the
 * event the service does not exist or the identity has not been given the access to the service the
 * #ZITI_SERVICE_UNAVAILABLE error code will be returned otherwise #ZITI_OK is expected.
 *
 * @see NF_service_available(), ZITI_ERRORS
 */
typedef void (*nf_service_cb)(nf_context nf_ctx, const char* service_name, int status, void *data);

/**
 * @brief Data callback.
 *
 * This callback is invoked when data arrives at the Ziti C SDK. Data arrives in the Ziti C SDK
 * either as a response to a Ziti connection from an NF_dial() or as an incoming request via
 * NF_accept.
 *
 * @param conn The Ziti connection which received the data
 * @param data incoming data buffer
 * @param length size of data or error code as defined in #ZITI_ERRORS (will receive #ZITI_EOF
 *               when connection is closed)
 *
 * @see NF_dial(), NF_accept(), ZITI_ERRORS
 */
typedef void (*nf_data_cb)(nf_connection conn, uint8_t *data, int length);

/**
 * @brief Connection callback.
 * 
 * This callback is invoked after NF_dial() or NF_accept() is completed.  The result of the
 * function may be an error condition so it is important to verify the status code in this callback.
 * If successful the status will be set to #ZITI_OK.
 *
 * @param conn the Ziti connection struct
 * @param status the result of the function. #ZITI_OK if successful otherwise see #ZITI_ERRORS
 *
 * @see NF_dial(), NF_accept(), ZITI_ERRORS
 */
typedef void (*nf_conn_cb)(nf_connection conn, int status);

/**
 * @brief Callback called when client connects to a service hosted by given context
 *
 * This callback is invoked after NF_listen() is completed. The result of the function may be an
 * error condition so it is important to verify the status code in this callback. If successful
 * the status will be set to #ZITI_OK otherwise the value will be a value defined in #ZITI_ERRORS
 *
 * Generally this callback is used for any preparations necessary before accepting incoming data
 * from the Ziti network.
 *
 * @param serv hosting connection, initialized with NF_listen()
 * @param client client connection - generally passed to NF_accept() in this function
 * @param status #ZITI_OK or error
 *
 * @see NF_listen(), ZITI_ERRORS
 */
typedef void (*nf_client_cb)(nf_connection serv, nf_connection client, int status);

/**
 * @brief Defines the nf_listen_cb
 * 
 * A convenience to make the API align better when a human looks at it and as a place to change the listen
 * callback in the unlikely event it is needed.
 *
 * @see NF_listen()
 */
typedef nf_conn_cb nf_listen_cb;

/**
 * @brief Callback called after NF_write() is complete.
 *
 * This callback is triggered on the completion of NF_write(). The result of the NF_write() function may be
 * an error condition so it is important to verify the provided status code in this callback.
 *
 * This callback is often used to free or reinitialize the buffer associated with the NF_write() invocation.
 * It is important to not free this memory until after data has been written to the wire else the results of
 * the write operation may be unexpected.
 *
 * @see NF_write(), ZITI_ERRORS
 */
typedef void (*nf_write_cb)(nf_connection conn, ssize_t status, void *write_ctx);

/**
 * @brief Initializes a Ziti Edge identity.
 * 
 * This function is used to initialize a Ziti Edge identity. The Ziti C SDK is based around the [libuv](http://libuv.org/)
 * library and is maintains similar semantics.  This function is used to setup the chain of callbacks
 * needed once the loop begins to execute.
 *
 * This function will initialize the Ziti C SDK using the default TLS engine [mbed](https://tls.mbed.org/). If a
 * different TLS engine is desired use NF_init_with_tls().
 *
 * @param config location of identity configuration
 * @param loop libuv event loop
 * @param init_cb callback to be called when initialization is complete
 * @param init_ctx custom data to be passed into init_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see NF_init_with_tls()
 */
extern int NF_init(const char* config, uv_loop_t* loop, nf_init_cb init_cb, void* init_ctx);

/**
 * @brief Initialize Ziti Edge identity context with the provided TLS context.
 *
 * This function is very similar to NF_init() with the exception that it allows the tls_context to be
 * specified. This allows for a TLS implementation other than the included mbed.
 *
 * @param ctrl_url the url of the Ziti Controller
 * @param tls_context the context to use when establishing new TLS connections
 * @param loop libuv event loop
 * @param init_cb callback to be called when initialization is complete
 * @param init_ctx custom data to be passed into callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see NF_init()
 */
extern int
NF_init_with_tls(const char* ctrl_url, tls_context* tls_context, uv_loop_t* loop, nf_init_cb init_cb, void* init_ctx);

/**
 * @brief Sets connect and write timeouts(in millis).
 *
 * The #NF_DEFAULT_TIMEOUT is used if this function is not invoked prior to initializing connections. This value is only
 * referenced when initializing new connections via NF_conn_init(). Any connection initialized before this function will
 * have the whatever timeout was set at the time of initialization.
 *
 * Note: There is no check to verify the timeout specified is not "too small". Setting this value to a very small value
 * may lead to a large number of timeouts.
 * 
 * @param nf_ctx the Ziti Edge identity context to set a timeout on
 * @param timeout the value in milliseconds of the timeout (must be > 0)
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_set_timeout(nf_context nf_ctx, int timeout);

/**
 * @brief Shutdown Ziti Edge identity context and reclaim the memory from the provided #nf_context
 * 
 * @param nf_ctx the Ziti Edge identity context to be shut down
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_shutdown(nf_context nf_ctx);

/**
 * @brief Shutdown Ziti Edge identity context and reclaim the memory from the provided #nf_context
 *
 * This function will output debugging information to standard out. The output from this command may
 * be useful when submitting issues.
 *
 * @param nf_ctx the Ziti Edge identity context to print debug information for
*/
extern void NF_dump(nf_context nf_ctx);

/**
 * @brief Initializes a connection.
 *
 * This function takes an uninitialized #nf_connection and prepares it to be used in the Ziti C SDK
 * and allows for additional context to be carried forward.
 *
 * @param nf_ctx the Ziti Edge identity context to initialize the connection with
 * @param conn an uninitialized #nf_connection to be initialized
 * @param data additional context to carry forward in NF_dial() and NF_listen() related callbacks
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see NF_dial(), NF_listen(), ZITI_ERRORS
 */
extern int NF_conn_init(nf_context nf_ctx, nf_connection *conn, void *data);

/**
 * @brief Retrieves any custom data associated with the given #nf_connection
 * 
 * This function returns the custom data associated to the #nf_connection supplied
 * in the NF_conn_init() function.
 *
 * @param conn the #nf_connection to retrieve the context from
 *
 * @return custom data passed into NF_conn_init()
 */
extern void *NF_conn_data(nf_connection conn);

/**
 * @brief Checks availability of the service for the given edge context.
 *
 * Checks to see if a given #nf_context has a service available by the name supplied. The supplied name
 * is case sensitive.
 *
 * @param nf_ctx the Ziti Edge identity context to use to check for the service's availability on
 * @param service the name of the service to check
 * @param cb callback called with #ZITI_OK or #ZITI_SERVICE_NOT_AVAILABLE
 * @param ctx custom data passed to the #nf_service_cb
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_service_available(nf_context nf_ctx, const char *service, nf_service_cb cb, void *ctx);

/**
 * @brief Establishes connection to a Ziti service.
 *
 * @param conn connection object
 * @param service service name
 * @param cb
 * @param data_cb
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_dial(nf_connection conn, const char *service, nf_conn_cb cb, nf_data_cb data_cb);

/**
 * @brief Start accepting ziti client connections.
 *
 * @param serv_conn
 * @param service service name
 * @param lcb listen callback
 * @param cb client callback, called when client is attempting to connect to advertised service.
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_listen(nf_connection serv_conn, const char *service, nf_listen_cb lcb, nf_client_cb cb);

/**
 * @brief Completes client connection.
 *
 * @param clt client connection
 * @param cb connection callback
 * @param data_cb data callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_accept(nf_connection clt, nf_conn_cb cb, nf_data_cb data_cb);

/**
 * @brief Close connection.
 *
 * @param conn
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_close(nf_connection *conn);

/**
 * @brief Send data to the connection peer.
 *
 * data buffer passed into this function should be intact until callback is called. It is only safe to free the buffer in
 * the write callback.
 * @param conn
 * @param data
 * @param length
 * @param write_cb
 * @param write_ctx
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int NF_write(nf_connection conn, uint8_t *data, size_t length, nf_write_cb write_cb, void *write_ctx);
// ReSharper enable CppInconsistentNaming

#ifdef __cplusplus
}
#endif

#endif /* NF_ZT_H */
