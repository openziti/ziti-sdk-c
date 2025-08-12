// Copyright (c) 2022.  NetFoundry Inc.
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


#ifndef ZITI_SDK_ZITILIB_H
#define ZITI_SDK_ZITILIB_H


#ifdef __cplusplus
extern "C" {
#endif

#include "externs.h"
#include "errors.h"

#include <stdint.h>

#include "ziti_model.h"

typedef uint32_t ziti_handle_t;
#define ZITI_INVALID_HANDLE ((ziti_handle_t)-1)

#if _WIN32
#include <WinSock2.h>
typedef SOCKET ziti_socket_t;
#else
#include <netinet/in.h>

typedef int ziti_socket_t;
#endif

/**
 * @brief Initialize Ziti library.
 *
 * Creates a background processing thread for Ziti processing.
 */
ZITI_FUNC
void Ziti_lib_init(void);

/**
 * @brief return Ziti error code for last failed operation.
 * Use [ziti_errorstr] to get error message.
 * @return
 */
ZITI_FUNC
int Ziti_last_error(void);

/**
 * @brief enroll a new Ziti identity
 * @param jwt enrollment token
 * @param key private key (required for third party CA enrollment, otherwise optional)
 * @param cert identity x.509 certificate (required for third party CA enrollment, otherwise ignored)
 * @param id_json (output) identity in JSON format, caller is responsible for freeing it
 * @param id_json_len (output) length of id_json
 * @return ZITI_OK on success, error code on failures
 */
ZITI_FUNC
int Ziti_enroll_identity(const char *jwt, const char *key, const char *cert,
                         char **id_json, unsigned long *id_json_len);
/**
 * @brief Load Ziti identity.
 *
 * First it tries to parse [identity] as identity Json.
 * if that fails it tries to load it from file using [identity] as the path.
 *
 * Ziti identity handle is returned to [h] on success or if additional authentication is required
 * if passed [identity] parameter is deemed invalid the handle is set to [ZITI_INVALID_HANDLE] and error code is returned.
 *
 * @param h pointer to ziti_handle_t to be initialized
 * @param identity identity config JSON or path to a file.
 * @return
 *   [ZITI_OK] success, returned handle can be used to access/bind ziti services
 *   [ZITI_EXTERNAL_LOGIN_REQUIRED] if the identity requires external login,
 *               application must call [Ziti_get_ext_signers] to get available external signers
 *               and then call [Ziti_login_external] with the selected signer name.
 *   [ZITI_PARTIALLY_AUTHENTICATED] if the identity is partially authenticated and requires additional authentication (TOTP)
 *   [ZITI_MFA_NOT_ENROLLED] if the identity is not enrolled in MFA but is required for authentication
 *   [ZITI_INVALID_STATE] if [h] is NULL
 *   [ZITI_INVALID_CONFIG] if [identity] is not a valid Ziti identity JSON
 */
ZITI_FUNC
int Ziti_load_context(ziti_handle_t *h, const char *identity);

/**
 * @brief Get external signers available for authentication.
 *
 * The result must be freed with [free_ziti_jwt_signer_array].
 * @return a dynamically allocated array of ziti_jwt_signer pointers, terminated with NULL.
 */
ZITI_FUNC
ziti_jwt_signer_array Ziti_get_ext_signers(ziti_handle_t ztx);

/**
 * @brief Start external login process.
 *
 * This method is used to start the external login process for the given Ziti context.
 * It will return a URL that the application should prompt user to open in their browser to complete the authentication.
 *
 * the returned URL must be freed with free().
 *
 * @param ztx Ziti context handle
 * @param signer_name name of the external JWT signer to use
 * @return URL to be opened in a browser, or NULL on error.
 */
ZITI_FUNC
char* Ziti_login_external(ziti_handle_t ztx, const char *signer_name);

/**
 * @brief Login with TOTP code.
 *
 * This method is used to complete the authentication process by providing a TOTP code.
 * It should be called after the user has entered their TOTP code.
 *
 * @param ztx Ziti context handle
 * @param code TOTP code provided by the user
 * @return 0 on success, error code on failure
 */
ZITI_FUNC
int Ziti_login_totp(ziti_handle_t ztx, const char *code);

/**
 * @brief Wait for authentication to complete.
 *
 * This method blocks until the authentication is completed or the timeout is reached.
 * If the authentication is successful, it returns 0, otherwise it returns a negative error code.
 *
 * @param ztx Ziti context handle
 * @param timeout_ms timeout in milliseconds, 0 means no timeout
 * @return 0 on success, negative error code on failure
 */
ZITI_FUNC
int Ziti_wait_for_auth(ziti_handle_t ztx, int timeout_ms);

/**
 * @brief creates a socket handle(Windows) or file descriptor(*nix) suitable for connecting to a Ziti service
 * @param type socket type which defines communication semantics, only SOCK_STREAM and SOCK_DGRAM are supported at this time (see socket(2))
 * @return native socket handle
 */
ZITI_FUNC
ziti_socket_t Ziti_socket(int type);

/**
 * @brief close the given socket handle/file descriptor.
 * This method facilitates faster cleanup of Ziti socket. Calling standard close()/closesocket() methods still works but may lead to
 * race conditions.
 * @param socket
 */
ZITI_FUNC
int Ziti_close(ziti_socket_t socket);

/**
 * Check if the given socket handle/fd is attached to a Ziti connection via `Ziti_connect()`/`Ziti_bind()`
 * @param socket
 * @return 0 - not a ziti socket, 1 - connected ziti socket, 2 - ziti server socket
 */
ZITI_FUNC
int Ziti_check_socket(ziti_socket_t socket);

/**
 * @brief Connect socket to a Ziti service
 * @param socket socket handle created with [Ziti_socket()]
 * @param ztx Ziti context handle
 * @param service service name provided by [ztx]
 * @param terminator (optional) specific terminator to connect to
 * @return 0 on success, negative error code on failure
 */
ZITI_FUNC
int Ziti_connect(ziti_socket_t socket, ziti_handle_t ztx, const char *service, const char *terminator);

/**
 * @brief Connect socket to a Ziti service with the given intercept address
 * @param socket socket handle created with [Ziti_socket()]
 * @param host target hostname
 * @param port target port
 * @return
 */
ZITI_FUNC
int Ziti_connect_addr(ziti_socket_t socket, const char *host, unsigned int port);

/**
 * @brief Bind socket to a Ziti service
 * @param socket socket handle created with [Ziti_socket()]
 * @param ztx Ziti context
 * @param service service name provided by [ztx]
 * @param terminator (optional) create specific terminator
 * @return 0 on success, negative error code on failure
 */
ZITI_FUNC
int Ziti_bind(ziti_socket_t socket, ziti_handle_t ztx, const char *service, const char *terminator);

/**
 * @brief marks the [socket] as a socket able to accept incoming connections
 * @param socket a file descriptor created with [Ziti_socket()] and bound to a service with [Ziti_bind] or [Ziti_bind_addr]
 * @param backlog maximum size of the queue of pending connections.
 * @return On success, 0 is returned. On error -1, is returned and [Ziti_last_error()] is set to actual code.
 */
ZITI_FUNC
int Ziti_listen(ziti_socket_t socket, int backlog);

/**
 * @brief accept a client Ziti connection as a socket
 *
 * Extracts the first [ziti_connection] from pending queue, accepts it, and opens a new socket fd for it.
 *
 * If no pending connection requests are present, behavior depends on whether [socket] is marked non-blocking.
 * - marked as non-blocking: fails with error code EAGAIN or EWOULDBLOCK.
 * - not marked as non-blocking: blocks until a connection request is present.
 *
 * @param socket socket created with [Ziti_socket()], bound to a service with [Ziti_bind()] or [Ziti_bind_addr()], and is listening after [Ziti_listen()]
 * @param caller buffer to store caller ID (dialing identity name)
 * @param caller_len length of the [caller] buffer
 * @return on success returns a file descriptor for the accepted connection. on error -1 is returned, use [Ziti_last_error()] to get actual error code.
 */
ZITI_FUNC
ziti_socket_t Ziti_accept(ziti_socket_t socket, char *caller, int caller_len);

/**
 * @brief Shutdown Ziti library.
 *
 * All loaded contexts are shutdown and background thread is terminated.
 */
ZITI_FUNC
void Ziti_lib_shutdown(void);


#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITILIB_H
