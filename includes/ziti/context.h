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
 * @file context.h
 * @brief Ziti identity context: options, lifecycle, controller and identity info, and service queries.
 */

#ifndef ZITI_CONTEXT_H
#define ZITI_CONTEXT_H

#include <stdbool.h>
#include <uv.h>

#include "enums.h"
#include "externs.h"
#include "handles.h"
#include "posture.h"
#include "ziti_events.h"
#include "ziti_model.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Service status callback.
 *
 * This callback is invoked on the conclusion of ziti_service_available(). The result of the function
 * may be an error condition so it is important to verify the status code in this callback. In the
 * event the service does not exist or the identity has not been given the access to the service the
 * #ZITI_SERVICE_UNAVAILABLE error code will be returned otherwise #ZITI_OK is expected.
 *
 * @see ziti_service_available(), ZITI_ERRORS
 */
typedef void (*ziti_service_cb)(ziti_context ztx, const ziti_service *, int status, void *data);

/**
 * @brief callback providing the list of terminators
 *
 * Data is an NULL-terminated array of ziti_terminator pointers.
 * The application must copy desired data as the terminator array is freed after the callback
 *
 * @see ziti_list_terminators
 * @param ztx the handle to the Ziti Edge identity context
 * @param terminators the NULL-terminated array of [ziti_terminator] pointers
 * @param status the status of the operation
 * @param ctx application context
 */
typedef void (*ziti_terminator_cb)(ziti_context ztx, const ziti_terminator* const * terminators , int status, void *ctx);

/**
 * @brief Ziti Event callback.
 *
 * This callback is invoked when certain changes happen for a given ziti context.
 * Subscription to events is managed by setting desired types on `ziti_options.events` field.
 *
 * @see ziti_event_type
 * @see ziti_event_t
 * @see ziti_options.event_cb
 * @see ziti_options.events
 */
typedef void (*ziti_event_cb)(ziti_context ztx, const ziti_event_t *event);

/**
 * @brief ziti_context runtime options
 *
 * @see ziti_context_set_options()
 */
typedef struct ziti_options_s {
    bool disabled; // if true initial state will be disabled
    const char **config_types;
    ziti_crypto_method e2ee_mode;

    unsigned int api_page_size;
    long refresh_interval; //the duration in seconds between checking for updates from the controller
    rate_type metrics_type; //an enum describing the metrics to collect

    //posture query cbs
    ziti_pq_mac_cb pq_mac_cb;
    ziti_pq_os_cb pq_os_cb;
    ziti_pq_process_cb pq_process_cb;
    ziti_pq_domain_cb pq_domain_cb;

    void *app_ctx;

    /**
     * \brief subscribed event types.
     */
    unsigned int events;

    /**
     * \brief callback invoked is response to subscribed events.
     */
    ziti_event_cb event_cb;

    /**
     * \brief this setting allows SDK to auto-extend identity certificate.
     *
     * This only applies if certificate was issued by the OpenZiti network.
     * The application must handle [ZitiConfigEvent] to capture and save
     * the newly issued certificate.
     * SDK will extend certificate when expiration date falls
     * in the next [cert_extension_window] days.
     * To enable certificate extension the value must be greater than 0
     */
    unsigned int cert_extension_window;

    /**
     * \brief enrollment mode for just-in-time identity creation.
     *
     * Controls behavior when authenticating via an external JWT signer
     * and no identity credentials exist yet.
     * - ziti_enroll_none (0, default): no enrollment, identity pre-created by admin
     * - ziti_enroll_cert: generate CSR, exchange for client certificate
     * - ziti_enroll_token: auto-create identity, authenticate via external JWT
     */
    ziti_enroll_mode enroll_mode;
} ziti_options;

/**
 * Provide app information to Ziti SDK.
 *
 * App information is reported to Ziti Controller. Supplying this information is optional.
 */
ZITI_FUNC
extern void ziti_set_app_info(const char *app_id, const char *app_version);

/**
 * Provide device id to Ziti SDK.
 *
 * App information is reported to Ziti Controller. Supplying this information is optional.
 */
ZITI_FUNC
extern void ziti_set_device_id(const char *device_id);

/**
 * Override the hostname reported to the Ziti Controller in envInfo.
 *
 * On platforms where uv_os_gethostname() returns an unhelpful value (e.g. iOS
 * apps that always see "localhost"), the application can supply a more
 * meaningful name (such as UIDevice.current.name on iOS).
 *
 * Pass NULL or an empty string to revert to the value detected by the SDK.
 */
ZITI_FUNC
extern void ziti_set_hostname(const char *hostname);

/**
 * Load ziti identity config from memory or file.
 * First it tries to parse [conf_str] as identity Json.
 * if that fails it tries to load it from file using [conf_str] as the path.
 * @param config target ziti_config object
 * @param conf_str identity config JSON or path to a file.
 * @return ZITI_OK on success or error code
 */
ZITI_FUNC
extern int ziti_load_config(ziti_config *config, const char* conf_str);

ZITI_FUNC
extern int ziti_context_init(ziti_context *ztx, const ziti_config *config);

ZITI_FUNC
extern int ziti_context_set_options(ziti_context ztx, const ziti_options *options);

ZITI_FUNC
extern int ziti_context_run(ziti_context ztx, uv_loop_t *loop);

/**
 * \brief Trigger refresh ahead of normal refresh cycle.
 *
 * This method will force ziti context to update its internal model from ziti controller.
 * Appropriate events will be triggered as needed
 * (just like during normal refresh cycle [#ziti_options.refresh_interval]):
 * - Service Added/Removed, etc.
 *
 * The context has to be fully authenticated: the refresh goes to the controller with the API session.
 * @param ztx
 * @return #ZITI_OK on success, #ZITI_DISABLED if the context is disabled,
 * #ZITI_INVALID_STATE if it is not fully authenticated (yet or any more), or other error code
 */
ZITI_FUNC
extern int ziti_refresh(ziti_context ztx);

/**
 * return if context is enabled
 * @param ztx ziti context
 * @return
 */
ZITI_FUNC
extern bool ziti_is_enabled(ziti_context ztx);

/**
 * Enable or disable given Ziti context.
 * @param ztx
 * @param enabled
 */
ZITI_FUNC
extern void ziti_set_enabled(ziti_context ztx, bool enabled);

/**
 * @brief returns ziti_options.app_ctx for the given Ziti context.
 *
 * @param ztx
 * @return application context that was passed as ziti_options.app_ctx
 */
ZITI_FUNC
extern void *ziti_app_ctx(ziti_context ztx);

ZITI_FUNC
extern void ziti_set_app_ctx(ziti_context ztx, void *app_ctx);

/**
 * @brief return SDK version
 * @return SDK version
 */
ZITI_FUNC
extern const ziti_version *ziti_get_version();

/**
 * @brief return Ziti controller version for given context
 * @param ztx ziti context
 * @return controller version
 */
ZITI_FUNC
extern const ziti_version *ziti_get_controller_version(ziti_context ztx);

/**
 * @brief controller URL of the given context
 * @param ztx ziti context
 * @return controller URL
 */
ZITI_FUNC
extern const char *ziti_get_controller(ziti_context ztx);

/**
 * @brief Ziti identity of the given context.
 * @param ztx ziti context
 * @return ziti identity
 */
ZITI_FUNC
extern const ziti_identity *ziti_get_identity(ziti_context ztx);

/**
 * @brief Retrieve current transfer rates. Rates are in bytes/second.
 *
 * Calculation is using 1 minute EWMA.
 * @param ztx ziti context
 * @param up rate of bytes going up
 * @param down rate of bytes going down
 * @return ZITI_OK or error code
 */
ZITI_FUNC
extern int ziti_get_transfer_rates(ziti_context ztx, double *up, double *down);

/**
 * @brief Shutdown Ziti Edge identity context and reclaim the memory from the provided #ziti_context.
 * 
 * @param ztx the Ziti Edge identity context to be shut down. this reference is not safe to use after this call
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_shutdown(ziti_context ztx);

/**
 * @brief Write a human-readable snapshot of the identity context state.
 *
 * Dumps SDK/dependency versions, environment info, controller and authentication state,
 * known services with their posture queries, sessions, and edge router channels.
 * The output is intended for troubleshooting and is useful to attach when submitting issues.
 *
 * The dump is produced by repeated calls to `printer`, which must accept a `printf()`-like
 * format string and arguments, with @p ctx passed as its first argument. This makes it directly
 * compatible with `fprintf()`:
 * \code
 *     ziti_dump(ztx, (int (*)(void *, const char *, ...)) fprintf, stderr);
 * \endcode
 *
 * @note Must be called on the thread running the #ziti_context loop — e.g. from within an SDK
 *       callback or a `uv_async_t` handler. It walks live context state without locking.
 * @note The format is not stable and must not be parsed programmatically.
 * @warning The output contains identity details, the identity certificate, and decoded token
 *          claims. Review it before sharing publicly.
 *
 * @param ztx the Ziti Edge identity context to print debug information for
 * @param printer function to be called for output
 * @param ctx first argument passed into the `printer` function
*/
ZITI_FUNC
extern void ziti_dump(ziti_context ztx, int (*printer)(void *ctx, const char *fmt, ...), void *ctx);

ZITI_FUNC
const char *ziti_get_appdata_raw(ziti_context ztx, const char *key);

ZITI_FUNC
int ziti_get_appdata(ziti_context ztx, const char *key, void *data,
                     int (*parse_func)(void *, const char *, size_t));

/**
 * @brief Checks availability of the service for the given edge context.
 *
 * Checks to see if a given #ziti_context has a service available by the name supplied. The supplied name
 * is case sensitive. This function is not synchronous - the #ziti_service_cb specified is invoked at the
 * end of the function invocation with the result.
 *
 * @param ztx the Ziti Edge identity context to use to check for the service's availability on
 * @param service the name of the service to check
 * @param cb callback called with #ZITI_OK or #ZITI_SERVICE_UNAVAILABLE
 * @param ctx additional context to be passed to the #ziti_service_cb
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_service_available(ziti_context ztx, const char *service, ziti_service_cb cb, void *ctx);

/**
 * @brief List all terminators for the given service.
 * Application must copy desired data passed into the callback.
 *
 * @param ztx ziti identity context
 * @param service name of the service
 * @param cb callback called with the list of terminators
 * @param ctx application context
 * @return ZITI_OK or error code
 */
ZITI_FUNC
extern int ziti_list_terminators(ziti_context ztx, const char *service, ziti_terminator_cb cb, void *ctx);

ZITI_FUNC
extern const ziti_service *ziti_service_for_addr_str(ziti_context ztx, ziti_protocol proto, const char *addr, int port);

ZITI_FUNC
extern const ziti_service *ziti_service_for_addr(ziti_context ztx, ziti_protocol proto, const ziti_address *addr, int port);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_CONTEXT_H */
