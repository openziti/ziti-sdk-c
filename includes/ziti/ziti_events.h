// Copyright (c) 2020-2023.  NetFoundry Inc.
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


#ifndef ZITI_SDK_ZITI_EVENTS_H
#define ZITI_SDK_ZITI_EVENTS_H

#include "ziti_model.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief Ziti Event Types.
 *
 * \see ziti_event_t
 * \see ziti_options.events
 */
typedef enum {
    ZitiContextEvent = 1,
    ZitiRouterEvent = 1 << 1,
    ZitiServiceEvent = 1 << 2,
    ZitiAuthEvent = 1 << 3,
    ZitiConfigEvent = 1 << 4,
} ziti_event_type;

/**
 * \brief Ziti Edge Router status.
 *
 * \see ziti_router_event
 */
typedef enum {
    EdgeRouterAdded,
    EdgeRouterConnected,
    EdgeRouterDisconnected,
    EdgeRouterRemoved,
    EdgeRouterUnavailable,
} ziti_router_status;

/**
 * \brief Context event.
 *
 * Informational event to notify app about issues communicating with Ziti controller.
 */
struct ziti_context_event {
    int ctrl_status;
    const char *err;
    size_t ctrl_count;
    struct ctrl_detail_s *ctrl_details;
};

struct ctrl_detail_s {
    const char *id;
    const char *url;
    bool online;
    bool active;
};

struct ziti_config_event {
    const char *identity_name;
    const ziti_config *config;
};
/**
 * \brief Edge Router Event.
 *
 * Informational event to notify app about status of edge router connections.
 */
struct ziti_router_event {
    ziti_router_status status;
    const char *name;
    const char *address;
    const char *version;
};

/**
 * \brief Ziti Service Status event.
 *
 * Event notifying app about service access changes.
 * Each field is a NULL-terminated array of `ziti_service*`.
 *
 * \see ziti_service
 */
struct ziti_service_event {

    /** Services no longer available in the Ziti Context */
    ziti_service_array removed;

    /** Modified services -- name, permissions, configs, etc */
    ziti_service_array changed;

    /** Newly available services in the Ziti Context */
    ziti_service_array added;
};

enum ziti_auth_action {
    ziti_auth_cannot_continue,
    ziti_auth_prompt_totp,
    ziti_auth_prompt_pin,
    ziti_auth_select_external,
    ziti_auth_login_external
};
/**
 * \brief Event notifying the app that additional action is required to continue authentication or normal operation.
 *
 * The app may request that information from the user and then submit it
 * to ziti_context.
 *
 * the following authentication actions are supported:
 *
 * [ziti_auth_prompt_totp] - request for MFA code, application must call [ziti_mfa_auth()] when it acquires TOTP code
 *
 * [ziti_auth_login_external] - request for that app to launch external program (web browser)
 *                 that can authenticate with provided url ([detail] field)
 *
 * TODO: future
 * [ziti_auth_prompt_pin] - request for HSM/TPM key pin, application must call [TBD method] when it acquires PIN
 */
struct ziti_auth_event {
    enum ziti_auth_action action;
    const char *type;
    const char *detail;
    ziti_jwt_signer_array providers;
};

/**
 * \brief Object passed to `ziti_options.event_cb`.
 *
 * \note event data becomes invalid as soon as callback returns.
 * App must copy data if it's needed for further processing.
 */
typedef struct ziti_event_s {
    ziti_event_type type;
    union {
        struct ziti_context_event ctx;
        struct ziti_router_event router;
        struct ziti_service_event service;
        struct ziti_auth_event auth;
        struct ziti_config_event cfg;
    };
} ziti_event_t;

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_EVENTS_H
