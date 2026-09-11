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
    ZitiPostureStatusEvent = 1 << 5,
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
 * \brief Payload for a PC_Process/PC_Process_Multi posture check: which of the check's
 * configured paths are currently running, per the SDK's own local detection (see
 * ziti_pr_process_cb). Not a compliance verdict -- the SDK is never given the hash or
 * signer policy actually requires, only what it observes on the running binary.
 */
struct ziti_posture_status_process_info {
    /** every path configured on the check; NULL-terminated */
    const char **paths;
    /** subset of `paths` not currently running; NULL-terminated, empty when all are */
    const char **missing_paths;
};

/**
 * \brief Posture Status event.
 *
 * Notifies the app of the SDK's own local observation of a posture check's requirements --
 * not of whether the check *passes*. Passing is a policy judgement the controller/router
 * makes, by matching submitted evidence against requirements the SDK is never given, and
 * isn't something the SDK can determine on its own; what's reported here is always a plain,
 * locally observed fact instead (see the union below for what that fact is, per check
 * type). Fired only when that local observation changes -- not on every re-check of an
 * already-steady-state result.
 *
 * A posture check is defined on a policy, and a policy can govern more than one service --
 * `services` lists every service this check currently applies to. One event is sent per
 * status change, never one per service.
 *
 * `query_type` discriminates the union below; only PC_Process/PC_Process_Multi are
 * currently implemented.
 */
struct ziti_posture_status_event {
    /** every service this check currently governs; NULL-terminated */
    ziti_service_array services;
    ziti_posture_query_type query_type;

    union {
        struct ziti_posture_status_process_info process;
    };
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
    ziti_auth_enroll_totp,
    ziti_auth_prompt_totp,
    ziti_auth_prompt_pin,
    ziti_auth_select_external,
    ziti_auth_login_external,
    ziti_auth_success,
};
/**
 * \brief Event notifying the app that additional action is required to continue authentication or normal operation.
 *
 * The app may request that information from the user and then submit it
 * to ziti_context.
 *
 * the following authentication actions are supported:
 *
 * [ziti_auth_enroll_totp] - request for MFA enrollment,
 * application must prompt user to start [ziti_mfa_enroll()/ziti_mfa_verify()] flow
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
    /** error message, if any action == ziti_auth_cannot_continue */
    const char *error;
    /** controller error code, if any (e.g. "ENROLLMENT_IDENTITY_ALREADY_ENROLLED") */
    const char *error_code;
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
        struct ziti_posture_status_event posture_status;
    };
} ziti_event_t;

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_EVENTS_H
