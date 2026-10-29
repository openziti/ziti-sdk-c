// Copyright (c) 2020-2022.  NetFoundry Inc.
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

#ifndef ZITI_SDK_POSTURE_H
#define ZITI_SDK_POSTURE_H

#include <uv.h>
#include "zt_internal.h"
#include "deadline.h"
#include "proto/edge_client.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mfa_status;

struct posture_checks {
    deadline_t deadline;
    uint64_t send_period;

    // map<type/process_path,response>
    model_map responses;

    // map<type/process_path, is errored
    model_map error_states;

    cstr previous_api_session_id;
    cstr controller_instance_id;
    bool must_send;
    bool must_send_every_time;

    model_map active_work;

    // the TOTP token the controller issued for a code (OIDC): proves to the routers that MFA passed.
    // It is scoped to one api session, which is why it is kept with that session's id
    struct {
        cstr token;
        cstr api_session_id;
        // when the code of the token was given (its iat), seconds since the epoch
        int64_t issued_at;
    } totp;

    // what the app was told of the MFA checks by the last event, NULL when it was told nothing (yet), see ztx_posture_notify_mfa()
    struct mfa_status *mfa_told;
};

void ziti_posture_init(ziti_context ztx, long interval_secs);

void ziti_posture_checks_free(struct posture_checks *pcs);

// keeps a TOTP token to be sent to the routers as a TotpToken posture response; does not send it, and does not tell the app
// (ztx_posture_notify_mfa()): the app is told once the routers have the token, ztx_posture_send_all() comes first.
// ZITI_JWT_INVALID: not a JWT with a z_asid claim, ZITI_INVALID_STATE: no posture state (endpoint disabled)
int ztx_posture_set_totp_token(ziti_context ztx, const char *token);

// sends everything that was answered so far, with the TOTP token, to every connected router (what a router that connects
// gets, see ziti_send_posture_er()); it does not ask the OS, MAC, domain and process queries again.
// Nothing happens unless a TOTP token is there for the api session the context is on.
void ztx_posture_send_all(ziti_context ztx);

void ziti_send_posture_data(ziti_context ztx);

void ziti_send_posture_er(ziti_context ztx, ziti_channel_t *ch);

// collect_all also gathers responses that have not changed since the last send
void ztx_collect_posture(ziti_context ztx, model_list *send_prs, bool collect_all);

// exposed for tests: NULL when send_prs holds nothing the ER protocol can carry and no TOTP token is due.
// The TOTP token (see ztx_posture_set_totp_token) is part of every batch while the context is on its api session
Ziti__EdgeClient__Pb__PostureResponses *ztx_posture_resp_pb(ziti_context ztx, model_list *send_prs);

bool ziti_service_has_query_with_timeout(ziti_service *service);

// builds and sends a ZitiPostureStatusEvent reporting the SDK's current, locally observed
// state for a PC_Process/PC_Process_Multi query (which of its configured paths are running).
// Scans ztx->services itself to find every service currently governed by this query
// (matched by query->id), since one policy -- and so one query -- can apply to more than
// one service.
void ziti_pr_notify_process_status(ziti_context ztx, const ziti_posture_query *query);

// sends one ZitiPostureStatusEvent for the PC_MFA queries that matter to the app now, when what it was told last changed
// (a code, the timeout, the expiry warning, the services). One code serves every query, so the event is about the queries
// that need a code now (none was given, or its timeout is over), all together, or else about the queries whose code ends
// first (a query with no timeout never ends: those are the last ones). Its services are the ones of those queries, its
// timeout the shortest of theirs, the last code is the one of the TOTP token for the api session the context is on (0: none).
// Nothing is sent, and what was told is forgotten, when no service has an MFA query. Does nothing, and remembers nothing,
// unless the app subscribed to ZitiPostureStatusEvent.
void ztx_posture_notify_mfa(ziti_context ztx);

#ifdef __cplusplus
}
#endif


#endif //ZITI_SDK_POSTURE_H
