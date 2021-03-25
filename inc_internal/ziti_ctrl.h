/*
Copyright (c) 2019-2020 NetFoundry, Inc.

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


#ifndef ZITI_SDK_CONTROLLER_H
#define ZITI_SDK_CONTROLLER_H

#include <uv_mbed/um_http.h>
#include "internal_model.h"
#include "ziti/ziti_model.h"
#include "zt_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const char* const PC_DOMAIN_TYPE;
extern const char* const PC_OS_TYPE;
extern const char* const PC_PROCESS_TYPE;
extern const char* const PC_MAC_TYPE;

typedef struct ziti_controller_s {
    um_http_t client;
    ziti_version version;
    char *session;

} ziti_controller;

int ziti_ctrl_init(uv_loop_t *loop, ziti_controller *ctlr, const char *url, tls_context *tls);

int ziti_ctrl_close(ziti_controller *ctrl);

void ziti_ctrl_get_version(ziti_controller *ctrl, void (*ver_cb)(ziti_version *, ziti_error *, void *), void *ctx);

void
ziti_ctrl_login(ziti_controller *ctrl, const char **cfg_types, void (*login_cb)(ziti_session *, ziti_error *, void *),
                void *ctx);

void ziti_ctrl_current_api_session(ziti_controller *ctrl, void(*cb)(ziti_session *, ziti_error *, void *), void *ctx);

void ziti_ctrl_current_edge_routers(ziti_controller *ctrl, void(*cb)(ziti_edge_router_array, ziti_error *, void *),
                                    void *ctx);

void ziti_ctrl_logout(ziti_controller *ctrl, void(*cb)(void *, ziti_error *, void *), void *ctx);

void ziti_ctrl_get_services_update(ziti_controller *ctrl, void (*cb)(ziti_service_update *, ziti_error *, void *),
                                   void *ctx);

void ziti_ctrl_get_services(ziti_controller *ctrl, void (*srv_cb)(ziti_service_array, ziti_error *, void *), void *ctx);

void ziti_ctrl_get_service(ziti_controller *ctrl, const char *service_name,
                           void (*srv_cb)(ziti_service *, ziti_error *, void *), void *ctx);

void ziti_ctrl_get_net_session(
        ziti_controller *ctrl, const char *service_id, const char *type,
        void (*cb)(ziti_net_session *, ziti_error *, void *), void *ctx);

void ziti_ctrl_get_sessions(
        ziti_controller *ctrl, void (*cb)(ziti_net_session **, ziti_error *, void *), void *ctx);

void ziti_ctrl_get_well_known_certs(ziti_controller *ctrl, void (*cb)(char *, ziti_error *, void *), void *ctx);

void ziti_ctrl_enroll(ziti_controller *ctrl, const char *method, const char *token, const char *csr,
                      void (*cb)(ziti_enrollment_resp *, ziti_error *, void *), void *ctx);

//Posture
void ziti_pr_post_bulk(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, ziti_error *, void *), void *ctx);

void ziti_pr_post(ziti_controller *ctrl, char *body, size_t body_len,void(*cb)(void *, ziti_error *, void *), void *ctx);


//MFA
void ziti_ctrl_login_mfa(ziti_controller *ctrl, char* body, size_t body_len, void(*cb)(void *, ziti_error *, void *), void *ctx);

void ziti_ctrl_post_mfa(ziti_controller *ctrl,void(*cb)(void *, ziti_error *, void *), void *ctx);

void ziti_ctrl_get_mfa(ziti_controller *ctrl, void(*cb)(ziti_mfa_enrollment *, ziti_error *, void *), void *ctx);

void ziti_ctrl_delete_mfa(ziti_controller *ctrl, char* code, void(*cb)(void*, ziti_error *, void *), void *ctx);

void ziti_ctrl_post_mfa_verify(ziti_controller *ctrl, char* body, size_t body_len, void(*cb)(void *, ziti_error *, void *), void *ctx);

void ziti_ctrl_get_mfa_recovery_codes(ziti_controller *ctrl, char* code, void(*cb)(ziti_mfa_recovery_codes *, ziti_error *, void *), void *ctx);

void ziti_ctrl_post_mfa_recovery_codes(ziti_controller *ctrl, char* body, size_t body_len, void(*cb)(void *, ziti_error *, void *), void *ctx);


#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_CONTROLLER_H
