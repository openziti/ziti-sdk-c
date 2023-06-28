// Copyright (c) 2019-2023.  NetFoundry Inc.
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


#ifndef ZITI_SDK_CONTROLLER_H
#define ZITI_SDK_CONTROLLER_H

#include <tlsuv/http.h>
#include "internal_model.h"
#include "ziti/ziti_model.h"
#include "zt_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const char* const PC_DOMAIN_TYPE;
extern const char* const PC_OS_TYPE;
extern const char* const PC_PROCESS_TYPE;
extern const char* const PC_PROCESS_MULTI_TYPE;
extern const char* const PC_MAC_TYPE;
extern const char* const PC_ENDPOINT_STATE_TYPE;

typedef void (*ziti_ctrl_redirect_cb)(const char *new_address, void *ctx);

typedef struct ziti_controller_s {
    uv_loop_t *loop;
    tlsuv_http_t *client;
    char *url;

    // tuning options
    unsigned int page_size;

    ziti_version version;

    char *api_session_token;
    char *instance_id;

    ziti_ctrl_redirect_cb redirect_cb;
    void *redirect_ctx;
} ziti_controller;

int ziti_ctrl_init(uv_loop_t *loop, ziti_controller *ctlr, const char *url, tls_context *tls);

int ziti_ctrl_cancel(ziti_controller *ctrl);

void ziti_ctrl_set_page_size(ziti_controller *ctrl, unsigned int size);

void ziti_ctrl_set_redirect_cb(ziti_controller *ctrl, ziti_ctrl_redirect_cb cb, void *ctx);

int ziti_ctrl_close(ziti_controller *ctrl);

void ziti_ctrl_clear_api_session(ziti_controller *ctrl);

void ziti_ctrl_get_version(ziti_controller *ctrl, void (*ver_cb)(ziti_version *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_login(ziti_controller *ctrl, model_list *cfg_types, void (*cb)(ziti_api_session *, const ziti_error *, void *),
                     void *ctx);

void ziti_ctrl_current_api_session(ziti_controller *ctrl, void(*cb)(ziti_api_session *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_current_identity(ziti_controller *ctrl, void(*cb)(ziti_identity_data *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_current_edge_routers(ziti_controller *ctrl, void(*cb)(ziti_edge_router_array, const ziti_error *, void *),
                                    void *ctx);

void ziti_ctrl_logout(ziti_controller *ctrl, void(*cb)(void *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_get_services_update(ziti_controller *ctrl, void (*cb)(ziti_service_update *, const ziti_error *, void *),
                                   void *ctx);

void ziti_ctrl_get_services(ziti_controller *ctrl, void (*srv_cb)(ziti_service_array, const ziti_error *, void *),
                            void *ctx);

void ziti_ctrl_get_service(ziti_controller *ctrl, const char *service_name,
                           void (*srv_cb)(ziti_service *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_create_session(
        ziti_controller *ctrl, const char *service_id, ziti_session_type type,
        void (*cb)(ziti_net_session *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_get_session(
        ziti_controller *ctrl, const char *session_id,
        void (*cb)(ziti_net_session *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_get_sessions(
        ziti_controller *ctrl, void (*cb)(ziti_net_session **, const ziti_error *, void *), void *ctx);

void ziti_ctrl_get_well_known_certs(ziti_controller *ctrl, void (*cb)(char *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_enroll(ziti_controller *ctrl, ziti_enrollment_method method, const char *token, const char *csr,
                      const char *name,
                      void (*cb)(ziti_enrollment_resp *, const ziti_error *, void *), void *ctx);

//Posture
void ziti_pr_post_bulk(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(ziti_pr_response *, const ziti_error *, void *), void *ctx);

void ziti_pr_post(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(ziti_pr_response *, const ziti_error *, void *), void *ctx);


//MFA
void ziti_ctrl_login_mfa(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_post_mfa(ziti_controller *ctrl, void(*cb)(void *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_get_mfa(ziti_controller *ctrl, void(*cb)(ziti_mfa_enrollment *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_delete_mfa(ziti_controller *ctrl, char *code, void(*cb)(void *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_post_mfa_verify(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_get_mfa_recovery_codes(ziti_controller *ctrl, char *code, void(*cb)(ziti_mfa_recovery_codes *, const ziti_error *, void *), void *ctx);

void ziti_ctrl_post_mfa_recovery_codes(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const ziti_error *, void *), void *ctx);

//Authenticators

void ziti_ctrl_extend_cert_authenticator(ziti_controller *ctrl, const char *authenticatorId, const char *csr, void(*cb)(ziti_extend_cert_authenticator_resp*, const ziti_error *, void *), void *ctx);

void ziti_ctrl_verify_extend_cert_authenticator(ziti_controller *ctrl, const char *authenticatorId, const char *client_cert, void(*cb)(void *, const ziti_error *, void *), void *ctx);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_CONTROLLER_H
