/*
Copyright (c) 2020 NetFoundry, Inc.

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


#include <internal_model.h>
#include <ziti/ziti_model.h>
#include <ziti/errors.h>

#include <string.h>

IMPL_MODEL(ziti_posture_query, ZITI_POSTURE_QUERY_MODEL)

IMPL_MODEL(ziti_posture_query_set, ZITI_POSTURE_QUERY_SET_MODEL)

IMPL_MODEL(ziti_process, ZITI_PROCESS_MODEL)

IMPL_MODEL(ziti_service, ZITI_SERVICE_MODEL)

IMPL_MODEL(ziti_client_cfg_v1, ZITI_CLIENT_CFG_V1_MODEL)

IMPL_MODEL(ziti_port_range, ZITI_PORT_RANGE_MODEL)

IMPL_MODEL(ziti_intercept_cfg_v1, ZITI_INTERCEPT_CFG_V1_MODEL)

IMPL_MODEL(ziti_server_cfg_v1, ZITI_SERVER_CFG_V1_MODEL)

IMPL_MODEL(ziti_host_cfg_v1, ZITI_HOST_CFG_V1_MODEL)

IMPL_MODEL(ziti_id_cfg, ZITI_ID_CFG_MODEL)

IMPL_MODEL(ziti_config, ZITI_CONFIG_MODEL)

IMPL_MODEL(ziti_edge_router, ZITI_EDGE_ROUTER_MODEL)

IMPL_MODEL(ziti_net_session, ZITI_NET_SESSION_MODEL)

IMPL_MODEL(api_path, ZITI_API_PATH_MODEL)

IMPL_MODEL(ziti_api_versions, ZITI_API_VERSIONS_MODEL)

IMPL_MODEL(ziti_version, ZITI_VERSION_MODEL)

IMPL_MODEL(ziti_identity, ZITI_IDENTITY_MODEL)

IMPL_MODEL(ziti_auth_query_mfa, ZITI_AUTH_QUERY_MFA_MODEL)

IMPL_MODEL(ziti_api_session, ZITI_API_SESSION_MODEL)

IMPL_MODEL(ziti_error, ZITI_ERROR_MODEL)

IMPL_MODEL(ziti_sdk_info, ZITI_SDK_INFO_MODEL)

IMPL_MODEL(ziti_env_info, ZITI_ENV_INFO_MODEL)

IMPL_MODEL(ziti_auth_req, ZITI_AUTH_REQ)

IMPL_MODEL(ziti_enrollment_jwt_header, ZITI_ENROLLMENT_JWT_HEADER_MODEL)

IMPL_MODEL(ziti_enrollment_jwt, ZITI_ENROLLMENT_JWT_MODEL)

IMPL_MODEL(ziti_enrollment_resp, ZITI_ENROLLMENT_RESP)

IMPL_MODEL(ziti_pr_mac_req, ZITI_PR_MAC_REQ)

IMPL_MODEL(ziti_pr_os_req, ZITI_PR_OS_REQ)

IMPL_MODEL(ziti_pr_process, ZITI_PR_PROCESS)

IMPL_MODEL(ziti_pr_process_req, ZITI_PR_PROCESS_REQ)

IMPL_MODEL(ziti_pr_domain_req, ZITI_PR_DOMAIN_REQ)

IMPL_MODEL(ziti_pr_endpoint_state_req, ZITI_PR_ENDPOINT_STATE_REQ)

IMPL_MODEL(ziti_service_timer, ZITI_SERVICE_TIMER)

IMPL_MODEL(ziti_pr_response, ZITI_PR_RESPONSE)

IMPL_MODEL(ziti_service_update, ZITI_SERVICE_UPDATE)

IMPL_MODEL(ziti_mfa_recovery_codes, ZITI_MFA_RECOVERY_CODES_MODEL)

IMPL_MODEL(ziti_mfa_enrollment, ZITI_MFA_ENROLLMENT_MODEL)

IMPL_MODEL(ziti_mfa_code_req, ZITI_MFA_CODE_REQ)

IMPL_MODEL(ziti_identity_data, ZITI_IDENTITY_DATA_MODEL)

IMPL_ENUM(ziti_session_type, ZITI_SESSION_TYPE_ENUM)

const char *ziti_service_get_raw_config(ziti_service *service, const char *cfg_type) {
    return (const char *) model_map_get(&service->config, cfg_type);
}

int ziti_service_get_config(ziti_service *service, const char *cfg_type, void *cfg,
                            int (*parser)(void *, const char *, size_t)) {
    const char *cfg_json = ziti_service_get_raw_config(service, cfg_type);
    if (cfg_json == NULL) {
        return ZITI_CONFIG_NOT_FOUND;
    }

    if (parser(cfg, cfg_json, strlen(cfg_json)) != 0) {
        return ZITI_INVALID_CONFIG;
    };

    return ZITI_OK;
}