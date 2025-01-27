// Copyright (c) 2020-2024. NetFoundry Inc.
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

#ifndef ZITI_SDK_ZITI_MODEL_H
#define ZITI_SDK_ZITI_MODEL_H

#include "model_support.h"

#if _WIN32
#include <winsock2.h>
#include <in6addr.h>
#else

#include <netinet/in.h>

#endif

#define ZITI_PROTOCOL_ENUM(XX, ...) \
XX(tcp, __VA_ARGS__)                \
XX(udp, __VA_ARGS__)

#define ZITI_SESSION_TYPE_ENUM(XX, ...) \
XX(Bind, __VA_ARGS__)                   \
XX(Dial, __VA_ARGS__)

#define ZITI_AUTH_QUERY_TYPE_ENUM(XX, ...) \
XX(MFA, __VA_ARGS__) \
XX(TOTP, __VA_ARGS__) \
XX(EXT_JWT, "EXT-JWT", __VA_ARGS__)

#define ZITI_POSTURE_QUERY_TYPE_ENUM(XX, ...) \
XX(PC_Domain, "DOMAIN", __VA_ARGS__)          \
XX(PC_OS, "OS", __VA_ARGS__)                  \
XX(PC_Process, "PROCESS", __VA_ARGS__)        \
XX(PC_Process_Multi, "PROCESS_MULTI", __VA_ARGS__) \
XX(PC_MAC, "MAC", __VA_ARGS__)                \
XX(PC_MFA, "MFA", __VA_ARGS__)                \
XX(PC_Endpoint_State, "ENDPOINT_STATE", __VA_ARGS__)

#define ZITI_SIGNER_TARGET_TOKEN(XX, ...) \
XX(access_token, "ACCESS", __VA_ARGS__)   \
XX(id_token, "ID", __VA_ARGS__)

#define ZITI_JWT_SIGNER_MODEL(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(enabled, model_bool, none, enabled, __VA_ARGS__) \
XX(provider_url, model_string, none, externalAuthUrl, __VA_ARGS__) \
XX(client_id, model_string, none, clientId, __VA_ARGS__)           \
XX(audience, model_string, none, audience, __VA_ARGS__)           \
XX(scopes, model_string, list, scopes, __VA_ARGS__) \
XX(target_token, ziti_target_token, none, targetToken, __VA_ARGS__)

#define ZITI_ID_CFG_MODEL(XX, ...) \
XX(cert, model_string, none, cert, __VA_ARGS__) \
XX(key, model_string, none, key, __VA_ARGS__) \
XX(ca, model_string, none, ca, __VA_ARGS__)     \
XX(oidc, ziti_jwt_signer, ptr, oidc, __VA_ARGS__)

#define ZITI_CONFIG_MODEL(XX, ...) \
XX(controller_url, model_string, none, ztAPI, __VA_ARGS__) \
XX(controllers, model_string, list, ztAPIs, __VA_ARGS__)   \
XX(id, ziti_id_cfg, none, id, __VA_ARGS__)           \
XX(cfg_source, model_string, none, , __VA_ARGS__)

#define ZITI_API_PATH_MODEL(XX, ...) \
XX(path, model_string, none, path, __VA_ARGS__)

#define ZITI_API_VERSIONS_MODEL(XX, ...) \
XX(edge, api_path, map, edge, __VA_ARGS__)

#define ZITI_CTRL_CAP_ENUM(XX, ...) \
XX(HA_CONTROLLER, __VA_ARGS__)      \
XX(OIDC_AUTH, __VA_ARGS__)

#define ZITI_VERSION_MODEL(XX, ...) \
XX(version, model_string, none, version, __VA_ARGS__) \
XX(revision, model_string, none, revision, __VA_ARGS__) \
XX(build_date, model_string, none, buildDate, __VA_ARGS__) \
XX(capabilities, ziti_ctrl_cap, array, capabilities, __VA_ARGS__) \
XX(api_versions, ziti_api_versions, ptr, apiVersions, __VA_ARGS__)

#define ZITI_IDENTITY_MODEL(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(app_data, json, map, appData, __VA_ARGS__)

#define ZITI_PROCESS_MODEL(XX, ...) \
XX(path, model_string, none, path, __VA_ARGS__)

#define ZITI_POSTURE_QUERY_MODEL(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(is_passing, model_bool, none, isPassing, __VA_ARGS__) \
XX(query_type, ziti_posture_query_type, none, queryType, __VA_ARGS__) \
XX(process, ziti_process, ptr, process, __VA_ARGS__) \
XX(processes, ziti_process, array, processes, __VA_ARGS__) \
XX(timeout, model_number, none, timeout, __VA_ARGS__) \
XX(timeoutRemaining, model_number, ptr, timeoutRemaining, __VA_ARGS__) \
XX(updated_at,model_string, none, updatedAt, __VA_ARGS__)

#define ZITI_POSTURE_QUERY_SET_MODEL(XX, ...) \
XX(policy_id, model_string, none, policyId, __VA_ARGS__) \
XX(is_passing, model_bool, none, isPassing, __VA_ARGS__) \
XX(policy_type, model_string, none, policyType, __VA_ARGS__) \
XX(posture_queries, ziti_posture_query, array, postureQueries, __VA_ARGS__)

#define ZITI_SERVICE_MODEL(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(permissions, ziti_session_type, array, permissions, __VA_ARGS__) \
XX(encryption, model_bool, none, encryptionRequired, __VA_ARGS__) \
XX(perm_flags, model_number, none, NULL, __VA_ARGS__) \
XX(config, json, map, config, __VA_ARGS__) \
XX(posture_query_set, ziti_posture_query_set, array, postureQueries, __VA_ARGS__) \
XX(posture_query_map, ziti_posture_query_set, map, posturePolicies, __VA_ARGS__) \
XX(updated_at,model_string, none, updatedAt, __VA_ARGS__)

#define ZITI_CLIENT_CFG_V1_MODEL(XX, ...) \
XX(hostname, ziti_address, none, hostname, __VA_ARGS__) \
XX(port, model_number, none, port, __VA_ARGS__)

#define ZITI_PORT_RANGE_MODEL(XX, ...) \
XX(low, model_number, none, low, __VA_ARGS__) \
XX(high, model_number, none, high, __VA_ARGS__)

#define ZITI_INTERCEPT_CFG_V1 "intercept.v1"
#define ZITI_CLIENT_CFG_V1 "ziti-tunneler-client.v1"

#define ZITI_INTERCEPT_CFG_V1_MODEL(XX, ...) \
XX(protocols, ziti_protocol, list, protocols, __VA_ARGS__) \
XX(addresses, ziti_address, list, addresses, __VA_ARGS__) \
XX(port_ranges, ziti_port_range, list, portRanges, __VA_ARGS__) \
XX(dial_options, tag, map, dialOptions, __VA_ARGS__) \
XX(source_ip, model_string, none, sourceIp, __VA_ARGS__)

#define ZITI_SERVER_CFG_V1_MODEL(XX, ...) \
XX(protocol, model_string, none, protocol, __VA_ARGS__) \
XX(hostname, model_string, none, hostname, __VA_ARGS__) \
XX(port, model_number, none, port, __VA_ARGS__)

#define ZITI_PROXY_SERVER_TYPE_ENUM(XX, ...) \
XX(http, __VA_ARGS__)

#define ZITI_PROXY_SERVER_MODEL(XX, ...) \
XX(address, model_string, none, address, __VA_ARGS__) \
XX(type, ziti_proxy_server_type, none, type, __VA_ARGS__)

#define ZITI_HOST_CFG_V1_MODEL(XX, ...) \
XX(protocol, model_string, none, protocol, __VA_ARGS__) \
XX(forward_protocol, model_bool, none, forwardProtocol, __VA_ARGS__) \
XX(allowed_protocols, model_string, array, allowedProtocols, __VA_ARGS__) \
XX(address, model_string, none, address, __VA_ARGS__) \
XX(forward_address, model_bool, none, forwardAddress, __VA_ARGS__) \
XX(allowed_addresses, ziti_address, array, allowedAddresses, __VA_ARGS__) \
XX(port, model_number, none, port, __VA_ARGS__) \
XX(forward_port, model_bool, none, forwardPort, __VA_ARGS__) \
XX(allowed_port_ranges, ziti_port_range, array, allowedPortRanges, __VA_ARGS__) \
XX(allowed_source_addresses, ziti_address, array, allowedSourceAddresses, __VA_ARGS__) \
XX(proxy, ziti_proxy_server, none, proxy, __VA_ARGS__) \
XX(listen_options, ziti_listen_options, ptr, listenOptions, __VA_ARGS__)

#define ZITI_HOST_CFG_V2_MODEL(XX, ...) \
XX(terminators, ziti_host_cfg_v1, list, terminators, __VA_ARGS__)

#define ZITI_MFA_ENROLLMENT_MODEL(XX, ...) \
XX(is_verified, model_bool, none, isVerified, __VA_ARGS__) \
XX(recovery_codes, model_string, array, recoveryCodes, __VA_ARGS__) \
XX(provisioning_url, model_string, none, provisioningUrl, __VA_ARGS__)

#define ZITI_LISTEN_OPTS_MODEL(XX, ...) \
XX(bind_with_identity, model_bool, none, bindUsingEdgeIdentity, __VA_ARGS__) \
XX(connect_timeout, duration, none, connectTimeout, __VA_ARGS__)       \
XX(connect_timeout_seconds, model_number, none, connectTimeoutSeconds, __VA_ARGS__) \
XX(cost, model_number, none, cost, __VA_ARGS__) \
XX(identity, model_string, none, identity, __VA_ARGS__) \
XX(max_connections, model_number, none, maxConnections, __VA_ARGS__)\
XX(precendence, model_string, none, precendence, __VA_ARGS__)


#ifdef __cplusplus
extern "C" {
#endif

enum ziti_address_type {
    ziti_address_hostname,
    ziti_address_cidr
};

typedef struct ziti_address_s {
    enum ziti_address_type type;
    union {
        struct {
            char af;
            unsigned int bits;
            struct in6_addr ip;
        } cidr;
        char hostname[256];
    } addr;
} ziti_address;




// make sure ziti model functions are properly exported
#ifdef MODEL_API
#undef MODEL_API
#endif
#define MODEL_API ZITI_FUNC

ZITI_FUNC int parse_ziti_address_str(ziti_address *addr, const char *addr_str);

ZITI_FUNC int ziti_address_print(char *buf, size_t max, const ziti_address *address);

ZITI_FUNC int ziti_address_match(const ziti_address *addr, const ziti_address *range);

ZITI_FUNC int ziti_address_match_s(const char *addr, const ziti_address *range);

ZITI_FUNC int ziti_addrstr_match_list(const char *addr, const model_list *range);
ZITI_FUNC int ziti_address_match_list(const ziti_address *addr, const model_list *range);

ZITI_FUNC int ziti_address_match_array(const char *addr, ziti_address **range);

DECLARE_MODEL_FUNCS(ziti_address)

DECLARE_ENUM(ziti_protocol, ZITI_PROTOCOL_ENUM)

ZITI_FUNC model_bool ziti_protocol_match(ziti_protocol proto, const model_list *proto_list);
ZITI_FUNC int ziti_port_match(int port, const model_list *port_range_list);

DECLARE_ENUM(ziti_session_type, ZITI_SESSION_TYPE_ENUM)

DECLARE_ENUM(ziti_auth_query_type, ZITI_AUTH_QUERY_TYPE_ENUM)

DECLARE_ENUM(ziti_posture_query_type, ZITI_POSTURE_QUERY_TYPE_ENUM)

DECLARE_ENUM(ziti_ctrl_cap, ZITI_CTRL_CAP_ENUM)

DECLARE_ENUM(ziti_target_token, ZITI_SIGNER_TARGET_TOKEN)

DECLARE_MODEL(api_path, ZITI_API_PATH_MODEL)

DECLARE_MODEL(ziti_api_versions, ZITI_API_VERSIONS_MODEL)

DECLARE_MODEL(ziti_version, ZITI_VERSION_MODEL)

DECLARE_MODEL(ziti_jwt_signer, ZITI_JWT_SIGNER_MODEL)

DECLARE_MODEL(ziti_id_cfg, ZITI_ID_CFG_MODEL)

DECLARE_MODEL(ziti_config, ZITI_CONFIG_MODEL)

DECLARE_MODEL(ziti_identity, ZITI_IDENTITY_MODEL)

DECLARE_MODEL(ziti_process, ZITI_PROCESS_MODEL)

DECLARE_MODEL(ziti_posture_query, ZITI_POSTURE_QUERY_MODEL)

DECLARE_MODEL(ziti_posture_query_set, ZITI_POSTURE_QUERY_SET_MODEL)

DECLARE_MODEL(ziti_service, ZITI_SERVICE_MODEL)

DECLARE_MODEL(ziti_client_cfg_v1, ZITI_CLIENT_CFG_V1_MODEL)

DECLARE_MODEL(ziti_port_range, ZITI_PORT_RANGE_MODEL)

DECLARE_MODEL(ziti_intercept_cfg_v1, ZITI_INTERCEPT_CFG_V1_MODEL)

DECLARE_MODEL(ziti_listen_options, ZITI_LISTEN_OPTS_MODEL)

DECLARE_MODEL(ziti_server_cfg_v1, ZITI_SERVER_CFG_V1_MODEL)

DECLARE_ENUM(ziti_proxy_server_type, ZITI_PROXY_SERVER_TYPE_ENUM)

DECLARE_MODEL(ziti_proxy_server, ZITI_PROXY_SERVER_MODEL)

DECLARE_MODEL(ziti_host_cfg_v1, ZITI_HOST_CFG_V1_MODEL)

DECLARE_MODEL(ziti_host_cfg_v2, ZITI_HOST_CFG_V2_MODEL)

DECLARE_MODEL(ziti_mfa_enrollment, ZITI_MFA_ENROLLMENT_MODEL)

ZITI_FUNC model_bool ziti_service_has_permission(const ziti_service *service, ziti_session_type sessionType);

ZITI_FUNC const char *ziti_service_get_raw_config(ziti_service *service, const char *cfg_type);

typedef int (*parse_service_cfg_f)(void *, const char *, size_t);

ZITI_FUNC int ziti_service_get_config(ziti_service *service, const char *cfg_type, void *cfg,
                                      parse_service_cfg_f parse_func);

ZITI_FUNC int ziti_intercept_from_client_cfg(ziti_intercept_cfg_v1 *intercept, const ziti_client_cfg_v1 *client_cfg);

ZITI_FUNC int
ziti_intercept_match(const ziti_intercept_cfg_v1 *intercept, ziti_protocol proto, const char *addr, int port);

ZITI_FUNC int ziti_intercept_match2(const ziti_intercept_cfg_v1 *intercept, ziti_protocol proto, const ziti_address *addr, int port);


#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_MODEL_H
