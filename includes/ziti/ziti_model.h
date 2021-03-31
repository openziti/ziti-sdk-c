/*
Copyright (c) 2020 Netfoundry, Inc.

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


#ifndef ZITI_SDK_ZITI_MODEL_H
#define ZITI_SDK_ZITI_MODEL_H

#include "model_support.h"

#define ZITI_AUTH_QUERY_MFA_MODEL(XX, ...) \
XX(type_id, string, none, typeId, __VA_ARGS__) \
XX(provider, string, none, provider, __VA_ARGS__) \
XX(http_method, string, none, httpMethod, __VA_ARGS__) \
XX(http_url, string, none, httpUrl, __VA_ARGS__) \
XX(min_length, int, none, minLength, __VA_ARGS__) \
XX(max_length, int, none, maxLength, __VA_ARGS__) \
XX(format, string, none, format, __VA_ARGS__)

#define ZITI_ID_CFG_MODEL(XX, ...) \
XX(cert, string, none, cert, __VA_ARGS__) \
XX(key, string, none, key, __VA_ARGS__) \
XX(ca, string, none, ca, __VA_ARGS__)

#define ZITI_CONFIG_MODEL(XX, ...) \
XX(controller_url, string, none, ztAPI, __VA_ARGS__) \
XX(id, ziti_id_cfg, none, id, __VA_ARGS__)

#define ZITI_VERSION_MODEL(XX, ...) \
XX(version, string, none, version, __VA_ARGS__) \
XX(revision, string, none, revision, __VA_ARGS__) \
XX(build_date, string, none, buildDate, __VA_ARGS__)

#define ZITI_IDENTITY_MODEL(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(name, string, none, name, __VA_ARGS__)\
XX(tags, tag, map, tags, __VA_ARGS__)

#define ZITI_PROCESS_MODEL(XX, ...) \
XX(path, string, none, path, __VA_ARGS__)

#define ZITI_POSTURE_QUERY_MODEL(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(is_passing, bool, none, isPassing, __VA_ARGS__) \
XX(query_type, string, none, queryType, __VA_ARGS__) \
XX(process, ziti_process, ptr, process, __VA_ARGS__) \
XX(timeout, int, none, timeout, __VA_ARGS__)

#define ZITI_POSTURE_QUERY_SET_MODEL(XX, ...) \
XX(policy_id, string, none, policyId, __VA_ARGS__) \
XX(is_passing, bool, none, isPassing, __VA_ARGS__) \
XX(posture_queries, ziti_posture_query, array, postureQueries, __VA_ARGS__)

#define ZITI_SERVICE_MODEL(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(name, string, none, name, __VA_ARGS__) \
XX(permissions, string, array, permissions, __VA_ARGS__) \
XX(encryption, bool, none, encryptionRequired, __VA_ARGS__) \
XX(perm_flags, int, none, NULL, __VA_ARGS__) \
XX(config, json, map, config, __VA_ARGS__) \
XX(posture_query_set, ziti_posture_query_set, array, postureQueries, __VA_ARGS__)

#define ZITI_CLIENT_CFG_V1_MODEL(XX, ...) \
XX(hostname, string, none, hostname, __VA_ARGS__) \
XX(port, int, none, port, __VA_ARGS__)

#define ZITI_PORT_RANGE_MODEL(XX, ...) \
XX(low, int, none, low, __VA_ARGS__) \
XX(high, int, none, high, __VA_ARGS__)

#define ZITI_INTERCEPT_CFG_V1_MODEL(XX, ...) \
XX(protocols, string, array, protocols, __VA_ARGS__) \
XX(addresses, string, array, addresses, __VA_ARGS__) \
XX(port_ranges, ziti_port_range, array, portRanges, __VA_ARGS__) \
XX(dial_options, tag, map, dialOptions, __VA_ARGS__) \
XX(source_ip, string, none, sourceIp, __VA_ARGS__)

#define ZITI_SERVER_CFG_V1_MODEL(XX, ...) \
XX(protocol, string, none, protocol, __VA_ARGS__) \
XX(hostname, string, none, hostname, __VA_ARGS__) \
XX(port, int, none, port, __VA_ARGS__)

#define ZITI_HOST_CFG_V1_MODEL(XX, ...) \
XX(protocol, string, none, protocol, __VA_ARGS__) \
XX(forward_protocol, bool, none, forwardProtocol, __VA_ARGS__) \
XX(allowed_protocols, string, array, allowedProtocols, __VA_ARGS__) \
XX(address, string, none, address, __VA_ARGS__) \
XX(forward_address, bool, none, forwardAddress, __VA_ARGS__) \
XX(allowed_addresses, string, array, allowedAddresses, __VA_ARGS__) \
XX(port, int, none, port, __VA_ARGS__) \
XX(forward_port, bool, none, forwardPort, __VA_ARGS__) \
XX(allowed_port_ranges, ziti_port_range, array, allowedPortRanges, __VA_ARGS__) \
XX(listen_options, tag, map, listenOptions, __VA_ARGS__)

#define ZITI_MFA_ENROLLMENT_MODEL(XX, ...) \
XX(is_verified, bool, none, isVerified, __VA_ARGS__) \
XX(recovery_codes, string, array, recoveryCodes, __VA_ARGS__) \
XX(provisioning_url, string, none, provisioningUrl, __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

// make sure ziti model functions are properly exported
#ifdef MODEL_API
#undef MODEL_API
#endif
#define MODEL_API ZITI_FUNC

DECLARE_MODEL(ziti_version, ZITI_VERSION_MODEL)

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

DECLARE_MODEL(ziti_server_cfg_v1, ZITI_SERVER_CFG_V1_MODEL)

DECLARE_MODEL(ziti_host_cfg_v1, ZITI_HOST_CFG_V1_MODEL)

DECLARE_MODEL(ziti_auth_query_mfa, ZITI_AUTH_QUERY_MFA_MODEL)

DECLARE_MODEL(ziti_mfa_enrollment, ZITI_MFA_ENROLLMENT_MODEL)

ZITI_FUNC const char *ziti_service_get_raw_config(ziti_service *service, const char *cfg_type);

ZITI_FUNC int ziti_service_get_config(ziti_service *service, const char *cfg_type, void *cfg,
                                      int (*parse_func)(void *, const char *, size_t));

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_MODEL_H
