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


#ifndef ZITI_SDK_INTERNAL_MODEL_H
#define ZITI_SDK_INTERNAL_MODEL_H

#include "ziti/model_support.h"
#include "ziti/ziti_model.h"

// extends ziti_identity
#define ZITI_IDENTITY_DATA_MODEL(XX, ...) \
ZITI_IDENTITY_MODEL(XX, __VA_ARGS__) \
XX(default_hosting_precendence, string, none, defaultHostingPrecendence, __VA_ARGS__) \
XX(default_hosting_cost, int, none, defaultHostingCost, __VA_ARGS__)                  \
XX(service_hosting_precendences, string, map, serviceHostingPrecedences, __VA_ARGS__)\
XX(service_hosting_costs, int, map, serviceHostingCosts, __VA_ARGS__)

#define ZITI_EDGE_ROUTER_MODEL(XX, ...)\
XX(name, string, none, name, __VA_ARGS__)\
XX(hostname, string, none, hostname, __VA_ARGS__) \
XX(protocols, string, map, supportedProtocols, __VA_ARGS__) \
XX(ingress, string, map, urls, __VA_ARGS__) /* deprecated */

#define ZITI_NET_SESSION_MODEL(XX, ...) \
XX(token, string, none, token, __VA_ARGS__)\
XX(id, string, none, id, __VA_ARGS__) \
XX(session_type, string, none, type, __VA_ARGS__) \
XX(edge_routers, ziti_edge_router, array, edgeRouters, __VA_ARGS__) \
XX(service_id, string, none, NULL, __VA_ARGS__)

#define ZITI_PROCESS_MODEL(XX, ...) \
XX(path, string, none, path, __VA_ARGS__)

#define ZITI_API_SESSION_MODEL(XX, ...)\
XX(id, string, none, id, __VA_ARGS__) \
XX(token, string, none, token, __VA_ARGS__) \
XX(expires, timestamp, ptr, expiresAt, __VA_ARGS__) \
XX(expireSeconds, int, ptr, expirationSeconds, __VA_ARGS__) \
XX(updated, timestamp, ptr, updatedAt, __VA_ARGS__) \
XX(cached_last_activity_at, timestamp, ptr, cachedLastActivityAt, __VA_ARGS__) \
XX(identity, ziti_identity, ptr, identity, __VA_ARGS__) \
XX(posture_query_set, ziti_posture_query_set, array, postureQueries, __VA_ARGS__) \
XX(auth_queries, ziti_auth_query_mfa, array, authQueries, __VA_ARGS__)         \
XX(authenticator_id, string, none, authenticatorId, __VA_ARGS__)

#define ZITI_ERROR_MODEL(XX, ...) \
XX(err, int, none, , __VA_ARGS__) \
XX(http_code, int, none, , __VA_ARGS__) \
XX(code, string, none, code, __VA_ARGS__) \
XX(message, string, none, message, __VA_ARGS__)

#define ZITI_ENROLLMENT_JWT_HEADER_MODEL(XX, ...) \
XX(alg, string, none, alg, __VA_ARGS__) \
XX(typ, string, none, typ, __VA_ARGS__)

#define ZITI_ENROLLMENT_JWT_MODEL(XX, ...) \
XX(method, string, none, em, __VA_ARGS__) \
XX(controller, string, none, iss, __VA_ARGS__) \
XX(subject, string, none, sub, __VA_ARGS__) \
XX(token, string, none, jti, __VA_ARGS__)

#define ZITI_SDK_INFO_MODEL(XX, ...) \
XX(type, string, none, type, __VA_ARGS__) \
XX(version, string, none, version, __VA_ARGS__) \
XX(revision, string, none, revision, __VA_ARGS__) \
XX(branch, string, none, branch, __VA_ARGS__)   \
XX(app_id, string, none, appID, __VA_ARGS__)    \
XX(app_version, string, none, appVersion, __VA_ARGS__)

#define ZITI_ENV_INFO_MODEL(XX, ...) \
XX(os, string, none, os, __VA_ARGS__) \
XX(os_release, string, none, osRelease, __VA_ARGS__) \
XX(os_version, string, none, osVersion, __VA_ARGS__) \
XX(arch, string, none, arch, __VA_ARGS__)

#define ZITI_AUTH_REQ(XX, ...) \
XX(sdk_info, ziti_sdk_info, none, sdkInfo, __VA_ARGS__) \
XX(env_info, ziti_env_info, none, envInfo, __VA_ARGS__) \
XX(config_types, string, array, configTypes, __VA_ARGS__)

#define ZITI_ENROLLMENT_RESP(XX, ...) \
XX(cert, string, none, cert, __VA_ARGS__)

#define ZITI_PR_MAC_REQ(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(typeId, string, none, typeId, __VA_ARGS__) \
XX(mac_addresses, string, array, macAddresses, __VA_ARGS__)

#define ZITI_PR_DOMAIN_REQ(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(typeId, string, none, typeId, __VA_ARGS__) \
XX(domain, string, none, domain, __VA_ARGS__)

#define ZITI_PR_OS_REQ(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(typeId, string, none, typeId, __VA_ARGS__) \
XX(type, string, none, type, __VA_ARGS__) \
XX(version, string, none, version, __VA_ARGS__) \
XX(build, string, none, build, __VA_ARGS__)

#define ZITI_PR_PROCESS(XX, ...) \
XX(is_running, bool, none, isRunning, __VA_ARGS__) \
XX(hash, string, none, hash, __VA_ARGS__) \
XX(signer, string, none, signerFingerprint, __VA_ARGS__)

#define ZITI_PR_PROCESS_REQ(XX, ...) \
XX(id, string, none, id, __VA_ARGS__)\
XX(path, string, none, path, __VA_ARGS__) \
XX(typeId, string, none, typeId, __VA_ARGS__) \
XX(is_running, bool, none, isRunning, __VA_ARGS__) \
XX(hash, string, none, hash, __VA_ARGS__) \
XX(signers, string, array, signerFingerprints, __VA_ARGS__)

#define ZITI_PR_ENDPOINT_STATE_REQ(XX, ...) \
XX(id, string, none, id, __VA_ARGS__)\
XX(typeId, string, none, typeId, __VA_ARGS__) \
XX(unlocked, bool, none, unlocked, __VA_ARGS__) \
XX(woken, bool, none, woken, __VA_ARGS__)

#define ZITI_SERVICE_TIMER(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(name, string, none, name, __VA_ARGS__) \
XX(posture_query_type, string, none, postureQueryType, __VA_ARGS__) \
XX(timeout, int, ptr, timeout, __VA_ARGS__) \
XX(timeoutRemaining, int, ptr, timeoutRemaining, __VA_ARGS__)

#define ZITI_PR_RESPONSE(XX, ...) \
XX(services, ziti_service_timer, array, services, __VA_ARGS__)

#define ZITI_SERVICE_UPDATE(XX, ...) \
XX(last_change, string, none, lastChangeAt, __VA_ARGS__)

#define ZITI_MFA_CODE_REQ(XX, ...) \
XX(code, string, none, code, __VA_ARGS__)

#define ZITI_MFA_RECOVERY_CODES_MODEL(XX, ...) \
XX(recovery_codes, string, array, recoveryCodes, __VA_ARGS__)

#define ZITI_EXTEND_CERT_AUTHENTICATOR_REQ(XX, ...) \
XX(client_cert_csr, string, none, clientCertCsr, __VA_ARGS__)

#define ZITI_VERIFY_EXTEND_CERT_AUTHENTICATOR_REQ(XX, ...) \
XX(client_cert, string, none, clientCert, __VA_ARGS__)

#define ZITI_EXTEND_CERT_AUTHENTICATOR_RESP(XX, ...) \
XX(client_cert_pem, string, none, clientCert, __VA_ARGS__) \
XX(cas_pem, string, none, ca, __VA_ARGS__)

#define ZITI_AUTHENTICATOR_MODEL(XX, ...) \
XX(id, string, none, id, __VA_ARGS__) \
XX(method, string, none, method, __VA_ARGS__) \
XX(identity_id, string, none, identityId, __VA_ARGS__) \
XX(cert_pem, string, none, certPem, __VA_ARGS__) \
XX(fingerprint, string, none, fingerprint, __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MODEL(ziti_identity_data, ZITI_IDENTITY_DATA_MODEL)

DECLARE_MODEL(ziti_edge_router, ZITI_EDGE_ROUTER_MODEL)

DECLARE_MODEL(ziti_net_session, ZITI_NET_SESSION_MODEL)

DECLARE_MODEL(ziti_api_session, ZITI_API_SESSION_MODEL)

DECLARE_MODEL(ziti_error, ZITI_ERROR_MODEL)

DECLARE_MODEL(ziti_enrollment_jwt_header, ZITI_ENROLLMENT_JWT_HEADER_MODEL)

DECLARE_MODEL(ziti_enrollment_jwt, ZITI_ENROLLMENT_JWT_MODEL)

DECLARE_MODEL(ziti_enrollment_resp, ZITI_ENROLLMENT_RESP)

DECLARE_MODEL(ziti_sdk_info, ZITI_SDK_INFO_MODEL)

DECLARE_MODEL(ziti_env_info, ZITI_ENV_INFO_MODEL)

DECLARE_MODEL(ziti_auth_req, ZITI_AUTH_REQ)

DECLARE_MODEL(ziti_pr_mac_req, ZITI_PR_MAC_REQ)

DECLARE_MODEL(ziti_pr_os_req, ZITI_PR_OS_REQ)

DECLARE_MODEL(ziti_pr_process, ZITI_PR_PROCESS)

DECLARE_MODEL(ziti_pr_process_req, ZITI_PR_PROCESS_REQ)

DECLARE_MODEL(ziti_pr_endpoint_state_req, ZITI_PR_ENDPOINT_STATE_REQ)

DECLARE_MODEL(ziti_pr_domain_req, ZITI_PR_DOMAIN_REQ)

DECLARE_MODEL(ziti_service_update, ZITI_SERVICE_UPDATE)

DECLARE_MODEL(ziti_mfa_code_req, ZITI_MFA_CODE_REQ)

DECLARE_MODEL(ziti_mfa_recovery_codes, ZITI_MFA_RECOVERY_CODES_MODEL)

DECLARE_MODEL(ziti_service_timer, ZITI_SERVICE_TIMER)

DECLARE_MODEL(ziti_pr_response, ZITI_PR_RESPONSE)

DECLARE_MODEL(ziti_extend_cert_authenticator_req, ZITI_EXTEND_CERT_AUTHENTICATOR_REQ)

DECLARE_MODEL(ziti_verify_extend_cert_authenticator_req, ZITI_VERIFY_EXTEND_CERT_AUTHENTICATOR_REQ)

DECLARE_MODEL(ziti_authenticator, ZITI_AUTHENTICATOR_MODEL)

DECLARE_MODEL(ziti_extend_cert_authenticator_resp, ZITI_EXTEND_CERT_AUTHENTICATOR_RESP)

#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_INTERNAL_MODEL_H
