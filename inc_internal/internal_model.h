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


#ifndef ZITI_SDK_INTERNAL_MODEL_H
#define ZITI_SDK_INTERNAL_MODEL_H

#include "ziti/model_support.h"
#include "ziti/ziti_model.h"

// extends ziti_identity
#define ZITI_IDENTITY_DATA_MODEL(XX, ...) \
ZITI_IDENTITY_MODEL(XX, __VA_ARGS__) \
XX(default_hosting_precendence, model_string, none, defaultHostingPrecendence, __VA_ARGS__) \
XX(default_hosting_cost, model_number, none, defaultHostingCost, __VA_ARGS__)                  \
XX(service_hosting_precendences, model_string, map, serviceHostingPrecedences, __VA_ARGS__)\
XX(service_hosting_costs, model_number, map, serviceHostingCosts, __VA_ARGS__)

// add other protocols when we support them
#define ZITI_ER_PROTOCOLS(XX, ...) \
XX(tls, model_string, none, tls, __VA_ARGS__)

#define ZITI_EDGE_ROUTER_MODEL(XX, ...)\
XX(name, model_string, none, name, __VA_ARGS__)\
XX(hostname, model_string, none, hostname, __VA_ARGS__) \
XX(protocols, ziti_er_protocols, none, supportedProtocols, __VA_ARGS__)

#define ZITI_SERVICE_EDGE_ROUTERS_MODEL(XX, ...) \
XX(routers, ziti_edge_router, array, edgeRouters, __VA_ARGS__)

#define ZITI_SESSION_MODEL(XX, ...) \
XX(token, model_string, none, token, __VA_ARGS__)\
XX(id, model_string, none, id, __VA_ARGS__)      \
XX(api_session_id, model_string, none, apiSessionId, __VA_ARGS__) \
XX(edge_routers, ziti_edge_router, list, edgeRouters, __VA_ARGS__) \
XX(service_id, model_string, none, serviceId, __VA_ARGS__) \
XX(refresh, model_bool, none, , __VA_ARGS__)

#define ZITI_PROCESS_MODEL(XX, ...) \
XX(path, model_string, none, path, __VA_ARGS__)

#define ZITI_API_SESSION_MODEL(XX, ...)\
XX(id, model_string, none, id, __VA_ARGS__) \
XX(token, model_string, none, token, __VA_ARGS__) \
XX(expires, timestamp, none, expiresAt, __VA_ARGS__) \
XX(expireSeconds, model_number, none, expirationSeconds, __VA_ARGS__) \
XX(updated, timestamp, none, updatedAt, __VA_ARGS__) \
XX(cached_last_activity_at, timestamp, none, cachedLastActivityAt, __VA_ARGS__) \
XX(identity_id, model_string, none, identityId, __VA_ARGS__) \
XX(identity, ziti_identity, none, identity, __VA_ARGS__) \
XX(posture_query_set, ziti_posture_query_set, array, postureQueries, __VA_ARGS__) \
XX(is_mfa_required, model_bool, none, isMfaRequired, __VA_ARGS__) \
XX(is_mfa_complete, model_bool, none, isMfaComplete, __VA_ARGS__) \
XX(is_cert_extendable, model_bool, none, isCertExtendable, __VA_ARGS__) \
XX(auth_queries, ziti_auth_query_mfa, list, authQueries, __VA_ARGS__) \
XX(authenticator_id, model_string, none, authenticatorId, __VA_ARGS__)

#define ZITI_ERROR_MODEL(XX, ...) \
XX(err, model_number, none, , __VA_ARGS__) \
XX(http_code, model_number, none, , __VA_ARGS__) \
XX(code, model_string, none, code, __VA_ARGS__) \
XX(message, model_string, none, message, __VA_ARGS__) \
XX(cause, json, map, cause, __VA_ARGS__)

#define ZITI_ENROLLMENT_JWT_HEADER_MODEL(XX, ...) \
XX(alg, jwt_sig_method, none, alg, __VA_ARGS__) \
XX(typ, model_string, none, typ, __VA_ARGS__)

#define JWT_SIG_METHOD(XX, ...) \
XX(RS256, __VA_ARGS__) \
XX(ES256, __VA_ARGS__) \
XX(ES384, __VA_ARGS__) \
XX(ES512, __VA_ARGS__)


#define ZITI_ENROLLMENT_METHOD(XX, ...) \
XX(network, __VA_ARGS__)                \
XX(ott, __VA_ARGS__)                    \
XX(ottca, __VA_ARGS__)                  \
XX(ca, __VA_ARGS__)


#define ZITI_NETWORK_JWT(XX, ...) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(token, model_string, none, token, __VA_ARGS__)

#define ZITI_ENROLLMENT_JWT_MODEL(XX, ...) \
XX(method, ziti_enrollment_method, none, em, __VA_ARGS__) \
XX(controller, model_string, none, iss, __VA_ARGS__)      \
XX(subject, model_string, none, sub, __VA_ARGS__)         \
XX(controllers, model_string, list, ctrls, __VA_ARGS__)   \
XX(token, model_string, none, jti, __VA_ARGS__)

#define ZITI_SDK_INFO_MODEL(XX, ...) \
XX(type, model_string, none, type, __VA_ARGS__) \
XX(version, model_string, none, version, __VA_ARGS__) \
XX(revision, model_string, none, revision, __VA_ARGS__) \
XX(branch, model_string, none, branch, __VA_ARGS__)   \
XX(app_id, model_string, none, appID, __VA_ARGS__)    \
XX(app_version, model_string, none, appVersion, __VA_ARGS__)

#define ZITI_ENV_INFO_MODEL(XX, ...) \
XX(os, model_string, none, os, __VA_ARGS__) \
XX(os_release, model_string, none, osRelease, __VA_ARGS__) \
XX(os_version, model_string, none, osVersion, __VA_ARGS__) \
XX(arch, model_string, none, arch, __VA_ARGS__)            \
XX(hostname, model_string, none, hostname, __VA_ARGS__)    \
XX(domain, model_string, none, domain, __VA_ARGS__)

#define ZITI_AUTH_REQ(XX, ...) \
XX(sdk_info, ziti_sdk_info, none, sdkInfo, __VA_ARGS__) \
XX(env_info, ziti_env_info, ptr, envInfo, __VA_ARGS__) \
XX(config_types, model_string, list, configTypes, __VA_ARGS__)

#define ZITI_ENROLLMENT_RESP(XX, ...) \
XX(cert, model_string, none, cert, __VA_ARGS__)

#define ZITI_PR_BASE(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(typeId, ziti_posture_query_type, none, typeId, __VA_ARGS__)

#define ZITI_PR_MAC_REQ(XX, ...) \
ZITI_PR_BASE(XX, __VA_ARGS__)  \
XX(mac_addresses, model_string, list, macAddresses, __VA_ARGS__)

#define ZITI_PR_DOMAIN_REQ(XX, ...) \
ZITI_PR_BASE(XX, __VA_ARGS__)  \
XX(domain, model_string, none, domain, __VA_ARGS__)

#define ZITI_PR_OS_REQ(XX, ...) \
ZITI_PR_BASE(XX, __VA_ARGS__)  \
XX(type, model_string, none, type, __VA_ARGS__) \
XX(version, model_string, none, version, __VA_ARGS__) \
XX(build, model_string, none, build, __VA_ARGS__)

#define ZITI_PR_PROCESS(XX, ...) \
XX(is_running, model_bool, none, isRunning, __VA_ARGS__) \
XX(hash, model_string, none, hash, __VA_ARGS__) \
XX(signer, model_string, none, signerFingerprint, __VA_ARGS__)

#define ZITI_PR_PROCESS_REQ(XX, ...) \
ZITI_PR_BASE(XX, __VA_ARGS__)  \
XX(path, model_string, none, path, __VA_ARGS__) \
XX(is_running, model_bool, none, isRunning, __VA_ARGS__) \
XX(hash, model_string, none, hash, __VA_ARGS__) \
XX(signers, model_string, list, signerFingerprints, __VA_ARGS__)

#define ZITI_PR_ENDPOINT_STATE_REQ(XX, ...) \
ZITI_PR_BASE(XX, __VA_ARGS__)  \
XX(unlocked, model_bool, none, unlocked, __VA_ARGS__) \
XX(woken, model_bool, none, woken, __VA_ARGS__)

#define ZITI_AUTH_QUERY_MFA_MODEL(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(type_id, ziti_auth_query_type, none, typeId, __VA_ARGS__) \
XX(provider, model_string, none, provider, __VA_ARGS__) \
XX(http_method, model_string, none, httpMethod, __VA_ARGS__) \
XX(http_url, model_string, none, httpUrl, __VA_ARGS__) \
XX(min_length, model_number, none, minLength, __VA_ARGS__) \
XX(max_length, model_number, none, maxLength, __VA_ARGS__) \
XX(format, model_string, none, format, __VA_ARGS__)

#define ZITI_SERVICE_TIMER(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(posture_query_type, model_string, none, postureQueryType, __VA_ARGS__) \
XX(timeout, model_number, ptr, timeout, __VA_ARGS__) \
XX(timeoutRemaining, model_number, ptr, timeoutRemaining, __VA_ARGS__)

#define ZITI_PR_RESPONSE(XX, ...) \
XX(services, ziti_service_timer, array, services, __VA_ARGS__)

#define ZITI_SERVICE_UPDATE(XX, ...) \
XX(last_change, model_string, none, lastChangeAt, __VA_ARGS__)

#define ZITI_MFA_CODE_REQ(XX, ...) \
XX(code, model_string, none, code, __VA_ARGS__)

#define ZITI_MFA_RECOVERY_CODES_MODEL(XX, ...) \
XX(recovery_codes, model_string, array, recoveryCodes, __VA_ARGS__)

#define ZITI_EXTEND_CERT_AUTHENTICATOR_REQ(XX, ...) \
XX(client_cert_csr, model_string, none, clientCertCsr, __VA_ARGS__)

#define ZITI_CREATE_API_CERT_REQ(XX, ...) \
XX(client_cert_csr, model_string, none, csr, __VA_ARGS__)

#define ZITI_VERIFY_EXTEND_CERT_AUTHENTICATOR_REQ(XX, ...) \
XX(client_cert, model_string, none, clientCert, __VA_ARGS__)

#define ZITI_EXTEND_CERT_AUTHENTICATOR_RESP(XX, ...) \
XX(client_cert_pem, model_string, none, clientCert, __VA_ARGS__) \
XX(cas_pem, model_string, none, ca, __VA_ARGS__)

#define ZITI_CREATE_API_CERT_RESP(XX, ...) \
XX(client_cert_pem, model_string, none, certificate, __VA_ARGS__) \
XX(cas_pem, model_string, none, cas, __VA_ARGS__)

#define ZITI_AUTHENTICATOR_MODEL(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(method, model_string, none, method, __VA_ARGS__) \
XX(identity_id, model_string, none, identityId, __VA_ARGS__) \
XX(cert_pem, model_string, none, certPem, __VA_ARGS__) \
XX(fingerprint, model_string, none, fingerprint, __VA_ARGS__)

#define API_ADDRESS_MODEL(XX, ...) \
XX(url, model_string, none, url, __VA_ARGS__) \
XX(version, model_string, none, version, __VA_ARGS__)

#define CTRL_APIS_MODEL(XX, ...) \
XX(edge, api_address, list, edge-client, __VA_ARGS__) \
XX(oidc, api_address, list, edge-oidc, __VA_ARGS__)

#define ZITI_CONTROLLER_DETAIL(XX, ...) \
XX(id, model_string, none, id, __VA_ARGS__) \
XX(name, model_string, none, name, __VA_ARGS__) \
XX(apis, ctrl_apis, none, apiAddresses, __VA_ARGS__) \
XX(is_online, model_bool, none, isOnline, __VA_ARGS__) \
XX(offline_time, model_number, none, , __VA_ARGS__) \
XX(cert_pem, model_string, none, certPem, __VA_ARGS__) \
XX(fingerprint, model_string, none, fingerprint, __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_ENUM(ziti_enrollment_method, ZITI_ENROLLMENT_METHOD)
DECLARE_ENUM(jwt_sig_method, JWT_SIG_METHOD)

DECLARE_MODEL(ziti_identity_data, ZITI_IDENTITY_DATA_MODEL)

DECLARE_MODEL(ziti_er_protocols, ZITI_ER_PROTOCOLS)

DECLARE_MODEL(ziti_edge_router, ZITI_EDGE_ROUTER_MODEL)

DECLARE_MODEL(ziti_service_routers, ZITI_SERVICE_EDGE_ROUTERS_MODEL)

DECLARE_MODEL(ziti_session, ZITI_SESSION_MODEL)

DECLARE_MODEL(ziti_api_session, ZITI_API_SESSION_MODEL)

DECLARE_MODEL(ziti_error, ZITI_ERROR_MODEL)

DECLARE_MODEL(ziti_enrollment_jwt_header, ZITI_ENROLLMENT_JWT_HEADER_MODEL)

DECLARE_MODEL(ziti_enrollment_jwt, ZITI_ENROLLMENT_JWT_MODEL)

DECLARE_MODEL(ziti_network_jwt, ZITI_NETWORK_JWT)

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

DECLARE_MODEL(ziti_auth_query_mfa, ZITI_AUTH_QUERY_MFA_MODEL)

DECLARE_MODEL(ziti_service_update, ZITI_SERVICE_UPDATE)

DECLARE_MODEL(ziti_mfa_code_req, ZITI_MFA_CODE_REQ)

DECLARE_MODEL(ziti_mfa_recovery_codes, ZITI_MFA_RECOVERY_CODES_MODEL)

DECLARE_MODEL(ziti_service_timer, ZITI_SERVICE_TIMER)

DECLARE_MODEL(ziti_pr_response, ZITI_PR_RESPONSE)

DECLARE_MODEL(ziti_extend_cert_authenticator_req, ZITI_EXTEND_CERT_AUTHENTICATOR_REQ)

DECLARE_MODEL(ziti_verify_extend_cert_authenticator_req, ZITI_VERIFY_EXTEND_CERT_AUTHENTICATOR_REQ)

DECLARE_MODEL(ziti_authenticator, ZITI_AUTHENTICATOR_MODEL)

DECLARE_MODEL(ziti_extend_cert_authenticator_resp, ZITI_EXTEND_CERT_AUTHENTICATOR_RESP)

DECLARE_MODEL(ziti_create_api_cert_req, ZITI_CREATE_API_CERT_REQ)

DECLARE_MODEL(ziti_create_api_cert_resp, ZITI_CREATE_API_CERT_RESP)

DECLARE_MODEL(api_address, API_ADDRESS_MODEL)

DECLARE_MODEL(ctrl_apis, CTRL_APIS_MODEL)

DECLARE_MODEL(ziti_controller_detail, ZITI_CONTROLLER_DETAIL)

DECLARE_MODEL(ziti_pr_base, ZITI_PR_BASE)

bool ziti_has_capability(const ziti_version *v, ziti_ctrl_cap c);

#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_INTERNAL_MODEL_H
