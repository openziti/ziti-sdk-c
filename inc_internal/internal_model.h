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

#define ZITI_ID_CFG_MODEL(XX, ...) \
XX(cert, string, none, cert, __VA_ARGS__) \
XX(key, string, none, key, __VA_ARGS__) \
XX(ca, string, none, ca, __VA_ARGS__)

#define ZITI_CONFIG_MODEL(XX, ...) \
XX(controller_url, string, none, ztAPI, __VA_ARGS__) \
XX(id, ziti_id_cfg, none, id, __VA_ARGS__)

#define ZITI_INGRESS_MODEL(XX, ...) \
XX(tls, string, none, tls, __VA_ARGS__)

#define ZITI_EDGE_ROUTER_MODEL(XX, ...)\
XX(name, string, none, name, __VA_ARGS__)\
XX(hostname, string, none, hostname, __VA_ARGS__) \
XX(ingress, ziti_ingress, none, urls, __VA_ARGS__)

#define ZITI_NET_SESSION_MODEL(XX, ...) \
XX(token, string, none, token, __VA_ARGS__)\
XX(id, string, none, id, __VA_ARGS__) \
XX(session_type, string, none, type, __VA_ARGS__) \
XX(edge_routers, ziti_edge_router, array, edgeRouters, __VA_ARGS__) \
XX(service_id, string, none, NULL, __VA_ARGS__)

#define ZITI_SESSION_MODEL(XX, ...)\
XX(id, string, none, id, __VA_ARGS__) \
XX(token, string, none, token, __VA_ARGS__) \
XX(expires, timestamp, ptr, expiresAt, __VA_ARGS__)\
XX(identity, ziti_identity, ptr, identity, __VA_ARGS__)

#define ZITI_ERROR_MODEL(XX, ...) \
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

#define ZITI_ENROLLMENT_RESP(XX, ...) \
XX(cert, string, none, cert, __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif


DECLARE_MODEL(ziti_id_cfg, ZITI_ID_CFG_MODEL)

DECLARE_MODEL(ziti_config, ZITI_CONFIG_MODEL)


DECLARE_MODEL(ziti_ingress, ZITI_INGRESS_MODEL)

DECLARE_MODEL(ziti_edge_router, ZITI_EDGE_ROUTER_MODEL)

DECLARE_MODEL(ziti_net_session, ZITI_NET_SESSION_MODEL)

DECLARE_MODEL(ziti_session, ZITI_SESSION_MODEL)

DECLARE_MODEL(ziti_error, ZITI_ERROR_MODEL)

DECLARE_MODEL(ziti_enrollment_jwt_header, ZITI_ENROLLMENT_JWT_HEADER_MODEL)
DECLARE_MODEL(ziti_enrollment_jwt, ZITI_ENROLLMENT_JWT_MODEL)

DECLARE_MODEL(ziti_enrollment_resp, ZITI_ENROLLMENT_RESP)

#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_INTERNAL_MODEL_H
