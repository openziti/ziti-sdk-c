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

#include "model.h"

#define ZITI_CTRL_VERSION(XX) \
XX(version, string, none, version) \
XX(revision, string, none, revision) \
XX(build_date, string, none, buildDate)

#define ZITI_SERVICE_MODEL(XX) \
XX(id, string, none, id) \
XX(name, string, none, name) \
XX(dns_host, string, none, dns.hostname) \
XX(dns_port, int, none, dns.port) \
XX(permissions, string, array, permissions) \
XX(perm_flags, int, none, NULL)

#define ZITI_CONFIG_MODEL(XX) \
XX(controller_url, string, none, ztAPI) \
XX(cert, string, none, id.cert) \
XX(key, string, none, id.key) \
XX(ca, string, none, id.ca)

#define ZITI_EDGE_ROUTER_MODEL(XX)\
XX(name, string, none, name)\
XX(hostname, string, none, hostname) \
XX(url_tls, string, none, urls.tls)

#define ZITI_NET_SESSION_MODEL(XX) \
XX(token, string, none, token)\
XX(id, string, none, id) \
XX(session_type, string, none, type) \
XX(edge_routers, ziti_edge_router, array, edgeRouters) \
XX(service_id, string, none, NULL)

#define ZITI_SESSION_MODEL(XX)\
XX(id, string, none, id) \
XX(token, string, none, token) \
XX(expires, timeval_t, ptr, expiresAt)\
XX(identity, ziti_identity, ptr, identity)

#define ZITI_IDENTITY_MODEL(XX) \
XX(id, string, none, id) \
XX(name, string, none, name)

#define ZITI_ERROR_MODEL(XX) \
XX(code, string, none, code) \
XX(message, string, none, message)

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MODEL(ctrl_version, ZITI_CTRL_VERSION)

DECLARE_MODEL(nf_config, ZITI_CONFIG_MODEL)
DECLARE_MODEL(ziti_service, ZITI_SERVICE_MODEL)

DECLARE_MODEL(ziti_edge_router, ZITI_EDGE_ROUTER_MODEL)
DECLARE_MODEL(ziti_net_session, ZITI_NET_SESSION_MODEL)

DECLARE_MODEL(ziti_identity, ZITI_IDENTITY_MODEL)
DECLARE_MODEL(ziti_session, ZITI_SESSION_MODEL)

DECLARE_MODEL(ziti_error, ZITI_ERROR_MODEL)

#ifdef __cplusplus
}
#endif
#endif //ZITI_SDK_ZITI_MODEL_H
