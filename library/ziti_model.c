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


#include <ziti_model.h>
#include <old_model_impl.h>

MODEL_IMPL(ziti_service, ZITI_SERVICE_MODEL)
MODEL_IMPL(nf_config, ZITI_CONFIG_MODEL)

MODEL_IMPL(ziti_edge_router, ZITI_EDGE_ROUTER_MODEL)
MODEL_IMPL(ziti_net_session, ZITI_NET_SESSION_MODEL)

MODEL_IMPL(ctrl_version, ZITI_CTRL_VERSION)

MODEL_IMPL(ziti_session, ZITI_SESSION_MODEL)

MODEL_IMPL(ziti_identity, ZITI_IDENTITY_MODEL)

MODEL_IMPL(ziti_error, ZITI_ERROR_MODEL)

MODEL_IMPL(ziti_enrollment_jwt_header, ZITI_ENROLLMENT_JWT_HEADER_MODEL)
MODEL_IMPL(ziti_enrollment_jwt, ZITI_ENROLLMENT_JWT_MODEL)
