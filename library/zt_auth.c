/*
Copyright 2019 Netfoundry, Inc.

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


#include <stdlib.h>

#include "utils.h"
#include "tls.h"
#include "zt_internal.h"
#include "controller.h"


int ziti_logout(struct nf_ctx* ctx) {
    PREPF(ziti, ziti_errorstr);
    ziti_ctrl_logout(ctx, 0, NULL);

    free_ziti_service_array(ctx->services);
    ctx->services = NULL;
    free_ziti_net_session_array(ctx->net_sessions);
    ctx->net_sessions = NULL;

    CATCH(ziti);
    return ZITI_OK;
}

int ziti_auth(struct nf_ctx *ctx) {
    PREPF(ziti, ziti_errorstr);

    TRY(ziti, ziti_ctrl_process(ctx,
            ziti_ctrl_version,
            ziti_ctrl_login,
            ziti_ctrl_get_services,
            ziti_ctrl_get_network_sessions,
            NULL));

    CATCH(ziti){
        return ERR(ziti);
    }

    return ZITI_OK;
}