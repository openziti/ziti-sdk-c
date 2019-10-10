
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