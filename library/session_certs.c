// Copyright (c) 2026.  NetFoundry Inc
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.

//
//

#include "zt_internal.h"

#ifdef _WIN32
#define timegm _mkgmtime
#endif
#include <time.h>


static void on_create_cert(ziti_create_api_cert_resp *resp, const ziti_error *e, void *ctx) {
    ziti_context ztx = ctx;
    if (e) {
        ZTX_LOG(ERROR, "failed to create session cert: %d/%s", (int)e->err, e->message);
    } else {
        ZTX_LOG(DEBUG, "received API session certificate");
        if (ztx->session_creds.cert) {
            ztx->session_creds.cert->free(ztx->session_creds.cert);
            ztx->session_creds.cert = NULL;
        }

        tlsuv_private_key_t pk = ztx->session_creds.key ? ztx->session_creds.key : ztx->id_creds.key;
        tlsuv_certificate_t cert;
        if (ztx->channel_tls->load_cert(&cert, resp->client_cert_pem, strlen(resp->client_cert_pem)) != 0) {
            ZTX_LOG(ERROR, "failed to parse supplied session cert");
        } else if (ztx->channel_tls->set_own_cert(ztx->channel_tls, pk, cert) != 0) {
            ZTX_LOG(ERROR, "failed to set session cert");
            // what to do here? this shouldn't happen
            cert->free(cert);
        } else {
            ztx->session_creds.cert = cert;
            ZTX_LOG(VERBOSE, "API session cert: %s", cert->get_text(cert));

            free_ziti_create_api_cert_resp_ptr(resp);
        }
    }

    if (ztx->session_creds.cert) {
        tlsuv_certificate_t cert = ztx->session_creds.cert;
        struct tm expire;
        uv_timeval64_t now;
        if (cert->get_expiration(cert, &expire) == 0 &&
            uv_gettimeofday(&now) == 0) {
            int64_t expires_in = timegm(&expire) - now.tv_sec;
            if (expires_in < 30) { // avoid churn near the end of cert validity
                // this happens if we failed to reach controller for a while
                ZTX_LOG(WARN, "current session cert already expired");
                expires_in = 30;
            } else {
                ZTX_LOG(DEBUG, "session cert expires in %" PRId64 " seconds", expires_in);
                expires_in = (expires_in * 2) / 3;
            }
            ztx_set_deadline(ztx, expires_in * 1000, &ztx->session_creds_deadline,
                             ztx_request_session_cert, ztx);
        }
    }
}

void ztx_request_session_cert(ziti_context ztx) {
    if (ztx->auth_state != ZitiAuthStateFullyAuthenticated) {
        ZTX_LOG(WARN, "not requesting session cert, auth_state is %d", ztx->auth_state);
        return;
    }

    ZTX_LOG(DEBUG, "requesting session certificate");
    char *csr = NULL;
    char common_name[65]; // X509.CN has a limit of 64 chars

    if (ztx->identity_data) {
        snprintf(common_name, sizeof(common_name), "%s-%" PRIu64,
                 ztx->identity_data->id, uv_now(ztx->loop));
    } else {
        snprintf(common_name, sizeof(common_name), "ziti-%u-%" PRIu64,
                 ztx->id, uv_now(ztx->loop));
    }

    ZTX_LOG(DEBUG, "creating session CSR with CN=%s", common_name);
    size_t csr_len;
    int rc = ztx->channel_tls->generate_csr_to_pem(ztx->session_creds.key, &csr, &csr_len,
                                                   "O", "OpenZiti",
                                                   "OU", "ziti-sdk",
                                                   "CN", common_name,
                                                   NULL);
    if (rc != 0) {
        ZTX_LOG(ERROR, "failed to generate CSR for session cert");
    } else {
        ZTX_LOG(DEBUG, "sending CSR to sign");
        ZTX_LOG(DEBUG, "%.*s", (int)csr_len, csr);
        ziti_ctrl_create_api_certificate(ztx_get_controller(ztx), csr, on_create_cert, ztx);
    }
    free(csr);
}

void ztx_clear_session_creds(ziti_context ztx) {
    if (ztx->session_creds.cert || ztx->session_creds.key) {
        if (ztx->channel_tls) {
            ztx->channel_tls->set_own_cert(ztx->tlsCtx, NULL, NULL);
        }

        if (ztx->session_creds.cert) {
            ztx->session_creds.cert->free(ztx->session_creds.cert);
            ztx->session_creds.cert = NULL;
        }

        if (ztx->session_creds.key) {
            ztx->session_creds.key->free(ztx->session_creds.key);
            ztx->session_creds.key = NULL;
        }
    }
    clear_deadline(&ztx->session_creds_deadline);
}
