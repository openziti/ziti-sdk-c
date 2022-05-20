/*
Copyright (c) 2019-2020 NetFoundry, Inc.

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

#include "authenticators.h"

typedef struct authenticator_ctx_s {
    ziti_context ztx;
    ziti_extend_cert_authenticator_cb extend_cb;
    ziti_verify_extend_cert_authenticator_cb verify_cb;
    void* ctx;
    char* csr_pem;
    char* authenticator_id;
} authenticator_ctx;

const char* CAN_NOT_UPDATE_AUTHENTICATOR = "CAN_NOT_UPDATE_AUTHENTICATOR";
const char* UNAUTHORIZED = "UNAUTHORIZED";

static void extend_cb(ziti_extend_cert_authenticator_resp* resp, const ziti_error* err, void* ctx) {
    authenticator_ctx* wrapped_ctx = (authenticator_ctx*)ctx;
    ziti_context ztx = wrapped_ctx->ztx;

    if(err){
        ZTX_LOG(ERROR, "error response returned when attempting to extend authenticator: %d %s: %s, calling cb", err->http_code, err->code, err->message);
        if(err->http_code == 404) {
            wrapped_ctx->extend_cb(ztx, NULL, ZITI_NOT_FOUND, wrapped_ctx->ctx);
        } else if(strncmp(err->code, CAN_NOT_UPDATE_AUTHENTICATOR, strlen(CAN_NOT_UPDATE_AUTHENTICATOR)) == 0){
            wrapped_ctx->extend_cb(ztx, NULL, ZITI_INVALID_AUTHENTICATOR_TYPE, wrapped_ctx->ctx);
        } else if (strncmp(err->code, UNAUTHORIZED, strlen(UNAUTHORIZED)) == 0){
            wrapped_ctx->extend_cb(ztx, NULL, ZITI_INVALID_AUTHENTICATOR_CERT, wrapped_ctx->ctx);
        } else {
            wrapped_ctx->extend_cb(ztx, NULL, ZITI_WTF, wrapped_ctx->ctx);
        }

        return;
    } else {
        ZTX_LOG(INFO, "certificate authenticator extension occurred for id: %s, calling cb", wrapped_ctx->authenticator_id);
        wrapped_ctx->extend_cb(ztx, resp->client_cert_pem, ZITI_OK, wrapped_ctx->ctx);
    }

    FREE(wrapped_ctx->authenticator_id);
    FREE(wrapped_ctx->csr_pem);
    FREE(wrapped_ctx);

    free_ziti_extend_cert_authenticator_resp(resp);
}

static void verify_cb(void* empty, const ziti_error* err, void* ctx){
    authenticator_ctx* wrapped_ctx = (authenticator_ctx*)ctx;
    ziti_context ztx = wrapped_ctx->ztx;

    if(err) {
        ZTX_LOG(ERROR, "error response returned when attempting to verify extended authenticator: %d %s: %s", err->http_code, err->code, err->message);
        if(err->http_code == 404) {
            wrapped_ctx->verify_cb(ztx, ZITI_NOT_FOUND, wrapped_ctx->ctx);
        } else if(strncmp(err->code, CAN_NOT_UPDATE_AUTHENTICATOR, strlen(CAN_NOT_UPDATE_AUTHENTICATOR)) == 0){
            wrapped_ctx->verify_cb(ztx, ZITI_INVALID_AUTHENTICATOR_TYPE, wrapped_ctx->ctx);
        } else if (strncmp(err->code, UNAUTHORIZED, strlen(UNAUTHORIZED)) == 0){
            wrapped_ctx->verify_cb(ztx, ZITI_INVALID_AUTHENTICATOR_CERT, wrapped_ctx->ctx);
        } else {
            wrapped_ctx->verify_cb(ztx, ZITI_WTF, wrapped_ctx->ctx);
        }
    } else {
        ZTX_LOG(INFO, "certificate authenticator extension verified successfully for id: %s, raising event", wrapped_ctx->authenticator_id);
        wrapped_ctx->verify_cb(ztx, ZITI_OK, wrapped_ctx->ctx);
    }

    FREE(wrapped_ctx->authenticator_id);
    FREE(wrapped_ctx);
}

int ziti_extend_cert_authenticator(ziti_context ztx, const char *csr_pem, ziti_extend_cert_authenticator_cb cb, void *ctx) {
    if(ztx->api_session == NULL){
        return ZITI_INVALID_STATE;
    }

    ZTX_LOG(INFO, "attempting to extend certificate authenticator id: %s", ztx->api_session->authenticator_id);
    NEWP(wrapped_ctx, authenticator_ctx);
    wrapped_ctx->ztx = ztx;
    wrapped_ctx->ctx = ctx;
    wrapped_ctx->extend_cb = cb;
    wrapped_ctx->authenticator_id = strdup(ztx->api_session->authenticator_id);
    wrapped_ctx->csr_pem = strdup(csr_pem);

    ziti_ctrl_extend_cert_authenticator(&wrapped_ctx->ztx->controller, wrapped_ctx->authenticator_id,
                                        wrapped_ctx->csr_pem,
                                        extend_cb, wrapped_ctx);

    return ZITI_OK;
}

int ziti_verify_extend_cert_authenticator(ziti_context ztx, const char *new_cert, ziti_verify_extend_cert_authenticator_cb  cb, void *ctx) {
    if(ztx->api_session == NULL){
        return ZITI_INVALID_STATE;
    }

    ZTX_LOG(INFO, "attempting to verify certificate authenticator %s", ztx->api_session->authenticator_id);

    NEWP(wrapped_ctx, authenticator_ctx);
    wrapped_ctx->ztx = ztx;
    wrapped_ctx->ctx = ctx;
    wrapped_ctx->verify_cb = cb;
    wrapped_ctx->authenticator_id = strdup(ztx->api_session->authenticator_id);

    ziti_ctrl_verify_extend_cert_authenticator(&ztx->controller, wrapped_ctx->authenticator_id, new_cert, verify_cb, wrapped_ctx);

    return ZITI_OK;
}