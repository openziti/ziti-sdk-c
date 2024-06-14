// Copyright (c) 2019-2024. NetFoundry Inc.
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

#include "auth_queries.h"

const char *AUTH_QUERY_TYPE_MFA = "MFA";
const char *MFA_PROVIDER_ZITI = "ziti";

struct ziti_mfa_auth_ctx_s {
    ziti_context ztx;

    ziti_mfa_cb cb;
    void *cb_ctx;

    ziti_auth_query_mfa *auth_query_mfa;
    bool auth_attempted;

    char *code;
};

struct ziti_mfa_enroll_cb_ctx_s {
    ziti_context ztx;
    ziti_mfa_enroll_cb cb;
    void *cb_ctx;
};
typedef struct ziti_mfa_enroll_cb_ctx_s ziti_mfa_enroll_cb_ctx;

struct ziti_mfa_recovery_codes_cb_ctx_s {
    ziti_context ztx;
    ziti_mfa_recovery_codes_cb cb;
    void *cb_ctx;
    char *code;
};
typedef struct ziti_mfa_recovery_codes_cb_ctx_s ziti_mfa_recovery_codes_cb_ctx;

struct ziti_mfa_cb_ctx_s {
    ziti_context ztx;
    ziti_mfa_cb cb;
    void *cb_ctx;
    char *code;
};
typedef struct ziti_mfa_cb_ctx_s ziti_mfa_cb_ctx;

static void ziti_mfa_auth_internal_cb(void *empty, const ziti_error *err, void *ctx);

static void ziti_auth_query_mfa_process(ziti_mfa_auth_ctx *mfa_auth_ctx);

static void ziti_mfa_re_auth_internal_cb(ziti_api_session *session, const ziti_error *err, void *ctx);

static void ziti_mfa_verify_internal_cb(void *empty, const ziti_error *err, void *ctx);

static void ziti_mfa_enroll_get_internal_cb(ziti_mfa_enrollment *mfa_enrollment, const ziti_error *err, void *ctx);

char *ziti_mfa_code_body(const char *code) {
    ziti_mfa_code_req req = {0};
    req.code = (char*)code;
    size_t len;
    char *body = ziti_mfa_code_req_to_json(&req, 0, &len);
    return body;
}

extern void ziti_auth_query_init(ziti_context ztx) {
    if (ztx->auth_queries == NULL) {
        NEWP(aq, struct auth_queries);
        aq->outstanding_auth_query_ctx = NULL;
        ztx->auth_queries = aq;
    }
}

extern void ziti_auth_query_free(struct auth_queries *aq) {
    FREE(aq);
}

static void mfa_cb(ziti_context ztx, int status) {
    if (ztx->mfa_cb) {
        ztx->mfa_cb(ztx, status, ztx->mfa_ctx);
    }

    ztx->mfa_cb = NULL;
    ztx->mfa_ctx = NULL;
}

void ziti_mfa_auth(ziti_context ztx, const char *code, ziti_mfa_cb status_cb, void *status_ctx) {
    if (code == NULL) {
        ZTX_LOG(ERROR, "unexpected NULL MFA code");
        status_cb(ztx, ZITI_WTF, status_ctx);
    }

    if (ztx->mfa_cb != NULL) {
        ZTX_LOG(ERROR, "unexpected state MFA is already in progress");
        status_cb(ztx, ZITI_INVALID_STATE, status_ctx);
    }

    ztx->mfa_cb = status_cb;
    ztx->mfa_ctx = status_ctx;

    ztx->auth_method->submit_mfa(ztx->auth_method, code, (auth_mfa_cb) mfa_cb);
}

void ziti_auth_query_mfa_process(ziti_mfa_auth_ctx *mfa_auth_ctx) {
    if (mfa_auth_ctx->ztx->auth_queries->outstanding_auth_query_ctx == NULL) {
        mfa_auth_ctx->ztx->auth_queries->outstanding_auth_query_ctx = mfa_auth_ctx;

        ziti_event_t ev = {
                .type = ZitiMfaAuthEvent,
                .mfa_auth_event = {
                        .auth_query_mfa = mfa_auth_ctx->auth_query_mfa,
                }
        };

        ziti_send_event(mfa_auth_ctx->ztx, &ev);
    } else {
        FREE(mfa_auth_ctx);
    }
}

void ziti_mfa_enroll_post_internal_cb(void *empty, const ziti_error *err, void *ctx) {
    ziti_mfa_enroll_cb_ctx *mfa_enroll_cb_ctx = ctx;
    ziti_context ztx = mfa_enroll_cb_ctx->ztx;

    if (err == NULL) {
        ziti_ctrl_get_mfa(ztx_get_controller(ztx), ziti_mfa_enroll_get_internal_cb, ctx);
    } else {
        ZTX_LOG(ERROR, "error during create MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_enroll_cb_ctx->cb(mfa_enroll_cb_ctx->ztx, err->err, NULL, mfa_enroll_cb_ctx->cb_ctx);
        FREE(ctx);
    }
}

void ziti_mfa_enroll_get_internal_cb(ziti_mfa_enrollment *mfa_enrollment, const ziti_error *err, void *ctx) {
    ziti_mfa_enroll_cb_ctx *mfa_enroll_cb_ctx = ctx;
    ziti_context ztx = mfa_enroll_cb_ctx->ztx;

    if (err != NULL) {
        if (err->http_code != 404) {
            ZTX_LOG(ERROR, "error during enroll MFA call: %d - %s - %s", err->http_code, err->code, err->message);
            mfa_enroll_cb_ctx->cb(mfa_enroll_cb_ctx->ztx, err->err, NULL, mfa_enroll_cb_ctx->cb_ctx);
            FREE(ctx);
            return;
        }
    }

    if (mfa_enrollment == NULL) {
        ziti_ctrl_post_mfa(ztx_get_controller(ztx), ziti_mfa_enroll_post_internal_cb, ctx);
    } else {
        mfa_enroll_cb_ctx->cb(ztx, ZITI_OK, mfa_enrollment, mfa_enroll_cb_ctx->cb_ctx);
        FREE(ctx);
        free_ziti_mfa_enrollment(mfa_enrollment);
    }
}

void ziti_mfa_enroll(ziti_context ztx, ziti_mfa_enroll_cb enroll_cb, void *ctx) {
    if (!ztx->enabled) {
        enroll_cb(ztx, ZITI_DISABLED, NULL, ctx);
        return;
    }

    NEWP(mfa_enroll_cb_ctx, ziti_mfa_enroll_cb_ctx);

    mfa_enroll_cb_ctx->ztx = ztx;
    mfa_enroll_cb_ctx->cb = enroll_cb;
    mfa_enroll_cb_ctx->cb_ctx = ctx;

    ziti_ctrl_get_mfa(ztx_get_controller(ztx), ziti_mfa_enroll_get_internal_cb, mfa_enroll_cb_ctx);
}

void ziti_mfa_remove_internal_cb(void *empty, const ziti_error *err, void *ctx) {
    ziti_mfa_cb_ctx *mfa_cb_ctx = ctx;
    ziti_context ztx = mfa_cb_ctx->ztx;

    if (err != NULL) {
        ZTX_LOG(ERROR, "error during remove MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, err->err, mfa_cb_ctx->cb_ctx);
    } else {
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, ZITI_OK, mfa_cb_ctx->cb_ctx);
    }

    FREE(mfa_cb_ctx->code);
    FREE(ctx);
}

void ziti_mfa_remove(ziti_context ztx, char *code, ziti_mfa_cb remove_cb, void *ctx) {
    if (!ztx->enabled) {
        remove_cb(ztx, ZITI_DISABLED, ctx);
        return;
    }

    NEWP(mfa_cb_ctx, ziti_mfa_cb_ctx);
    mfa_cb_ctx->ztx = ztx;
    mfa_cb_ctx->cb = remove_cb;
    mfa_cb_ctx->cb_ctx = ctx;
    mfa_cb_ctx->code = strdup(code);

    ziti_ctrl_delete_mfa(ztx_get_controller(ztx), mfa_cb_ctx->code, ziti_mfa_remove_internal_cb, mfa_cb_ctx);
}

void ziti_mfa_verify_internal_cb(void *empty, const ziti_error *err, void *ctx) {
    ziti_mfa_cb_ctx *mfa_cb_ctx = ctx;
    ziti_context ztx = mfa_cb_ctx->ztx;

    if (err != NULL) {
        ZTX_LOG(ERROR, "error during verify MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, err->err, mfa_cb_ctx->cb_ctx);
    } else {
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, ZITI_OK, mfa_cb_ctx->cb_ctx);
    }

    FREE(ctx);
}

void ziti_mfa_verify(ziti_context ztx, char *code, ziti_mfa_cb verify_cb, void *ctx) {
    if (!ztx->enabled) {
        verify_cb(ztx, ZITI_DISABLED, ctx);
        return;
    }

    NEWP(mfa_cb_ctx, ziti_mfa_cb_ctx);
    mfa_cb_ctx->ztx = ztx;
    mfa_cb_ctx->cb = verify_cb;
    mfa_cb_ctx->cb_ctx = ctx;

    char *body = ziti_mfa_code_body(code);

    ziti_ctrl_post_mfa_verify(ztx_get_controller(ztx), body, strlen(body), ziti_mfa_verify_internal_cb, mfa_cb_ctx);
}

void ziti_mfa_get_recovery_codes_internal_cb(ziti_mfa_recovery_codes *rc, const ziti_error *err, void *ctx) {
    ziti_mfa_recovery_codes_cb_ctx *mfa_recovery_codes_cb_ctx = ctx;
    ziti_context ztx = mfa_recovery_codes_cb_ctx->ztx;
    if (err != NULL) {
        ZTX_LOG(ERROR, "error during get recovery codes MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, err->err, NULL, mfa_recovery_codes_cb_ctx->cb_ctx);
    } else {
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, ZITI_OK, rc->recovery_codes, mfa_recovery_codes_cb_ctx->cb_ctx);
        free_ziti_mfa_recovery_codes(rc);
    }

    FREE(mfa_recovery_codes_cb_ctx->code);
    FREE(ctx);
}

void ziti_mfa_get_recovery_codes(ziti_context ztx, char *code, ziti_mfa_recovery_codes_cb get_cb, void *ctx) {
    if (!ztx->enabled) {
        get_cb(ztx, ZITI_DISABLED, NULL, ctx);
        return;
    }

    NEWP(mfa_rc_cb_ctx, ziti_mfa_recovery_codes_cb_ctx);
    mfa_rc_cb_ctx->ztx = ztx;
    mfa_rc_cb_ctx->cb = get_cb;
    mfa_rc_cb_ctx->cb_ctx = ctx;
    mfa_rc_cb_ctx->code = strdup(code);

    ziti_ctrl_get_mfa_recovery_codes(ztx_get_controller(ztx), mfa_rc_cb_ctx->code, ziti_mfa_get_recovery_codes_internal_cb, mfa_rc_cb_ctx);
}

void ziti_mfa_post_recovery_codes_internal_cb(void *empty, const ziti_error *err, void *ctx) {
    ziti_mfa_recovery_codes_cb_ctx *mfa_recovery_codes_cb_ctx = ctx;
    ziti_context ztx = mfa_recovery_codes_cb_ctx->ztx;

    if (err != NULL) {
        ZTX_LOG(ERROR, "error during create recovery codes MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, err->err, NULL, mfa_recovery_codes_cb_ctx->cb_ctx);
    } else {
        ziti_mfa_get_recovery_codes(mfa_recovery_codes_cb_ctx->ztx, mfa_recovery_codes_cb_ctx->code, mfa_recovery_codes_cb_ctx->cb,
                                    mfa_recovery_codes_cb_ctx->cb_ctx);
    }

    FREE(ctx);
}

void ziti_mfa_new_recovery_codes(ziti_context ztx, char *code, ziti_mfa_recovery_codes_cb new_cb, void *ctx) {
    if (!ztx->enabled) {
        new_cb(ztx, ZITI_DISABLED, NULL, ctx);
        return;
    }

    NEWP(mfa_rc_cb_ctx, ziti_mfa_recovery_codes_cb_ctx);
    mfa_rc_cb_ctx->ztx = ztx;
    mfa_rc_cb_ctx->cb = new_cb;
    mfa_rc_cb_ctx->cb_ctx = ctx;
    mfa_rc_cb_ctx->code = code;

    char *body = ziti_mfa_code_body(code);

    ziti_ctrl_post_mfa_recovery_codes(ztx_get_controller(ztx), body, strlen(body), ziti_mfa_post_recovery_codes_internal_cb, mfa_rc_cb_ctx);
}
