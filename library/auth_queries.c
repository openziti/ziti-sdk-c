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
#include "posture.h"

#include <sodium/utils.h>

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

static void ziti_auth_query_mfa_process(ziti_mfa_auth_ctx *mfa_auth_ctx);

static void ziti_mfa_verify_internal_cb(void *empty, const ziti_error *err, void *ctx);

static void ziti_mfa_enroll_get_internal_cb(ziti_mfa_enrollment *mfa_enrollment, const ziti_error *err, void *ctx);

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
    if (status != ZITI_OK) {
        // the login did not take the code: nothing will need it
        ztx_mfa_drop_code(ztx);
    }

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
        return;
    }

    if (ztx->mfa_cb != NULL) {
        ZTX_LOG(ERROR, "unexpected state MFA is already in progress");
        status_cb(ztx, ZITI_INVALID_STATE, status_ctx);
        return;
    }

    bool oidc = ztx->auth_method->kind == OIDC;
    if (oidc && ztx->auth_state == ZitiAuthStateFullyAuthenticated) {
        // no login waits for a code (the identity passed TOTP earlier, a posture check needs it again, or came later):
        // the code goes to the controller for a TOTP token, which is what the routers take as proof
        ztx_mfa_request_totp_token(ztx, code, status_cb, status_ctx);
        return;
    }

    ztx->mfa_cb = status_cb;
    ztx->mfa_ctx = status_ctx;

    int err = ztx->auth_method->submit_mfa(ztx->auth_method, code, (auth_mfa_cb) mfa_cb);
    if (err != ZITI_OK) {
        ZTX_LOG(WARN, "failed to submit MFA code: %d/%s", err, ziti_errorstr(err));
        ztx->mfa_cb(ztx, err, ztx->mfa_ctx);
        ztx->mfa_cb = NULL;
        ztx->mfa_ctx = NULL;
    } else if (oidc) {
        ztx_mfa_keep_code(ztx, code);
    }
}

static void totp_token_cb(totp_token *token, const ziti_error *err, void *ctx) {
    ziti_mfa_cb_ctx *req = ctx;
    ziti_context ztx = req->ztx;

    int status;
    if (err != NULL) {
        ZTX_LOG(WARN, "failed to get a TOTP token: %d/%s", (int) err->err, err->message ? err->message : ziti_errorstr(err->err));
        status = (int) err->err;
    } else if (token == NULL) {
        ZTX_LOG(WARN, "the controller did not issue a TOTP token");
        status = ZITI_INVALID_STATE;
    } else {
        status = ztx_posture_set_totp_token(ztx, token->token);
        if (status == ZITI_OK) {
            ZTX_LOG(DEBUG, "the TOTP token of the api session is in place");
            ztx_posture_send_all(ztx);
        } else {
            ZTX_LOG(WARN, "the TOTP token of the controller is unusable: %d/%s", status, ziti_errorstr(status));
        }
    }

    if (req->cb) {
        req->cb(ztx, status, req->cb_ctx);
    }
    free_totp_token_ptr(token);
    FREE(req);
}

void ztx_mfa_request_totp_token(ziti_context ztx, const char *code, ziti_mfa_cb cb, void *ctx) {
    if (ztx->auth_state != ZitiAuthStateFullyAuthenticated) {
        ZTX_LOG(WARN, "cannot ask for a TOTP token: the context is not fully authenticated");
        if (cb) cb(ztx, ZITI_INVALID_STATE, ctx);
        return;
    }

    NEWP(req, ziti_mfa_cb_ctx);
    req->ztx = ztx;
    req->cb = cb;
    req->cb_ctx = ctx;
    ziti_ctrl_get_totp_token(ztx_get_controller(ztx), code, totp_token_cb, req);
}

void ztx_mfa_keep_code(ziti_context ztx, const char *code) {
    ztx_mfa_drop_code(ztx);
    cstr_assign(&ztx->totp_code, code);
}

void ztx_mfa_drop_code(ziti_context ztx) {
    cstr_drop(&ztx->totp_code);
    ztx->totp_code = cstr_init();
}

void ztx_mfa_token_for_login(ziti_context ztx) {
    if (cstr_is_empty(&ztx->totp_code)) {
        return;
    }

    // a failure is only logged: routers that seed MFA from the api session token do not need the token.
    // The body of the request has its own copy of the code by the time this returns.
    ztx_mfa_request_totp_token(ztx, cstr_str(&ztx->totp_code), NULL, NULL);
    ztx_mfa_drop_code(ztx);
}

void ziti_auth_query_mfa_process(ziti_mfa_auth_ctx *mfa_auth_ctx) {
    if (mfa_auth_ctx->ztx->auth_queries->outstanding_auth_query_ctx == NULL) {
        mfa_auth_ctx->ztx->auth_queries->outstanding_auth_query_ctx = mfa_auth_ctx;

        ziti_event_t ev = {
                .type = ZitiAuthEvent,
                .auth = {
                        .action = ziti_auth_prompt_totp,
                        .type = ziti_auth_query_types.name(mfa_auth_ctx->auth_query_mfa->type_id),
                        .detail = mfa_auth_ctx->auth_query_mfa->provider,
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
        ZTX_LOG(ERROR, "error during create MFA call: %d - %s - %s", (int)err->http_code, err->code, err->message);
        mfa_enroll_cb_ctx->cb(mfa_enroll_cb_ctx->ztx, (int)err->err, NULL, mfa_enroll_cb_ctx->cb_ctx);
        FREE(ctx);
    }
}

void ziti_mfa_enroll_get_internal_cb(ziti_mfa_enrollment *mfa_enrollment, const ziti_error *err, void *ctx) {
    assert(ctx != NULL);
    ziti_mfa_enroll_cb_ctx *mfa_enroll_cb_ctx = ctx;
    ziti_context ztx = mfa_enroll_cb_ctx->ztx;

    if (err != NULL) {
        if (err->http_code != 404) {
            ZTX_LOG(ERROR, "error during enroll MFA call: %d - %s - %s", (int)err->http_code, err->code, err->message);
            mfa_enroll_cb_ctx->cb(mfa_enroll_cb_ctx->ztx, (int)err->err, NULL, mfa_enroll_cb_ctx->cb_ctx);
            FREE(ctx);
            return;
        }
    }

    if (mfa_enrollment == NULL) {
        ziti_ctrl_post_mfa(ztx_get_controller(ztx), ziti_mfa_enroll_post_internal_cb, ctx);
    } else {
        mfa_enroll_cb_ctx->cb(ztx, ZITI_OK, mfa_enrollment, mfa_enroll_cb_ctx->cb_ctx);
        FREE(ctx);
        free_ziti_mfa_enrollment_ptr(mfa_enrollment);
    }
}

void ziti_mfa_enroll(ziti_context ztx, ziti_mfa_enroll_cb enroll_cb, void *ctx) {
    if (!ztx->enabled) {
        enroll_cb(ztx, ZITI_DISABLED, NULL, ctx);
        return;
    }

    if (!ztx->auth_method) {
        ZTX_LOG(ERROR, "cannot enroll MFA without an authentication method");
        enroll_cb(ztx, ZITI_INVALID_STATE, NULL, ctx);
        return;
    }

    NEWP(mfa_enroll_cb_ctx, ziti_mfa_enroll_cb_ctx);

    mfa_enroll_cb_ctx->ztx = ztx;
    mfa_enroll_cb_ctx->cb = enroll_cb;
    mfa_enroll_cb_ctx->cb_ctx = ctx;

    // OIDC auth supports MFA enrollment only during the authentication flow
    if (ztx->auth_method->enroll_mfa) {
        int rc = ztx->auth_method->enroll_mfa(ztx->auth_method, ziti_mfa_enroll_get_internal_cb, mfa_enroll_cb_ctx);
        if (rc == ZITI_OK) {
            return;
        }
        if (rc != ZITI_INVALID_STATE) {
            ZTX_LOG(ERROR, "error initiating MFA enroll");
            enroll_cb(ztx, rc, NULL, ctx);
            FREE(mfa_enroll_cb_ctx);
            return;
        }
        // ZITI_INVALID_STATE means that OIDC auth is completed
        // so fallback to default implementation
    }


    ziti_ctrl_get_mfa(ztx_get_controller(ztx), ziti_mfa_enroll_get_internal_cb, mfa_enroll_cb_ctx);
}

// the controller reports the MFA state with the identity data: keep it right until that is loaded again
static void set_mfa_enrolled(ziti_context ztx, bool enrolled) {
    if (ztx->identity_data) {
        ztx->identity_data->is_mfa_enabled = enrolled;
    }
}

void ziti_mfa_remove_internal_cb(void *empty, const ziti_error *err, void *ctx) {
    ziti_mfa_cb_ctx *mfa_cb_ctx = ctx;
    ziti_context ztx = mfa_cb_ctx->ztx;

    if (err != NULL) {
        ZTX_LOG(ERROR, "error during remove MFA call: %d - %s - %s", (int)err->http_code, err->code, err->message);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, (int)err->err, mfa_cb_ctx->cb_ctx);
    } else {
        set_mfa_enrolled(ztx, false);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, ZITI_OK, mfa_cb_ctx->cb_ctx);
    }

    FREE(mfa_cb_ctx->code);
    FREE(ctx);
}

void ziti_mfa_remove(ziti_context ztx, const char *code, ziti_mfa_cb remove_cb, void *ctx) {
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

static void wipe_code(char *code) {
    if (code != NULL) {
        sodium_memzero(code, strlen(code));
        free(code);
    }
}

void ziti_mfa_verify_internal_cb(void *empty, const ziti_error *err, void *ctx) {
    ziti_mfa_cb_ctx *mfa_cb_ctx = ctx;
    ziti_context ztx = mfa_cb_ctx->ztx;

    if (err != NULL) {
        ZTX_LOG(ERROR, "error during verify MFA call: %d - %s - %s", (int)err->http_code, err->code, err->message);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, (int)err->err, mfa_cb_ctx->cb_ctx);
    } else {
        set_mfa_enrolled(ztx, true);
        // the controller passes the MFA of the api session now: the routers need the token of the code to do the same
        if (mfa_cb_ctx->code != NULL) {
            if (ztx->auth_state == ZitiAuthStateFullyAuthenticated) {
                // an enrollment verified after the login: no login took the code
                ztx_mfa_request_totp_token(ztx, mfa_cb_ctx->code, NULL, NULL);
            } else {
                // a login took the code: the api session it creates is not there yet
                ztx_mfa_keep_code(ztx, mfa_cb_ctx->code);
            }
        }
        ziti_force_api_session_refresh(ztx);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, ZITI_OK, mfa_cb_ctx->cb_ctx);
    }

    wipe_code(mfa_cb_ctx->code);
    FREE(ctx);
}

void ziti_mfa_verify(ziti_context ztx, const char *code, ziti_mfa_cb verify_cb, void *ctx) {
    if (!ztx->enabled) {
        verify_cb(ztx, ZITI_DISABLED, ctx);
        return;
    }
    
    if (!ztx->auth_method) {
        ZTX_LOG(ERROR, "cannot verify MFA without an authentication method");
        verify_cb(ztx, ZITI_INVALID_STATE, ctx);
        return;
    }
    
    NEWP(mfa_cb_ctx, ziti_mfa_cb_ctx);
    mfa_cb_ctx->ztx = ztx;
    mfa_cb_ctx->cb = verify_cb;
    mfa_cb_ctx->cb_ctx = ctx;
    if (code != NULL && ztx->auth_method->kind == OIDC) {
        mfa_cb_ctx->code = strdup(code);
    }
    if (ztx->auth_method->verify_mfa) {
        int rc = ztx->auth_method->verify_mfa(ztx->auth_method, code, ziti_mfa_verify_internal_cb, mfa_cb_ctx);
        if (rc == ZITI_OK) {
            // verify request in progress
            return;
        }

        if (rc != ZITI_INVALID_STATE) {
            ZTX_LOG(ERROR, "error initiating MFA verify");
            verify_cb(ztx, rc, ctx);
            wipe_code(mfa_cb_ctx->code);
            free(mfa_cb_ctx);
            return;
        }
        
        // if rc == ZITI_INVALID_STATE then fallback to default
    }
    ziti_ctrl_post_mfa_verify(ztx_get_controller(ztx), code, ziti_mfa_verify_internal_cb, mfa_cb_ctx);
}

void ziti_mfa_get_recovery_codes_internal_cb(ziti_mfa_recovery_codes *rc, const ziti_error *err, void *ctx) {
    ziti_mfa_recovery_codes_cb_ctx *mfa_recovery_codes_cb_ctx = ctx;
    ziti_context ztx = mfa_recovery_codes_cb_ctx->ztx;
    if (err != NULL) {
        ZTX_LOG(ERROR, "error during get recovery codes MFA call: %d - %s - %s",
                (int)err->http_code, err->code, err->message);
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, (int)err->err, NULL,
                                      mfa_recovery_codes_cb_ctx->cb_ctx);
    } else {
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, ZITI_OK, rc->recovery_codes,
                                      mfa_recovery_codes_cb_ctx->cb_ctx);
        free_ziti_mfa_recovery_codes(rc);
    }

    FREE(mfa_recovery_codes_cb_ctx->code);
    FREE(ctx);
}

void ziti_mfa_get_recovery_codes(ziti_context ztx, const char *code, ziti_mfa_recovery_codes_cb get_cb, void *ctx) {
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
        ZTX_LOG(ERROR, "error during create recovery codes MFA call: %d - %s - %s",
                (int)err->http_code, err->code, err->message);
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, (int)err->err, NULL, mfa_recovery_codes_cb_ctx->cb_ctx);
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

    ziti_ctrl_post_mfa_recovery_codes(ztx_get_controller(ztx), code, ziti_mfa_post_recovery_codes_internal_cb, mfa_rc_cb_ctx);
}
