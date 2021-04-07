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

#include "auth_queries.h"

const char *AUTH_QUERY_TYPE_MFA = "MFA";
const char *MFA_PROVIDER_ZITI = "ziti";

struct ziti_mfa_auth_ctx_s {
    ziti_context ztx;
    ziti_auth_query_mfa *query;

    void (*cb)(ziti_context);

    ziti_ar_mfa_status_cb status_cb;
    void *status_ctx;
};

typedef struct ziti_mfa_auth_ctx_s ziti_mfa_auth_ctx;

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

void ziti_auth_query_mfa_auth_internal_cb(void *empty, ziti_error *err, void *ctx);

void ziti_auth_query_mfa_process(ziti_mfa_auth_ctx *mfa_ctx);

char *ziti_mfa_code_body(char *code) {
    NEWP(code_req, ziti_mfa_code_req);
    code_req->code = code;

    size_t len;
    char* body = ziti_mfa_code_req_to_json(code_req, 0, &len);

    FREE(code_req)

    return body;
}

extern void ziti_auth_query_init(ziti_context ztx) {
    if (ztx->auth_queries == NULL) {
        NEWP(aq, struct auth_queries);
        aq->outstanding_auth_queries = false;
        aq->awaiting_mfa_cb = false;
        ztx->auth_queries = aq;
    }
}

extern void ziti_auth_query_free(struct auth_queries *aq) {
    FREE(aq)
}

void ziti_auth_query_mfa_cb(ziti_context ztx, void *v_mfa_ctx, char *code, ziti_ar_mfa_status_cb status_cb, void* status_ctx) {
    ztx->auth_queries->awaiting_mfa_cb = false;
    ziti_mfa_auth_ctx *mfa_ctx = v_mfa_ctx;
    mfa_ctx->status_cb = status_cb;
    mfa_ctx->status_ctx = status_ctx;

    if (code == NULL) {
        ZITI_LOG(ERROR, "expected mfa auth query to return non empty string, trying again");
        ziti_auth_query_mfa_process(mfa_ctx);
    }

    char *body = ziti_mfa_code_body(code);

    ziti_ctrl_login_mfa(&ztx->controller, body, strlen(body), ziti_auth_query_mfa_auth_internal_cb, mfa_ctx);
}

void ziti_auth_query_mfa_process(ziti_mfa_auth_ctx *mfa_ctx) {
    if (!mfa_ctx->ztx->auth_queries->awaiting_mfa_cb) {
        mfa_ctx->ztx->auth_queries->awaiting_mfa_cb = true;
        mfa_ctx->ztx->opts->aq_mfa_cb(mfa_ctx->ztx, mfa_ctx, mfa_ctx->query, ziti_auth_query_mfa_cb);
    }
}

void ziti_auth_query_process(ziti_context ztx, void(*cb)(ziti_context)) {
    ziti_auth_query_mfa **aq;

    ziti_auth_query_mfa *ziti_mfa = NULL;
    if (ztx->session->auth_queries != NULL) {
        for (aq = ztx->session->auth_queries; *aq != NULL; aq++) {
            ziti_auth_query_mfa *current_aq = *aq;

            if (strncmp(current_aq->type_id, AUTH_QUERY_TYPE_MFA, strlen(AUTH_QUERY_TYPE_MFA)) == 0 &&
                strncmp(current_aq->provider, MFA_PROVIDER_ZITI, strlen(MFA_PROVIDER_ZITI)) == 0) {
                if (ziti_mfa == NULL) {
                    ziti_mfa = current_aq;
                } else {
                    ZITI_LOG(ERROR, "multiple auth queries for [type: %s] [provider: %s], cannot continue", current_aq->type_id, current_aq->provider);
                    cb(ztx);
                    return;
                }
            } else {
                ZITI_LOG(ERROR, "could not process authentication query [type: %s] [provider: %s], unknown type or provider", current_aq->type_id, current_aq->provider);
                cb(ztx); //fail with unsupported auth query
                return;
            }
        }
    }

    if (ziti_mfa == NULL) {
        ztx->auth_queries->outstanding_auth_queries = false;
        ztx->auth_queries->awaiting_mfa_cb = false;
        cb(ztx); //succeed no mfa to handle
        return;
    }

    ztx->auth_queries->outstanding_auth_queries = true;

    if (ztx->opts->aq_mfa_cb == NULL) {
        ZITI_LOG(ERROR, "could not process authentication query [type: %s] [provider: %s], no callback handler specified", ziti_mfa->type_id, ziti_mfa->provider);
        cb(ztx); //fail with unsupported auth query
        return;
    }

    ziti_mfa_auth_ctx *mfa_ctx = calloc(1, sizeof(ziti_mfa_auth_ctx));
    mfa_ctx->ztx = ztx;
    mfa_ctx->cb = cb;
    mfa_ctx->query = ziti_mfa;

    ziti_auth_query_mfa_process(mfa_ctx);
}

void ziti_mfa_enroll_get_internal_cb(ziti_mfa_enrollment *mfa_enrollment, ziti_error *err, void *ctx);

void ziti_mfa_enroll_post_internal_cb(void *empty, ziti_error *err, void *ctx) {
    ziti_mfa_enroll_cb_ctx *mfa_enroll_cb_ctx = ctx;

    if (err == NULL) {
        ziti_ctrl_get_mfa(&mfa_enroll_cb_ctx->ztx->controller, ziti_mfa_enroll_get_internal_cb, ctx);
    } else {
        ZITI_LOG(ERROR, "error during create MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_enroll_cb_ctx->cb(mfa_enroll_cb_ctx->ztx, err->err, NULL, mfa_enroll_cb_ctx->cb_ctx);
        FREE(err)
        FREE(ctx)
    }
}

void ziti_mfa_enroll_get_internal_cb(ziti_mfa_enrollment *mfa_enrollment, ziti_error *err, void *ctx) {
    ziti_mfa_enroll_cb_ctx *mfa_enroll_cb_ctx = ctx;

    if (err != NULL) {
        if (err->http_code != 404) {
            ZITI_LOG(ERROR, "error during enroll MFA call: %d - %s - %s", err->http_code, err->code, err->message);
            mfa_enroll_cb_ctx->cb(mfa_enroll_cb_ctx->ztx, err->err, NULL, mfa_enroll_cb_ctx->cb_ctx);
            FREE(err)
            FREE(ctx)
            return;
        }
        FREE(err)
    }

    if (mfa_enrollment == NULL) {
        ziti_ctrl_post_mfa(&mfa_enroll_cb_ctx->ztx->controller, ziti_mfa_enroll_post_internal_cb, ctx);
    } else {
        mfa_enroll_cb_ctx->cb(mfa_enroll_cb_ctx->ztx, ZITI_OK, mfa_enrollment, mfa_enroll_cb_ctx->cb_ctx);
        FREE(ctx)
        free_ziti_mfa_enrollment(mfa_enrollment);
    }
}

void ziti_mfa_enroll(ziti_context ztx, ziti_mfa_enroll_cb enroll_cb, void *ctx) {
    NEWP(mfa_enroll_cb_ctx, ziti_mfa_enroll_cb_ctx);

    mfa_enroll_cb_ctx->ztx = ztx;
    mfa_enroll_cb_ctx->cb = enroll_cb;
    mfa_enroll_cb_ctx->cb_ctx = ctx;

    ziti_ctrl_get_mfa(&ztx->controller, ziti_mfa_enroll_get_internal_cb, mfa_enroll_cb_ctx);
}

void ziti_mfa_remove_internal_cb(void *empty, ziti_error *err, void *ctx) {
    ziti_mfa_cb_ctx *mfa_cb_ctx = ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "error during remove MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, err->err, mfa_cb_ctx->cb_ctx);
        FREE(err)
    } else {
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, ZITI_OK, mfa_cb_ctx->cb_ctx);
    }

    FREE(mfa_cb_ctx->code)
    FREE(ctx)
}

void ziti_mfa_remove(ziti_context ztx, char *code, ziti_mfa_cb remove_cb, void *ctx) {
    NEWP(mfa_cb_ctx, ziti_mfa_cb_ctx);
    mfa_cb_ctx->ztx = ztx;
    mfa_cb_ctx->cb = remove_cb;
    mfa_cb_ctx->cb_ctx = ctx;
    mfa_cb_ctx->code = strdup(code);

    ziti_ctrl_delete_mfa(&ztx->controller, mfa_cb_ctx->code, ziti_mfa_remove_internal_cb, mfa_cb_ctx);
}

void ziti_mfa_verify_internal_cb(void *empty, ziti_error *err, void *ctx) {
    ziti_mfa_cb_ctx *mfa_cb_ctx = ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "error during verify MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, err->err, mfa_cb_ctx->cb_ctx);
        FREE(err)
    } else {
        mfa_cb_ctx->cb(mfa_cb_ctx->ztx, ZITI_OK, mfa_cb_ctx->cb_ctx);
    }

    FREE(ctx)
}

void ziti_mfa_verify(ziti_context ztx, char *code, ziti_mfa_cb verify_cb, void *ctx) {
    NEWP(mfa_cb_ctx, ziti_mfa_cb_ctx);
    mfa_cb_ctx->ztx = ztx;
    mfa_cb_ctx->cb = verify_cb;
    mfa_cb_ctx->cb_ctx = ctx;

    char *body = ziti_mfa_code_body(code);

    ziti_ctrl_post_mfa_verify(&ztx->controller, body, strlen(body), ziti_mfa_verify_internal_cb, mfa_cb_ctx);
}

void ziti_auth_query_mfa_auth_internal_cb(void *empty, ziti_error *err, void *ctx) {
    ziti_mfa_auth_ctx *mfa_ctx = ctx;
    ziti_context ztx = mfa_ctx->ztx;
    if (err != NULL) {
        ZITI_LOG(ERROR, "error during MFA auth call: %d - %s - %s", err->http_code, err->code, err->message);

        if(mfa_ctx->status_cb != NULL) {
            mfa_ctx->status_cb(ztx, mfa_ctx, err->err, mfa_ctx->status_ctx);
        } else {
            ZITI_LOG(WARN, "no mfa status callback provided, mfa failed, status was: %d", err->err);
            //only free if there is no status handler, if there is a status handler it is up to the
            //status handler to try again (submit another mfa code, or call ziti_mfa_abort()
            FREE(ctx)
        }
        FREE(err)
        return;
    } else {
        mfa_ctx->ztx->auth_queries->outstanding_auth_queries = false;

        if(mfa_ctx->status_cb != NULL) {
            mfa_ctx->status_cb(ztx, mfa_ctx, ZITI_OK, mfa_ctx->status_ctx);
        } else {
            ZITI_LOG(WARN, "no mfa status callback provided, mfa was a success, status was: %d", err->err);
        }

        mfa_ctx->cb(ztx);
        FREE(ctx)
    }
}

void ziti_mfa_abort(void *mfa_ctx) {
        FREE(mfa_ctx)
}

void ziti_mfa_get_recovery_codes_internal_cb(ziti_mfa_recovery_codes *rc, ziti_error *err, void *ctx) {
    ziti_mfa_recovery_codes_cb_ctx *mfa_recovery_codes_cb_ctx = ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "error during get recovery codes MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, err->err, NULL, mfa_recovery_codes_cb_ctx->cb_ctx);
        FREE(err)
    } else {
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, ZITI_OK, rc->recovery_codes, mfa_recovery_codes_cb_ctx->cb_ctx);
        free_ziti_mfa_recovery_codes(rc);
    }

    FREE(mfa_recovery_codes_cb_ctx->code)
    FREE(ctx)
}

void ziti_mfa_get_recovery_codes(ziti_context ztx, char *code, ziti_mfa_recovery_codes_cb get_cb, void *ctx) {
    NEWP(mfa_rc_cb_ctx, ziti_mfa_recovery_codes_cb_ctx);
    mfa_rc_cb_ctx->ztx = ztx;
    mfa_rc_cb_ctx->cb = get_cb;
    mfa_rc_cb_ctx->cb_ctx = ctx;
    mfa_rc_cb_ctx->code = strdup(code);

    ziti_ctrl_get_mfa_recovery_codes(&ztx->controller, mfa_rc_cb_ctx->code, ziti_mfa_get_recovery_codes_internal_cb, mfa_rc_cb_ctx);
}

void ziti_mfa_post_recovery_codes_internal_cb(void *empty, ziti_error *err, void *ctx) {
    ziti_mfa_recovery_codes_cb_ctx *mfa_recovery_codes_cb_ctx = ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "error during create recovery codes MFA call: %d - %s - %s", err->http_code, err->code, err->message);
        mfa_recovery_codes_cb_ctx->cb(mfa_recovery_codes_cb_ctx->ztx, err->err, NULL, mfa_recovery_codes_cb_ctx->cb_ctx);
        FREE(err)
    } else {
        ziti_mfa_get_recovery_codes(mfa_recovery_codes_cb_ctx->ztx, mfa_recovery_codes_cb_ctx->code, mfa_recovery_codes_cb_ctx->cb, mfa_recovery_codes_cb_ctx->cb_ctx);
    }

    FREE(ctx)
}

void ziti_mfa_new_recovery_codes(ziti_context ztx, char *code, ziti_mfa_recovery_codes_cb new_cb, void *ctx) {
    NEWP(mfa_rc_cb_ctx, ziti_mfa_recovery_codes_cb_ctx);
    mfa_rc_cb_ctx->ztx = ztx;
    mfa_rc_cb_ctx->cb = new_cb;
    mfa_rc_cb_ctx->cb_ctx = ctx;
    mfa_rc_cb_ctx->code = code;

    char *body = ziti_mfa_code_body(code);

    ziti_ctrl_post_mfa_recovery_codes(&ztx->controller, body, strlen(body), ziti_mfa_post_recovery_codes_internal_cb, mfa_rc_cb_ctx);
}
