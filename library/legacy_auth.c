// Copyright (c) 2023-2024. NetFoundry Inc.
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

#include "auth_method.h"
#include "zt_internal.h"
#include <assert.h>
#include <inttypes.h>

#define MAX_BACKOFF 5
#define BACKOFF_BASE_DELAY 5000
#define API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS 60
#define API_SESSION_DELAY_WINDOW_SECONDS 60
#define API_SESSION_EXPIRATION_TOO_SMALL_SECONDS 120


struct legacy_auth_s {
    ziti_auth_method_t api;
    auth_state_cb cb;
    auth_mfa_cb mfa_cb;
    void *ctx;
    ziti_controller *ctrl;
    uv_timer_t timer;
    ziti_api_session *session;
    model_list config_types;
    int backoff;
    char *jwt;
};

static const char *AUTH_QUERY_TYPE_MFA = "MFA";
static const char *MFA_PROVIDER_ZITI = "ziti";

static int legacy_auth_jwt_token(ziti_auth_method_t *self, const char *token);
static int legacy_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx);
static int legacy_auth_stop(ziti_auth_method_t *self);
static int legacy_auth_refresh(ziti_auth_method_t *self);
static void legacy_auth_free(ziti_auth_method_t *self);
static int legacy_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb);
static const ziti_auth_query_mfa* get_mfa(ziti_api_session *session);
static uint64_t refresh_delay(ziti_api_session *);

char *ziti_mfa_code_body(const char *code);

static void auth_timer_cb(uv_timer_t *t);
static void login_cb(ziti_api_session *session, const ziti_error *err, void *ctx);

#define LEGACY_AUTH_INIT()          \
    (ziti_auth_method_t) {          \
        .kind = LEGACY,             \
        .set_ext_jwt = legacy_auth_jwt_token, \
        .start = legacy_auth_start, \
        .force_refresh = legacy_auth_refresh, \
        .stop = legacy_auth_stop,   \
        .free = legacy_auth_free,   \
        .submit_mfa = legacy_auth_mfa, \
    }

ziti_auth_method_t *new_legacy_auth(ziti_controller *ctrl) {
    struct legacy_auth_s *auth = calloc(1, sizeof(*auth));
    auth->api = LEGACY_AUTH_INIT();
    auth->ctrl = ctrl;
    uv_timer_init(ctrl->loop, &auth->timer);
    model_list_append(&auth->config_types, "all");
    return &auth->api;
}

static int legacy_auth_jwt_token(ziti_auth_method_t *self, const char *token) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    free(auth->jwt);
    auth->jwt = strdup(token);
    if (auth->session) {
        ziti_ctrl_mfa_jwt(auth->ctrl, auth->jwt, login_cb, auth);
    }
    return 0;
}


int legacy_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    auth->cb = cb;
    auth->ctx = ctx;

    if (!uv_is_active((const uv_handle_t *)&auth->timer)) {
        uv_timer_start(&auth->timer, auth_timer_cb, 0, 0);
    }

    return ZITI_OK;
}

int legacy_auth_refresh(ziti_auth_method_t *self) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    assert(auth->ctx);
    assert(auth->cb);

    return uv_timer_start(&auth->timer, auth_timer_cb, 0, 0);
}


int legacy_auth_stop(ziti_auth_method_t *self) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    uv_timer_stop(&auth->timer);
    return ZITI_OK;
}

static void close_cb(uv_timer_t *t) {
    struct legacy_auth_s *auth = container_of(t, struct legacy_auth_s, timer);
    free(auth);
}

void legacy_auth_free(ziti_auth_method_t *self) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    model_list_clear(&auth->config_types, NULL);
    free_ziti_api_session_ptr(auth->session);
    free(auth->jwt);
    uv_close((uv_handle_t *)&auth->timer, (uv_close_cb)close_cb);
}

static void mfa_cb(void * UNUSED(empty), const ziti_error *err, void *ctx) {
    struct legacy_auth_s *auth = container_of(ctx, struct legacy_auth_s, api);

    if (auth->mfa_cb) {
        auth->mfa_cb(auth->ctx, err ? (int)err->err : ZITI_OK);
        auth->mfa_cb = NULL;
    }

    if (err == NULL) { // success
        // refresh session to clear auth_query
        uv_timer_start(&auth->timer, auth_timer_cb, 0, 0);
    } else {
        if (err->http_code == HTTP_STATUS_UNAUTHORIZED) {
            free_ziti_api_session_ptr(auth->session);
            auth->session = NULL;
            FREE(auth->jwt);
            auth->cb(auth->ctx, ZitiAuthStateUnauthenticated, err);
            uv_timer_start(&auth->timer, auth_timer_cb, 0, 0);
        } else {
            ZITI_LOG(ERROR, "failed to submit MFA code: %d/%s", (int)err->err, err->message);
            uv_timer_start(&auth->timer, auth_timer_cb, 0, 0);
        }
    }
}

static int legacy_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);

    auth->mfa_cb = cb;
    char *req = ziti_mfa_code_body(code);
    ziti_ctrl_login_mfa(auth->ctrl, req, strlen(req), mfa_cb, auth);
    return 0;
}

static void login_cb(ziti_api_session *session, const ziti_error *err, void *ctx) {
    struct legacy_auth_s *auth = ctx;
    free_ziti_api_session_ptr(auth->session);
    auth->session = NULL;

    int errCode = err ? (int)err->err : ZITI_OK;
    if (session) {
        auth->backoff = 0;
        ZITI_LOG(DEBUG, "logged in successfully => api_session[%s]", session->id);

        auth->session = session;
        const ziti_auth_query_mfa *ziti_mfa = get_mfa(session);

        if (ziti_mfa) {
            auth->cb(auth->ctx, ZitiAuthStatePartiallyAuthenticated, ziti_mfa);
        } else {
            auth->cb(auth->ctx, ZitiAuthStateFullyAuthenticated, session->token);
        }
        uint64_t delay = refresh_delay(session);
        uv_timer_start(&auth->timer, auth_timer_cb, delay, 0);
    } else if (err) {
        ZITI_LOG(WARN, "failed to login to ctrl[%s] %s[%d] %s", auth->ctrl->url, err->code, errCode, err->message);

        if (errCode == ZITI_AUTHENTICATION_FAILED) {
            auth->cb(auth->ctx, ZitiAuthImpossibleToAuthenticate, err);
        } else {
            uint64_t delay = next_backoff(&auth->backoff, 5, 5000);
            ZITI_LOG(DEBUG, "failed to login [%d/%s] setting retry in %" PRIu64 "ms",
                     errCode, err->message, delay);
            uv_timer_start(&auth->timer, auth_timer_cb, delay, 0);
        }
    }
}

static void refresh_cb(ziti_api_session *session, const ziti_error *err, void *ctx) {
    struct legacy_auth_s *auth = ctx;
    if (err == NULL) {
        auth->backoff = 0;
        assert(session);
        free_ziti_api_session_ptr(auth->session);
        auth->session = session;

        const ziti_auth_query_mfa *ziti_mfa = get_mfa(auth->session);
        if (ziti_mfa) {
            auth->cb(auth->ctx, ZitiAuthStatePartiallyAuthenticated, ziti_mfa);
        } else {
            auth->cb(auth->ctx, ZitiAuthStateFullyAuthenticated, session->token);
        }

        uint64_t delay = refresh_delay(session);
        uv_timer_start(&auth->timer, auth_timer_cb, delay, 0);

        return;
    }

    switch (err->err) {
        case ZITI_AUTHENTICATION_FAILED:
            // session expired or was deleted, try to re-auth
            auth->cb(auth->ctx, ZitiAuthStateUnauthenticated, err);
            free_ziti_api_session_ptr(auth->session);
            auth->session = NULL;
            uv_timer_start(&auth->timer, auth_timer_cb, 0, 0);
            break;
        default: {
            uint64_t delay = next_backoff(&auth->backoff, MAX_BACKOFF, BACKOFF_BASE_DELAY);
            ZITI_LOG(WARN, "failed to refresh API session: %d/%s, retry in %" PRIu64 "ms",
                     (int)err->err, err->message, delay);
            uv_timer_start(&auth->timer, auth_timer_cb, delay, 0);
        }
    }
}

void auth_timer_cb(uv_timer_t *t) {
    struct legacy_auth_s *auth = container_of(t, struct legacy_auth_s, timer);

    if (auth->session == NULL) {
        if (auth->jwt) {
            ziti_ctrl_login_ext_jwt(auth->ctrl, auth->jwt, login_cb, auth);
        } else {
            ziti_ctrl_login(auth->ctrl, &auth->config_types, login_cb, auth);
        }
    } else {
        ziti_ctrl_current_api_session(auth->ctrl, refresh_cb, auth);
    }
}

static const ziti_auth_query_mfa* get_mfa(ziti_api_session *session) {
    if (model_list_size(&session->auth_queries) > 1) {
        ZITI_LOG(WARN, "multiple auth queries are not supported");
    }
    const ziti_auth_query_mfa *aq = model_list_head(&session->auth_queries);
    return aq;
}

static uint64_t refresh_delay(ziti_api_session *session) {
    int time_diff;
    uv_timeval64_t session_received_at;
    uv_gettimeofday(&session_received_at);

    if (session->cached_last_activity_at.tv_sec > 0) {
        ZITI_LOG(TRACE, "API supports cached_last_activity_at");
        time_diff = (int) (session_received_at.tv_sec - session->cached_last_activity_at.tv_sec);
    } else {
        ZITI_LOG(TRACE, "API doesn't support cached_last_activity_at - using updated");
        time_diff = (int) (session_received_at.tv_sec - session->updated.tv_sec);
    }
    if (abs(time_diff) > 10) {
        ZITI_LOG(ERROR, "local clock is %d seconds %s UTC (as reported by controller)", abs(time_diff),
                time_diff > 0 ? "ahead" : "behind");
    }

    uint64_t delay_seconds;

    if (session->expireSeconds > 0) {
        delay_seconds = session->expireSeconds;
    } else {
        // adjust expiration to local time if needed
        session->expires.tv_sec += time_diff;
        delay_seconds = (session->expires.tv_sec - session_received_at.tv_sec);
    }

    delay_seconds = delay_seconds - API_SESSION_DELAY_WINDOW_SECONDS; //renew a little early

    if (delay_seconds < API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS) {
        delay_seconds = API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS;
        ZITI_LOG(WARN, "api session expiration window is set too small (<%d) and may cause issues with "
                      "connectivity and api session maintenance, defaulting api session refresh delay [%ds]",
                API_SESSION_EXPIRATION_TOO_SMALL_SECONDS, API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS);
    }

    ZITI_LOG(DEBUG, "api session set, next refresh in %" PRIu64 "s", delay_seconds);
    return delay_seconds * 1000;
}