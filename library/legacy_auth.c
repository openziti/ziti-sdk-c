// Copyright (c) 2023-2026.  NetFoundry Inc
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

#include "auth_method.h"
#include "zt_internal.h"
#include <assert.h>
#include <inttypes.h>

#define MAX_BACKOFF 5
#define BACKOFF_BASE_DELAY 5000
#define API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS 60
#define API_SESSION_DELAY_WINDOW_SECONDS 60
#define API_SESSION_EXPIRATION_TOO_SMALL_SECONDS 120

#define AUTH_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "legacy_auth[%s]: " fmt, auth->http.host, ##__VA_ARGS__)

struct legacy_auth_s {
    ziti_auth_method_t api;
    auth_state_cb cb;
    auth_mfa_cb mfa_cb;
    void *ctx;

    tlsuv_http_t http;
    uv_timer_t timer;
    ziti_api_session *session;
    
    bool has_x509;
    cstr primary_jwt;
    cstr secondary_jwt;
    
    int fail_count;
    bool refreshing;
};

static const char *AUTH_QUERY_TYPE_MFA = "MFA";
static const char *MFA_PROVIDER_ZITI = "ziti";

static int legacy_auth_jwt_token(ziti_auth_method_t *self, const char *token);
static int legacy_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx);
static int legacy_auth_stop(ziti_auth_method_t *self);
static int legacy_auth_refresh(ziti_auth_method_t *self);
static void legacy_auth_free(ziti_auth_method_t *self);
static int legacy_auth_totp(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb);
static const ziti_auth_query_mfa* get_mfa(ziti_api_session *session);
static uint64_t refresh_delay(struct legacy_auth_s *auth, ziti_api_session *);
static const struct timeval* legacy_auth_expiration(ziti_auth_method_t *self);

char *ziti_mfa_code_body(const char *code);

static void free_body_cb(tlsuv_http_req_t *req, char *body, ssize_t len) {
    free(body);
}

static void legacy_timer_cb(uv_timer_t *t);

#define LEGACY_AUTH_INIT()          \
    (ziti_auth_method_t) {          \
        .kind = LEGACY,             \
        .set_ext_jwt = legacy_auth_jwt_token, \
        .start = legacy_auth_start, \
        .force_refresh = legacy_auth_refresh, \
        .expiration = legacy_auth_expiration, \
        .stop = legacy_auth_stop,   \
        .free = legacy_auth_free,   \
        .submit_mfa = legacy_auth_totp, \
    }

ziti_auth_method_t *new_legacy_auth(uv_loop_t *loop, const char *url, tls_context *tls, bool x509) {
    struct legacy_auth_s *auth = calloc(1, sizeof(*auth));
    auth->api = LEGACY_AUTH_INIT();
    auth->has_x509 = x509;

    tlsuv_http_init(loop, &auth->http, url);
    tlsuv_http_set_ssl(&auth->http, tls);
    uv_timer_init(loop, &auth->timer);
    AUTH_LOG(DEBUG, "method initialized");
    return &auth->api;
}

static int legacy_auth_jwt_token(ziti_auth_method_t *self, const char *token) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    
    token = token != NULL ? token : "";
    
    if (auth->has_x509 || auth->session) {
        AUTH_LOG(DEBUG, "setting secondary JWT token: %s", 
                 token[0] ? jwt_payload(token) : "<empty>");
        cstr_assign(&auth->secondary_jwt, token);
    } else {
        AUTH_LOG(DEBUG, "setting primary JWT token: %s", 
                 token[0] ? jwt_payload(token) : "<empty>");
        cstr_assign(&auth->primary_jwt, token);
    } 
    
    return 0;
}


int legacy_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    auth->cb = cb;
    auth->ctx = ctx;

    if (!uv_is_active((const uv_handle_t *)&auth->timer)) {
        uv_timer_start(&auth->timer, legacy_timer_cb, 0, 0);
    }

    return ZITI_OK;
}

const struct timeval* legacy_auth_expiration(ziti_auth_method_t *self) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    return auth->session ? &auth->session->expires : NULL;
}

int legacy_auth_refresh(ziti_auth_method_t *self) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);
    assert(auth->ctx);
    assert(auth->cb);

    if (auth->refreshing) {
        AUTH_LOG(DEBUG, "refresh already in progress");
        return 0;
    }

    return uv_timer_start(&auth->timer, legacy_timer_cb, 0, 0);
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
    free_ziti_api_session_ptr(auth->session);
    auth->session = NULL;
    cstr_drop(&auth->primary_jwt);
    cstr_drop(&auth->secondary_jwt);

    uv_close((uv_handle_t *)&auth->timer, (uv_close_cb)close_cb);
    tlsuv_http_close(&auth->http, NULL);
}

static void legacy_totp_cb(tlsuv_http_resp_t *resp, const char *err, json_object *body, void *ctx) {
    struct legacy_auth_s *auth = ctx;

    int status = ZITI_OK;

    switch (resp->code) {
    case HTTP_STATUS_OK:
        AUTH_LOG(DEBUG, "MFA code accepted");
        // refresh session to clear auth_query
        uv_timer_start(&auth->timer, legacy_timer_cb, 0, 0);
        break;
    case HTTP_STATUS_BAD_REQUEST: // this is not specified in the spec but is returned by controller
    case HTTP_STATUS_UNAUTHORIZED:
        AUTH_LOG(DEBUG, "MFA code rejected");
        status = ZITI_MFA_INVALID_TOKEN;
        break;
    default:
        if (resp->code < 0) {
            AUTH_LOG(WARN, "failed to submit MFA code: %d/%s", resp->code, uv_strerror(resp->code));
        } else {
            AUTH_LOG(WARN, "failed to submit MFA code: %d %s", resp->code, resp->status);
        }
        status = ZITI_CONTROLLER_UNAVAILABLE;
        break;
    }
    if (auth->mfa_cb) {
        auth->mfa_cb(auth->ctx, status);
    }

    if (status != ZITI_OK && auth->session) {
        auth->cb(auth->ctx, ZitiAuthStatePartiallyAuthenticated, get_mfa(auth->session));
    }
}

static int legacy_auth_totp(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb) {
    struct legacy_auth_s *auth = container_of(self, struct legacy_auth_s, api);

    if (auth->session == NULL) {
        AUTH_LOG(ERROR, "cannot submit MFA code without an active session");
        return ZITI_INVALID_STATE;
    }

    auth->mfa_cb = cb;
    char *code_json = ziti_mfa_code_body(code);

    tlsuv_http_req_t *req = ziti_json_request(&auth->http, "POST", "/authenticate/mfa", legacy_totp_cb, auth);
    tlsuv_http_req_header(req, HTTP_ZT_SESSION, auth->session ? auth->session->token : NULL);
    tlsuv_http_req_header(req, HTTP_CONTENT_TYPE, APPLICATION_JSON);
    tlsuv_http_req_data(req, code_json, strlen(code_json), free_body_cb);
    return 0;
}

static void legacy_session_cb(tlsuv_http_resp_t *resp, const char *err, json_object *json, void *ctx) {
    struct legacy_auth_s *auth = ctx;
    auth->refreshing = false;
    const char *delay_type = "refresh";
    uint64_t delay = 0;
    json_object *session_json = json_object_object_get(json, "data");
    ziti_api_session *session = NULL;

    switch(resp->code) {
    case HTTP_STATUS_UNAUTHORIZED:
        if (auth->session) {
            AUTH_LOG(DEBUG, "session is no longer valid: %s", resp->status);
            free_ziti_api_session_ptr(auth->session);
            auth->session = NULL;
            AUTH_LOG(DEBUG, "restarting authentication flow");
        } else {
            auth->fail_count++;
            AUTH_LOG(DEBUG, "authentication failed");
            auth->cb(auth->ctx, ZitiAuthImpossibleToAuthenticate,
                     &(ziti_error){
                         .err = ZITI_AUTHENTICATION_FAILED,
                         .code = resp->status,
                         .message = "authentication failed",
                     });
            delay = next_backoff(&auth->fail_count, MAX_BACKOFF, BACKOFF_BASE_DELAY);
            delay_type = "backoff";
        }
        break;

    case HTTP_STATUS_OK:
        if (session_json == NULL || ziti_api_session_ptr_from_json(&session, session_json) != 0 || session == NULL) {
            // this should never happen but handle it just in case
            AUTH_LOG(ERROR, "failed to parse api session from response");
            auth->fail_count++;
            delay = auth->session ? refresh_delay(auth, auth->session)
                                  : next_backoff(&auth->fail_count, MAX_BACKOFF, BACKOFF_BASE_DELAY);
            delay_type = auth->session ? "refresh" : "backoff";
        } else {
            auth->fail_count = 0;
            ziti_api_session *old_session = auth->session;
            auth->session = session;

            const ziti_auth_query_mfa *ziti_mfa = get_mfa(session);
            if (ziti_mfa) {
                AUTH_LOG(DEBUG, "received api session with pending MFA query type[%s] provider[%s]",
                         ziti_auth_query_types.name(ziti_mfa->type_id), ziti_mfa->provider);
                auth->cb(auth->ctx, ZitiAuthStatePartiallyAuthenticated, ziti_mfa);
            } else {
                const ziti_auth_query_mfa *old_mfa = old_session ? get_mfa(old_session) : NULL;
                // if new session or current session had pending MFA notify as fully authenticated
                if (old_session == NULL || strcmp(old_session->id, session->id) != 0 || old_mfa) {
                    AUTH_LOG(DEBUG, "logged in successfully => api_session[%s]", auth->session->id);
                    auth->cb(auth->ctx, ZitiAuthStateFullyAuthenticated, auth->session->token);
                } else {
                    AUTH_LOG(DEBUG, "refreshed api session[%s]", session->id);
                }
            }
            free_ziti_api_session_ptr(old_session);
            delay = refresh_delay(auth, auth->session);
        }
        break;

    default:  // non-auth related error, usually means controller cannot be reached
        auth->fail_count++;
        if (auth->session) {
            AUTH_LOG(WARN, "failed[%d] to refresh session: %d %s", auth->fail_count, resp->code, resp->status);
            delay = refresh_delay(auth, auth->session);
        } else {
            AUTH_LOG(WARN, "failed[%d] to acquire response: %d %s", auth->fail_count, resp->code, resp->status);
            delay = next_backoff(&auth->fail_count, MAX_BACKOFF, BACKOFF_BASE_DELAY);
            delay_type = "backoff";
        }
        break;
    }

    AUTH_LOG(INFO, "%s in %" PRIu64 " s", delay_type, delay / 1000);
    uv_timer_start(&auth->timer, legacy_timer_cb, delay, 0);
}

void legacy_timer_cb(uv_timer_t *t) {
    struct legacy_auth_s *auth = container_of(t, struct legacy_auth_s, timer);
    auth->refreshing = true;

    if (auth->session) {
        uv_timeval64_t now;
        if (uv_gettimeofday(&now) == 0 && auth->session->expires.tv_sec < now.tv_sec) {
            AUTH_LOG(WARN, "session expired according to local clock");
            free_ziti_api_session_ptr(auth->session);
            auth->session = NULL;
        } else {
            AUTH_LOG(DEBUG, "refreshing session[%p]", auth->session->id);
            tlsuv_http_req_t *req = ziti_json_request(&auth->http, "GET", "/current-api-session", legacy_session_cb, auth);
            tlsuv_http_req_header(req, HTTP_ZT_SESSION, auth->session->token);
            return;
        }
    }

    if (cstr_is_empty(&auth->primary_jwt) && !auth->has_x509) {
        AUTH_LOG(ERROR, "no primary x509 or JWT credentials available for authentication");
        auth->cb(auth->ctx, ZitiAuthImpossibleToAuthenticate,
                 &(ziti_error){
                     .err = ZITI_AUTHENTICATION_FAILED,
                     .code = 0,
                     .message = "no primary x509 or JWT credentials available for authentication",
                 });
        auth->refreshing = false;
        return;
    }

    ziti_auth_req authreq = {
        .sdk_info = {
            .type = "ziti-sdk-c",
            .version = ziti_get_build_version(0),
            .revision = ziti_git_commit(),
            .branch = ziti_git_branch(),
            .app_id = APP_ID,
            .app_version = APP_VERSION,
        },
        .env_info = (ziti_env_info *)get_env_info(),
    };

    size_t body_len;
    char *body = ziti_auth_req_to_json(&authreq, 0, &body_len);

    tlsuv_http_req_t *req = ziti_json_request(&auth->http, "POST", "/authenticate", legacy_session_cb, auth);

    if (auth->has_x509) {
        tlsuv_http_req_query(req, 1, &(tlsuv_http_pair){"method", "cert"});
    } else {
        cstr bearer = cstr_from_fmt(HTTP_BEARER_FMT, cstr_str(&auth->primary_jwt));
        tlsuv_http_req_header(req, HTTP_AUTHORIZATION, cstr_str(&bearer));
        tlsuv_http_req_query(req, 1, &(tlsuv_http_pair){"method", "ext-jwt"});
    }

    tlsuv_http_req_header(req, HTTP_CONTENT_TYPE, APPLICATION_JSON);
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

static const ziti_auth_query_mfa* get_mfa(ziti_api_session *session) {
    const ziti_auth_query_mfa *aq = model_list_head(&session->auth_queries);
    return aq;
}

static uint64_t refresh_delay(struct legacy_auth_s *auth, ziti_api_session *session) {
    uint64_t delay_seconds;
    const char *source;

    uv_timeval64_t now;
    if (uv_gettimeofday(&now) == 0 && session->expires.tv_sec > 0) {
        if (session->expires.tv_sec < now.tv_sec) {
            AUTH_LOG(WARN, "api session is already expired according to local clock");
            return 0;
        }

        delay_seconds = session->expires.tv_sec - now.tv_sec;
        source = "session->expires";
    } else if (session->expireSeconds > 0) {
        delay_seconds = session->expireSeconds;
        source = "session->expireSeconds";
    } else {
        int64_t time_diff;
        uint64_t time_diff_abs;
        uv_timeval64_t session_received_at;
        int err = uv_gettimeofday(&session_received_at);
        if (err != 0) {
            AUTH_LOG(WARN, "gettimeofday failed: %d(%s)", err, uv_strerror(err));
            delay_seconds = API_SESSION_EXPIRATION_TOO_SMALL_SECONDS; // ensure another attempt
        }

        if (session->cached_last_activity_at.tv_sec > 0) {
            AUTH_LOG(TRACE, "API supports cached_last_activity_at");
            time_diff = session_received_at.tv_sec - session->cached_last_activity_at.tv_sec;
            time_diff_abs =
                    MAX(session_received_at.tv_sec,session->cached_last_activity_at.tv_sec) -
                    MIN(session_received_at.tv_sec, session->cached_last_activity_at.tv_sec);
        } else {
            AUTH_LOG(TRACE, "API doesn't support cached_last_activity_at - using updated");
            time_diff = session_received_at.tv_sec - session->updated.tv_sec;
            time_diff_abs =
                    MAX(session_received_at.tv_sec, session->updated.tv_sec) -
                    MIN(session_received_at.tv_sec, session->updated.tv_sec);
        }
        if (time_diff_abs > 10) {
            AUTH_LOG(ERROR, "local clock is %" PRIu64 " seconds %s UTC (as reported by controller)", time_diff_abs,
                     time_diff > 0 ? "ahead" : "behind");
        }

        // adjust expiration to local time if needed
        session->expires.tv_sec += time_diff;
        delay_seconds = (session->expires.tv_sec - session_received_at.tv_sec);
        source = "calculation";
    }

    // add some jitter and time buffer
    // renew some time between 1/2 and 5/6 of remaining time
    uint64_t rando = randombytes_random();
    rando = rando % (delay_seconds / 3);
    delay_seconds = delay_seconds / 2 + rando;


    if (delay_seconds < API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS) {
        delay_seconds = API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS;
        AUTH_LOG(WARN, "api session expiration window is set too small (<%d) and may cause issues with "
                      "connectivity and api session maintenance, defaulting api session refresh delay [%ds]",
                API_SESSION_EXPIRATION_TOO_SMALL_SECONDS, API_SESSION_MINIMUM_REFRESH_DELAY_SECONDS);
    }

    AUTH_LOG(DEBUG, "api session set based on %s, next refresh in %" PRIu64 "s", source, delay_seconds);
    return delay_seconds * 1000;
}