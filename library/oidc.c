// Copyright (c) 2023-2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <ctype.h>

#include <json-c/json.h>
#include <sodium.h>
#include <stc/cstr.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "auth_method.h"
#include "buffer.h"
#include "internal_model.h"
#include "oidc.h"
#include "utils.h"
#include "zt_internal.h"
#include "ziti/errors.h"

#define state_len 30
#define state_code_len sodium_base64_ENCODED_LEN(code_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)

#define code_len 40
#define code_verifier_len sodium_base64_ENCODED_LEN(code_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
#define code_challenge_len sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING)

#define _str(x) #x
#define auth_cb_port 20314 /* 'OZ' */
#define auth_url_path "/auth/callback"
#define cb_url(host,port,path) "http://" host ":" _str(port) path
#define default_cb_url cb_url("localhost",auth_cb_port,auth_url_path)
#define default_scope "openid"

#define AUTH_EP "authorization_endpoint"
#define TOKEN_EP "token_endpoint"
#define OIDC_CONFIG ".well-known/openid-configuration"

#define INTERNAL_CLIENT_ID  "openziti"
#define INTERNAL_TOKEN_TYPE "access_token"
#define INTERNAL_SCOPES     "openid offline_access"


#define OIDC_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "oidc[internal] " fmt, ##__VA_ARGS__)

static void oidc_client_set_tokens(oidc_client_t *clt, json_object *tok_json);

static void failed_auth_req(struct auth_req *req, const char *error);

static void refresh_time_cb(uv_timer_t *t);

static uint64_t oidc_refresh_delay(oidc_client_t *clt);

typedef struct auth_req {
    oidc_client_t *clt;
    char code_verifier[code_verifier_len];
    char code_challenge[code_challenge_len];
    char state[state_code_len];
    json_tokener *json_parser;
    cstr id;
    bool totp;
} auth_req;


static void handle_unexpected_resp(oidc_client_t *clt, tlsuv_http_resp_t *resp, json_object *body) {
    OIDC_LOG(WARN, "unexpected OIDC response");
    OIDC_LOG(WARN, "%s %d %s", resp->http_version, resp->code, resp->status);
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &resp->headers, _next) {
        OIDC_LOG(WARN, "%s: %s", h->name, h->value);
    }
    OIDC_LOG(WARN, "%s", json_object_get_string(body));
}

int oidc_client_init(uv_loop_t *loop, oidc_client_t *clt,
                     const char *provider, tls_context *tls) {
    assert(clt != NULL);
    assert(provider != NULL);

    OIDC_LOG(INFO, "initializing with provider[%s]", provider);
    clt->config = NULL;
    clt->config_cb = NULL;
    clt->token_cb = NULL;
    clt->close_cb = NULL;
    clt->provider_url = cstr_init();

    if (tlsuv_http_init(loop, &clt->http, provider) != 0) {
        OIDC_LOG(ERROR, "ziti_jwt_signer.provider_url[%s] is invalid", provider);
        return ZITI_INVALID_CONFIG;
    }
    int rc = oidc_client_set_cfg(clt, provider);
    if (rc != 0) {
        return rc;
    }
    tlsuv_http_set_ssl(&clt->http, tls);
    tlsuv_http_connect_timeout(&clt->http, 10000);
    tlsuv_http_idle_keepalive(&clt->http, 0);
    tlsuv_http_header(&clt->http, HTTP_ACCEPT, APPLICATION_JSON);

    clt->timer = calloc(1, sizeof(*clt->timer));
    uv_timer_init(loop, clt->timer);
    clt->timer->data = clt;
    uv_unref((uv_handle_t *) clt->timer);

    return 0;
}

int oidc_client_set_cfg(oidc_client_t *clt, const char *provider) {
    assert(provider != NULL);
    struct tlsuv_url_s url = {0};
    if (tlsuv_parse_url(&url, provider) != 0 || url.scheme_len == 0 || url.hostname_len == 0) {
        OIDC_LOG(ERROR, "invalid provider URL[%s]", provider);
        return ZITI_INVALID_CONFIG;
    }

    cstr_assign(&clt->provider_url, provider);
    if (!cstr_contains(&clt->provider_url, "/oidc")) {
        cstr_append(&clt->provider_url, "/oidc");
    }

    return 0;
}

static void internal_config_cb(tlsuv_http_resp_t *r, const char * err, json_object *resp, void *ctx) {
    oidc_client_t *clt = ctx;
    int status = 0;

    if (r->code < 0) {
        status = r->code;
        err = err ? err : uv_strerror((int) r->code);
    } else if (r->code != 200 && resp == NULL) {
        OIDC_LOG(ERROR, "unexpected response code[%d] body=%s", r->code, json_object_get_string(resp));
        status = UV_EINVAL;
        err = r->status;
    } else {
        // check expected configuration values are present and valid
        // to avoid surprises later
        if (json_object_get_type(resp) != json_type_object) {
            status = UV_EINVAL;
        } else if (json_object_object_get(resp, AUTH_EP) == NULL ||
                   json_object_object_get(resp, TOKEN_EP) == NULL) {
            OIDC_LOG(ERROR, "invalid OIDC config: %s and %s are required", AUTH_EP, TOKEN_EP);
            OIDC_LOG(DEBUG, "response body: %s", json_object_get_string(resp));
            status = UV_EINVAL;
        }
    }

    clt->configuring = false;

    if (status == 0) {
        json_object_put(clt->config);
        clt->config = json_object_get(resp);
        // config has full URLs, so we can drop the prefix now
        tlsuv_http_set_path_prefix(&clt->http, "");

        if (clt->need_refresh) {
            clt->need_refresh = false;
            uv_timer_start(clt->timer, refresh_time_cb, 0, 0);
            OIDC_LOG(DEBUG, "continuing pending token refresh");
        } else if (clt->token_cb != NULL) {
            oidc_client_start(clt, clt->token_cb);
        }
    }

    oidc_config_cb cb = clt->config_cb;
    if (cb) {
        clt->config_cb = NULL;
        cb(clt, status, err);
    }
}

int oidc_client_configure(oidc_client_t *clt, oidc_config_cb cb) {
    if (clt->request) {
        OIDC_LOG(ERROR, "cannot configure while another request is in progress");
        return UV_EALREADY;
    }
    if (clt->refresh_req) {
        OIDC_LOG(DEBUG, "cancelling pending refresh request");
        tlsuv_http_req_cancel(&clt->http, clt->refresh_req);
        clt->refresh_req = NULL;
        clt->need_refresh = true;
    }

    uv_timer_stop(clt->timer);
    clt->configuring = true;
    clt->config_cb = cb;
    json_object_put(clt->config);
    clt->config = NULL;

    OIDC_LOG(DEBUG, "configuring provider[%s]", cstr_str(&clt->provider_url));
    tlsuv_http_set_url(&clt->http, cstr_str(&clt->provider_url));
    ziti_json_request(&clt->http, "GET", OIDC_CONFIG, internal_config_cb, clt);
    return 0;
}

static auth_req *new_auth_req(oidc_client_t *clt) {
    auth_req *req = calloc(1, sizeof(*req));
    req->clt = clt;

    uint8_t code[code_len];
    uv_random(NULL, NULL, code, sizeof(code), 0, NULL);
    sodium_bin2base64(req->code_verifier, sizeof(req->code_verifier),
                      code, sizeof(code), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    uint8_t hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, (const uint8_t *) req->code_verifier, strlen(req->code_verifier));
    sodium_bin2base64(req->code_challenge, sizeof(req->code_challenge),
                      hash, sizeof(hash), sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    uint8_t state[state_len];
    uv_random(NULL, NULL, state, sizeof(state), 0, NULL);
    sodium_bin2base64(req->state, sizeof(req->state),
                      state, sizeof(state), sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    return req;
}

static void free_auth_req(auth_req *req) {
    if (req == NULL) return;

    if (req->json_parser) {
        json_tokener_free(req->json_parser);
        req->json_parser = NULL;
    }
    cstr_drop(&req->id);
    free(req);
}

static void failed_auth_req(auth_req *req, const char *error) {
    oidc_client_t *clt = req->clt;
    if (clt) {
        if (clt->request == req) {
            clt->request = NULL;
        }

        if (clt->token_cb) {
            OIDC_LOG(WARN, "OIDC authorization failed: %s", error);
            clt->token_cb(clt, OIDC_TOKEN_FAILED, error);
            clt->request = NULL;
            clt = NULL;
        }
    }

    free_auth_req(req);
}

static void token_cb(tlsuv_http_resp_t *http_resp, const char *err, json_object *resp, void *ctx) {
    auth_req *req = ctx;
    oidc_client_t *clt = req->clt;
    OIDC_LOG(DEBUG, "%d %s err[%s]", http_resp->code, http_resp->status, err);
    if (http_resp->code == 200) {
        oidc_client_set_tokens(clt, resp);
        clt->request = NULL;
        free_auth_req(req);
    } else {
        failed_auth_req(req, http_resp->status);
        http_resp->req->data = NULL;
        handle_unexpected_resp(clt, http_resp, resp);
    }
}

static void request_token(auth_req *req, const char *auth_code) {
    oidc_client_t *clt = req->clt;
    json_object *token_ep = json_object_object_get(clt->config, TOKEN_EP);
    const char *token_url = json_object_get_string(token_ep);
    OIDC_LOG(INFO, "requesting token path[%s] auth[%s]", token_url, auth_code);
    tlsuv_http_set_url(&clt->http, token_url);
    tlsuv_http_req_t *token_req = ziti_json_request(&clt->http, "POST", NULL, token_cb, req);
    tlsuv_http_pair form[] = {
            {"state",         req->state},
            {"code",          auth_code},
            {"grant_type",    "authorization_code"},
            {"code_verifier", req->code_verifier},
            {"client_id",     INTERNAL_CLIENT_ID},
            {"redirect_uri",  default_cb_url},
    };
    tlsuv_http_req_form(token_req, sizeof(form) / sizeof(form[0]), form);
}

static void code_cb(tlsuv_http_resp_t *http_resp, void *ctx) {
    auth_req *req = ctx;
    if (http_resp->code / 100 == 3) {
        const char *redirect = tlsuv_http_resp_header(http_resp, HTTP_LOCATION);
        struct tlsuv_url_s uri;
        if (redirect == NULL || tlsuv_parse_url(&uri, redirect) != 0) { // guard against missing/invalid Location header
            failed_auth_req(req, "missing or invalid redirect");
            return;
        }
        char *code = uri.query ? strstr(uri.query, "code=") : NULL; // guard against missing query string
        if (code == NULL) { // guard against missing code= parameter
            failed_auth_req(req, "missing auth code in redirect");
            return;
        }
        code += strlen("code=");

        request_token(req, code);
    } else {
        failed_auth_req(req, http_resp->status);
    }
}

static void login_cb(tlsuv_http_resp_t *http_resp, const char *err, json_object *body, void *ctx) {
    auth_req *req = ctx;
    oidc_client_t *clt = req->clt;

    OIDC_LOG(DEBUG, "%d login[%s] body = %s", http_resp->code, err, json_object_to_json_string(body));
    json_object *auth_queries = json_object_object_get(body, "authQueries");
    model_list queries = {};
    if (auth_queries) {
        ziti_auth_query_mfa_list_from_json(&queries, auth_queries);
    }

    if (model_list_size(&queries) > 0) {
        ziti_auth_query_mfa *q;
        MODEL_LIST_FOREACH(q, queries) {
            switch (q->type_id) {
                case ziti_auth_query_type_MFA:
                case ziti_auth_query_type_TOTP:
                    req->totp = true;
                    clt->request = req;
                    clt->token_cb(req->clt, OIDC_TOTP_NEEDED, NULL);
                    break;
                case ziti_auth_query_type_EXT_JWT:
                    clt->request = req;
                    clt->token_cb(req->clt, OIDC_EXT_JWT_NEEDED, q);
                    break;
                default:
                    OIDC_LOG(ERROR, "unknown auth query type[%d]", q->type_id);
            }
        }
        model_list_clear(&queries, (_free_f)free_ziti_auth_query_mfa_ptr);
        return;
    }

    if (http_resp->code / 100 == 2) {
        const char *totp = tlsuv_http_resp_header(http_resp, "totp-required");
        if (totp && tolower(totp[0]) == 't') {
            req->totp = true;
            req->clt->request = req;
            req->clt->token_cb(req->clt, OIDC_TOTP_NEEDED, NULL);
        }
    } else if (http_resp->code / 100 == 3) {
        const char *redirect = tlsuv_http_resp_header(http_resp, HTTP_LOCATION);
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        tlsuv_http_set_path_prefix(&req->clt->http, NULL);
        tlsuv_http_req(&req->clt->http, "GET", uri.path, code_cb, req);
    } else {
        failed_auth_req(req, http_resp->status);
    }
}

static void free_body_cb(tlsuv_http_req_t * UNUSED(req), char *body, ssize_t UNUSED(len)) {
    free(body);
}

static void auth_cb(tlsuv_http_resp_t *http_resp, const char *err, json_object *resp, void *ctx) {
    auth_req *req = ctx;
    oidc_client_t *clt = req->clt;
    OIDC_LOG(DEBUG, "%d %s err[%s] body=%s", http_resp->code, http_resp->status, err, json_object_to_json_string(resp));
    if (http_resp->code / 100 == 3) {
        const char *redirect = tlsuv_http_resp_header(http_resp, HTTP_LOCATION);
        struct tlsuv_url_s uri;
        if (redirect == NULL || tlsuv_parse_url(&uri, redirect) != 0) { // guard against missing/invalid Location header
            failed_auth_req(req, "missing or invalid redirect");
            return;
        }
        char *p = uri.query ? strstr(uri.query, "authRequestID=") : NULL; // guard against missing query string
        if (p == NULL) { // guard against missing authRequestID parameter
            failed_auth_req(req, "missing authRequestID in redirect");
            return;
        }
        p += strlen("authRequestID=");
        char *end = strchr(p, '&'); // stop at next query param to avoid capturing trailing params
        req->id = end ? cstr_with_n(p, end - p) : cstr_from(p);

        const char *path = !cstr_is_empty(&req->clt->jwt_token_auth) ?
                    "/oidc/login/ext-jwt" :
                    "/oidc/login/cert";

        OIDC_LOG(DEBUG, "login with path[%s] ", path);
        tlsuv_http_set_path_prefix(&req->clt->http, NULL);
        tlsuv_http_req_t *login_req = ziti_json_request(&req->clt->http, "POST", path, login_cb, req);
        HTTP_REQ_QUERY(login_req, { "id", cstr_str(&req->id) });
        if (!cstr_is_empty(&clt->jwt_token_auth)) {
            tlsuv_http_req_header(login_req, HTTP_AUTHORIZATION, cstr_str(&clt->jwt_token_auth));
        }
        tlsuv_http_req_header(login_req, HTTP_CONTENT_TYPE, APPLICATION_JSON);
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
        const char *body = ziti_auth_req_to_json(&authreq, 0, &body_len);
        tlsuv_http_req_data(login_req, body, body_len, free_body_cb);
    } else {
        failed_auth_req(req, http_resp->status);
    }
}

int oidc_client_start(oidc_client_t *clt, oidc_token_cb cb) {
    assert(cb != NULL);
    clt->token_cb = cb;
    if (clt->config == NULL) {
        OIDC_LOG(DEBUG, "deferring auth flow until configuration is complete");
        return 0;
    }
    if (clt->request) {
        OIDC_LOG(DEBUG, "auth request in progress");
        return 0;
    }

    OIDC_LOG(DEBUG, "starting auth flow");
    json_object *cfg = (json_object *) clt->config;
    json_object *auth_ep = json_object_object_get(cfg, AUTH_EP);
    if (auth_ep  == NULL) {
        OIDC_LOG(ERROR, "OIDC configuration is missing `%s'", AUTH_EP);
        return ZITI_INVALID_CONFIG;
    }
    const char *auth_url = json_object_get_string(auth_ep);

    OIDC_LOG(DEBUG, "requesting authentication code from auth_url[%s]", auth_url);
    auth_req *req = new_auth_req(clt);
    clt->request = req;

    int rc = tlsuv_http_set_url(&clt->http, auth_url);
    if (rc == 0) {
        tlsuv_http_req_t *http_req = ziti_json_request(&clt->http, "POST", NULL, auth_cb, req);
        rc = HTTP_REQ_QUERY(http_req,
                            {"client_id",             INTERNAL_CLIENT_ID},
                            {"scope",                 INTERNAL_SCOPES},
                            {"response_type",         "code"},
                            {"redirect_uri",          default_cb_url},
                            {"code_challenge",        req->code_challenge},
                            {"code_challenge_method", "S256"},
                            {"state",                 req->state},
                            {"audience",              "openziti"},
        );
    } else {
        OIDC_LOG(ERROR, AUTH_EP "[%s] is an invalid URL", auth_url);
    }

    return rc;
}

static void http_close_cb(tlsuv_http_t *h) {
    oidc_client_t *clt = container_of(h, struct oidc_client_s, http);

    oidc_close_cb cb = clt->close_cb;
    json_object_put(clt->config);
    if (cb) {
        cb(clt);
    }
}

static void on_totp(tlsuv_http_resp_t *resp, void *ctx) {
    auth_req *req = ctx;
    oidc_client_t *clt = req->clt;
    OIDC_LOG(VERBOSE, "TOTP result[%d:%s]", resp->code, resp->status);

    int code = resp->code / 100;
    if (code == 3) {
        clt->token_cb(req->clt, OIDC_TOTP_SUCCESS, NULL);
        req->totp = false;
        const char *redirect = tlsuv_http_resp_header(resp, HTTP_LOCATION);
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        tlsuv_http_req(&clt->http, "GET", uri.path, code_cb, req);
    } else if (code == 4) {
        OIDC_LOG(WARN, "totp failed: %s", resp->status);
        clt->token_cb(clt, OIDC_TOTP_FAILED, NULL);
    } else {
        OIDC_LOG(WARN, "totp request failed: %s", resp->status);
        clt->token_cb(clt, OIDC_TOTP_FAILED, NULL);
    }
}

int oidc_client_token(oidc_client_t *clt, const char *token) {
    cstr_clear(&clt->jwt_token_auth);
    cstr_append_fmt(&clt->jwt_token_auth, HTTP_BEARER_FMT, token);

    if (clt->request) {
        auth_req *req = clt->request;
        tlsuv_http_set_path_prefix(&clt->http, NULL);
        tlsuv_http_req_t *r = ziti_json_request(&clt->http, "POST", "/oidc/login/ext-jwt", login_cb, req);
        tlsuv_http_req_header(r, HTTP_AUTHORIZATION, cstr_str(&clt->jwt_token_auth));
        tlsuv_http_req_form(r, 1, &(tlsuv_http_pair) {"id", cstr_str(&req->id)});
    }
    return 0;
}

int oidc_client_mfa(oidc_client_t *clt, const char *code) {
    struct auth_req *req = clt->request;
    if (req == NULL || !req->totp) {
        OIDC_LOG(ERROR, "TOTP is not required or completed");
        return -1;
    }

    tlsuv_http_set_path_prefix(&clt->http, NULL);
    tlsuv_http_req_t *r = tlsuv_http_req(&clt->http, "POST", "/oidc/login/totp", on_totp, req);
    tlsuv_http_req_form(r, 2, (tlsuv_http_pair[]){
            {"id", cstr_str(&req->id)},
            {"code", code},
    });
    return 0;
}

int oidc_client_refresh(oidc_client_t *clt) {
    if (clt->close_cb) {
        OIDC_LOG(ERROR, "already closed");
        return UV_EINVAL;
    }

    if (clt->token_cb == NULL) {
        OIDC_LOG(ERROR, "token callback is not set");
        return UV_EINVAL;
    }

    if (clt->timer == NULL || uv_is_closing((const uv_handle_t *) clt->timer)) {
        OIDC_LOG(ERROR, "invalid state: refresh timer is %s", clt->timer ? "closing" : "null");
        return UV_EINVAL;
    }

    if (clt->refresh_req) {
        OIDC_LOG(DEBUG, "refresh is already in progress");
        return UV_EALREADY;
    }

    if (clt->configuring) {
        OIDC_LOG(DEBUG, "configuration is in progress, deferring refresh");
        clt->need_refresh = true;
        return 0;
    }

    uv_ref((uv_handle_t *) clt->timer);
    return uv_timer_start(clt->timer, refresh_time_cb, 0, 0);
}

int oidc_client_close(oidc_client_t *clt, oidc_close_cb cb) {
    if (clt->close_cb) {
        return UV_EALREADY;
    }

    OIDC_LOG(DEBUG, "closing");
    clt->token_cb = NULL;
    clt->close_cb = cb;
    tlsuv_http_close(&clt->http, http_close_cb);
    uv_close((uv_handle_t *) clt->timer, (uv_close_cb) free);
    clt->timer = NULL;
    cstr_drop(&clt->provider_url);
    cstr_drop(&clt->jwt_token_auth);
    zt_jwt_drop(&clt->current);
    zt_jwt_drop(&clt->refresh_token);

    if (clt->request) {
        failed_auth_req(clt->request, strerror(ECANCELED));
    }

    return 0;
}

static void oidc_client_set_tokens(oidc_client_t *clt, json_object *tok_json) {
    if (clt->close_cb) {
        OIDC_LOG(WARN, "already closed");
        return;
    }
    struct json_object *jt = json_object_object_get(tok_json, INTERNAL_TOKEN_TYPE);
    if (!jt) {
        OIDC_LOG(ERROR, INTERNAL_TOKEN_TYPE " was not provided by Ziti Controller");
        clt->token_cb(clt, OIDC_TOKEN_FAILED, NULL);
        return;
    }

    const char *token_str = json_object_get_string(jt);
    if (zt_jwt_parse(token_str, &clt->current)) {
        OIDC_LOG(ERROR, "failed to parse " INTERNAL_TOKEN_TYPE " as JWT");
        clt->token_cb(clt, OIDC_TOKEN_FAILED, NULL);
        return;
    }
    uv_timeval64_t now;
    uv_gettimeofday(&now);
    OIDC_LOG(DEBUG, "using " INTERNAL_TOKEN_TYPE "=%s", json_object_get_string(clt->current.claims));
    OIDC_LOG(DEBUG, "token expires in %" PRIi64 " seconds", clt->current.expiration - now.tv_sec);

    if (clt->token_cb) {
        clt->token_cb(clt, OIDC_TOKEN_OK, cstr_str(&clt->current.encoded));
    }

    json_object *refresh_tok = json_object_object_get(tok_json, "refresh_token");
    if (zt_jwt_parse(json_object_get_string(refresh_tok), &clt->refresh_token)) {
        OIDC_LOG(ERROR, "failed to parse refresh_token as JWT");
    } else {
        OIDC_LOG(DEBUG, "refresh token expires in %" PRIi64 " seconds",
                 clt->refresh_token.expiration - now.tv_sec);
    }

    uint64_t delay = oidc_refresh_delay(clt);
    assert(clt->timer && !uv_is_closing((uv_handle_t*)clt->timer));
    OIDC_LOG(DEBUG, "scheduling token refresh in %" PRIu64 ".%03" PRIu64 " s", delay/1000, delay%1000);
    uv_timer_start(clt->timer, refresh_time_cb, delay, 0);
}

static void oidc_refresh_cb(tlsuv_http_resp_t *http_resp, const char *err, json_object *resp, void *ctx) {
    oidc_client_t *clt = ctx;
    assert(clt->refresh_req == http_resp->req);
    clt->refresh_req = NULL;

    if (http_resp->code == 200) {
        assert(resp != NULL);
        OIDC_LOG(DEBUG,  "token refresh success");
        clt->refresh_failures = 0;
        oidc_client_set_tokens(clt, resp);
        return;
    }

    if (http_resp->code == UV_ECANCELED) {
        OIDC_LOG(DEBUG, "OIDC token refresh was canceled");
        return;
    }

    clt->refresh_failures++;
    uint64_t delay = oidc_refresh_delay(clt);
    if (ziti_http_error_is_temporary(http_resp, resp) && delay > 0) {
        OIDC_LOG(WARN, "OIDC token refresh failed (%d/%s), attempt %d",
                 http_resp->code, err, clt->refresh_failures);

        OIDC_LOG(DEBUG, "scheduling token refresh retry in %" PRIu64 ".%03" PRIu64 " s", delay/1000, delay%1000);
        uv_timer_start(clt->timer, refresh_time_cb, delay, 0);
        return;
    }

    // token expired, or was rejected
    // restart full auth
    OIDC_LOG(WARN, "OIDC token refresh failed: %d %s [%s] %s",
             http_resp->code, http_resp->status, err, json_object_get_string(resp));
    clt->refresh_failures = 0;
    zt_jwt_drop(&clt->current);
    zt_jwt_drop(&clt->refresh_token);

    oidc_client_start(clt, clt->token_cb);
}

static const char* get_basic_auth_header(const char *client_id) {
    static char header[256];
    char auth[128];
    char auth64[sodium_base64_ENCODED_LEN(sizeof(auth), sodium_base64_VARIANT_URLSAFE)];
    size_t auth_len = snprintf(auth, sizeof(auth), "%s:", client_id);
    sodium_bin2base64(auth64, sizeof(auth64), (uint8_t*)auth, auth_len, sodium_base64_VARIANT_URLSAFE);
    snprintf(header, sizeof(header), "Basic %s", auth64);
    return header;
}

static void refresh_time_cb(uv_timer_t *t) {
    uv_unref((uv_handle_t *) t);
    oidc_client_t *clt = t->data;
    if (clt->configuring) {
        OIDC_LOG(DEBUG, "configuration is in progress, deferring refresh");
        clt->need_refresh = true;
        return;
    }

    struct json_object *token_ep = json_object_object_get(clt->config, TOKEN_EP);
    const char *token_url = json_object_get_string(token_ep);
    if (token_url == NULL) {
        OIDC_LOG(DEBUG, "must restart authentication flow: no configuration or token_endpoint");
        oidc_client_start(clt, clt->token_cb);
        return;
    }

    if (clt->refresh_req) {
        OIDC_LOG(DEBUG, "refresh is already in progress");
        return;
    }

    if (cstr_is_empty(&clt->refresh_token.encoded)) {
        OIDC_LOG(DEBUG, "refresh token is missing");
        oidc_client_start(clt, clt->token_cb);
        return;
    }

    OIDC_LOG(DEBUG, "refreshing OIDC token using refresh_token[%s]",
             json_object_get_string(clt->refresh_token.claims));
    tlsuv_http_set_url(&clt->http, token_url);
    tlsuv_http_req_t *req = ziti_json_request(&clt->http, "POST", NULL, oidc_refresh_cb, clt);
    tlsuv_http_req_header(req, HTTP_AUTHORIZATION, get_basic_auth_header(INTERNAL_CLIENT_ID));
    tlsuv_http_req_form(req, 3, (tlsuv_http_pair[]) {
        {"client_id",     INTERNAL_CLIENT_ID},
        {"grant_type",    "refresh_token"},
        {"refresh_token", cstr_str(&clt->refresh_token.encoded)},
    });

    clt->refresh_req = req;
}

// calculate delay until next token refresh attempt:
// - if token is valid, schedule before expiration
// - if token is expired, schedule with exponential backoff, giving up when refresh token expires
static uint64_t oidc_refresh_delay(oidc_client_t *clt) {
    uv_timeval64_t now;
    uv_gettimeofday(&now);

    // access_token is still valid, schedule refresh before it expires
    if (clt->current.expiration > now.tv_sec + 15) {
        uint64_t delay = (clt->current.expiration - now.tv_sec) * 1000;
        // add some jitter and time buffer
        // renew some time between 1/2 and 5/6 of remaining time
        uint64_t rando = randombytes_random();
        rando = rando % (delay / 3);
        delay = (uint64_t)delay / 2 + rando;

        return delay;
    }

    if (clt->refresh_token.expiration == 0) {
        OIDC_LOG(WARN, "access token is expired and refresh token is missing, restarting auth flow");
        return 0;
    }

    // if we failed to refresh access_token something (this app or controller) may be offline
    // do exponential backoff until refresh_token expires
    int failures = clt->refresh_failures > 10 ? 10 : clt->refresh_failures;
    uint64_t backoff = 1 << failures; // max backoff is 1024 seconds (~17 min)
    if (clt->refresh_token.expiration > now.tv_sec) {
        // if backoff would exceed refresh token expiration, give up and restart auth
        if (now.tv_sec + backoff < clt->refresh_token.expiration) {
            backoff *= 1000; // convert to ms
            uint64_t rando = (uint64_t)randombytes_random();
            backoff = backoff / 2 + rando % (backoff / 2);
            return backoff;
        }
    }
    return 0;
}

// =====================================================================
// auth-method facade
//
// Wraps oidc_client_t in the ziti_auth_method_t interface used by ziti.c.
// new_oidc_auth() returns &clt->api; callers use container_of to recover
// the enclosing oidc_client_t.
// =====================================================================

#define OIDC_AUTH_FROM_API(s) container_of((s), oidc_client_t, api)

static cstr internal_oidc_path(const char *base, const char *path);
static void oidc_auth_config_cb(oidc_client_t *oidc, int status, const char *err);
static void oidc_auth_token_cb(oidc_client_t *oidc, enum oidc_status status, const void *data);
static int oidc_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx);
static int oidc_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb);
static int oidc_auth_stop(ziti_auth_method_t *self);
static int oidc_auth_refresh(ziti_auth_method_t *self);
static const struct timeval *oidc_auth_expiration(ziti_auth_method_t *self);
static int oidc_auth_ext_jwt(ziti_auth_method_t *self, const char *token);
static int oidc_auth_set_endpoint(ziti_auth_method_t *self, const api_path *api);
static void oidc_auth_free(ziti_auth_method_t *self);
static void oidc_auth_close_cb(oidc_client_t *clt);

ziti_auth_method_t *new_oidc_auth(uv_loop_t *l, const api_path *api, tls_context *tls) {
    oidc_client_t *clt = calloc(1, sizeof(*clt));

    clt->api = (ziti_auth_method_t){
        .kind = OIDC,
        .start = oidc_auth_start,
        .set_endpoint = oidc_auth_set_endpoint,
        .stop = oidc_auth_stop,
        .force_refresh = oidc_auth_refresh,
        .expiration = oidc_auth_expiration,
        .submit_mfa = oidc_auth_mfa,
        .free = oidc_auth_free,
        .set_ext_jwt = oidc_auth_ext_jwt,
    };

    const char *u;
    FOR(u, api->base_urls) {
        model_list_append(&clt->urls, strdup(u));
    }
    clt->cur_url = model_list_iterator(&clt->urls);
    u = model_list_it_element(clt->cur_url);

    clt->loop = l;
    cstr oidc_url = internal_oidc_path(u, api->path);
    oidc_client_init(l, clt, cstr_str(&oidc_url), tls);
    cstr_drop(&oidc_url);
    return &clt->api;
}

static cstr internal_oidc_path(const char *base, const char *path) {
    struct tlsuv_url_s base_url = {};
    tlsuv_parse_url(&base_url, base);

    cstr result = cstr_from_fmt("%.*s://%.*s",
        (int)base_url.scheme_len, base_url.scheme,
        (int)base_url.hostname_len, base_url.hostname);
    if (base_url.port) {
        cstr_append_fmt(&result, ":%d", base_url.port);
    }

    // older controllers did not have path in the base URL
    if (base_url.path) {
        cstr_append_n(&result, base_url.path, (isize)base_url.path_len);
    } else if (path) {
        cstr_append(&result, path);
    }

    return result;
}

static int oidc_auth_set_endpoint(ziti_auth_method_t *self, const api_path *api) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);

    model_list_clear(&clt->urls, free);
    const char *u;
    FOR(u, api->base_urls) {
        model_list_append(&clt->urls, strdup(u));
    }
    clt->cur_url = model_list_iterator(&clt->urls);
    u = model_list_it_element(clt->cur_url);

    cstr oidc_url = internal_oidc_path(u, api->path);
    oidc_client_set_cfg(clt, cstr_str(&oidc_url));
    cstr_drop(&oidc_url);

    return oidc_client_configure(clt, oidc_auth_config_cb);
}

static void oidc_auth_close_cb(oidc_client_t *clt) {
    model_list_clear(&clt->urls, free);
    free(clt);
}

static void oidc_auth_free(ziti_auth_method_t *self) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);
    oidc_client_close(clt, oidc_auth_close_cb);
}

static void set_expiration(oidc_client_t *clt, const char *token) {
    json_object *payload = json_tokener_parse(jwt_payload(token));
    json_object *exp = json_object_object_get(payload, "exp");
    if (exp) {
        int exp_time = json_object_get_int(exp);
        clt->expiration.tv_sec = exp_time;
        clt->expiration.tv_usec = 0;
    } else {
        clt->expiration = (struct timeval){};
    }
    json_object_put(payload);
}

static void oidc_auth_token_cb(oidc_client_t *clt, enum oidc_status status, const void *data) {
    char err[128];

    clt->expiration = (struct timeval){};
    if (clt->auth_cb) {
        switch (status) {
            case OIDC_TOKEN_OK:
                set_expiration(clt, (const char*)data);
                clt->auth_cb(clt->auth_cb_ctx, ZitiAuthStateFullyAuthenticated, data);
                break;
            case OIDC_EXT_JWT_NEEDED:
                clt->auth_cb(clt->auth_cb_ctx, ZitiAuthStatePartiallyAuthenticated, data);
                break;
            case OIDC_TOTP_NEEDED:
                clt->auth_cb(clt->auth_cb_ctx, ZitiAuthStatePartiallyAuthenticated, (void *) &ZITI_MFA);
                break;
            case OIDC_TOTP_FAILED:
                assert(clt->mfa_cb != NULL);
                clt->mfa_cb(clt->auth_cb_ctx, ZITI_MFA_INVALID_TOKEN);
                clt->mfa_cb = NULL;
                break;
            case OIDC_TOTP_SUCCESS:
                assert(clt->mfa_cb != NULL);
                clt->mfa_cb(clt->auth_cb_ctx, ZITI_OK);
                clt->mfa_cb = NULL;
                break;
            case OIDC_TOKEN_FAILED: {
                const char *reason = data ? (const char *) data : "unknown";
                snprintf(err, sizeof(err), "%s", reason);
                clt->auth_cb(clt->auth_cb_ctx, ZitiAuthStateUnauthenticated, &(ziti_error){
                        .err = ZITI_AUTHENTICATION_FAILED,
                        .message = err});
                break;
            }
            case OIDC_RESTART:
                ZITI_LOG(DEBUG, "restarting internal OIDC flow");
                oidc_client_start(clt, oidc_auth_token_cb);
                break;
        }
    }
}

static void oidc_auth_config_cb(oidc_client_t *clt, int status, const char *err) {
    ZITI_LOG(DEBUG, "oidc config callback: %d/%s", status, err);
    if (status == 0) {
        if (clt->started) {
            oidc_client_refresh(clt);
        } else {
            clt->started = true;
            oidc_client_start(clt, oidc_auth_token_cb);
        }
    } else {
        const char *prev_url = model_list_it_element(clt->cur_url);
        clt->cur_url = model_list_it_next(clt->cur_url);
        if (clt->cur_url == NULL) {
            ZITI_LOG(ERROR, "failed to configure OIDC[%s] (no more URLs to try): %d/%s",
                     prev_url, status, err);
            if (clt->auth_cb) {
                ziti_error error = {
                    .err = status,
                    .message = err,
                };
                clt->auth_cb(clt->auth_cb_ctx, ZitiAuthImpossibleToAuthenticate, &error);
            }
            return;
        }

        ZITI_LOG(DEBUG, "failed to configure OIDC[%s] client: %d/%s",
                 prev_url, status, err);

        const char *u = model_list_it_element(clt->cur_url);
        cstr oidc_url = internal_oidc_path(u, "/oidc");
        ZITI_LOG(DEBUG, "trying next url[%s]", cstr_str(&oidc_url));
        oidc_client_set_cfg(clt, cstr_str(&oidc_url));
        oidc_client_configure(clt, oidc_auth_config_cb);
        cstr_drop(&oidc_url);
    }
}

static int oidc_auth_ext_jwt(ziti_auth_method_t *self, const char *token) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);
    oidc_client_token(clt, token);
    return 0;
}

static int oidc_auth_start(ziti_auth_method_t *self, auth_state_cb cb, void *ctx) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);
    clt->auth_cb = cb;
    clt->auth_cb_ctx = ctx;

    return oidc_client_configure(clt, oidc_auth_config_cb);
}

static int oidc_auth_mfa(ziti_auth_method_t *self, const char *code, auth_mfa_cb cb) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);
    clt->mfa_cb = cb;
    if (oidc_client_mfa(clt, code) != 0) {
        ZITI_LOG(WARN, "failed to submit MFA code");
        clt->mfa_cb = NULL;
        return ZITI_MFA_EXISTS;
    }
    return ZITI_OK;
}

static int oidc_auth_stop(ziti_auth_method_t *self) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);
    clt->auth_cb = NULL;
    clt->auth_cb_ctx = NULL;
    return 0;
}

static int oidc_auth_refresh(ziti_auth_method_t *self) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);
    return oidc_client_refresh(clt);
}

static const struct timeval *oidc_auth_expiration(ziti_auth_method_t *self) {
    oidc_client_t *clt = OIDC_AUTH_FROM_API(self);
    if (clt->expiration.tv_sec > 0) return &clt->expiration;
    return NULL;
}
