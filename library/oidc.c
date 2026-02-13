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

#include <oidc.h>
#include <assert.h>
#include <json-c/json.h>
#include <sodium.h>
#include <ctype.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "ziti/ziti_log.h"
#include "utils.h"
#include "ziti/errors.h"
#include "ziti/ziti_buffer.h"
#include "buffer.h"
#include "internal_model.h"
#include "zt_internal.h"

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

typedef struct auth_req {
    oidc_client_t *clt;
    char code_verifier[code_verifier_len];
    char code_challenge[code_challenge_len];
    char state[state_code_len];
    json_tokener *json_parser;
    char *id;
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
    clt->tokens = NULL;
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
    tlsuv_http_header(&clt->http, "Accept", "application/json");

    clt->timer = calloc(1, sizeof(*clt->timer));
    uv_timer_init(loop, clt->timer);
    clt->timer->data = clt;
    uv_unref((uv_handle_t *) clt->timer);

    return 0;
}

int oidc_client_set_cfg(oidc_client_t *clt, const char *provider) {
    assert(provider != NULL);
    cstr_assign(&clt->provider_url, provider);
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
    FREE(req->id);
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
            clt->token_cb(clt, ZITI_AUTHENTICATION_FAILED, error);
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
        const char *redirect = tlsuv_http_resp_header(http_resp, "Location");
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        char *code = strstr(uri.query, "code=");
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
        const char *redirect = tlsuv_http_resp_header(http_resp, "Location");
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
        const char *redirect = tlsuv_http_resp_header(http_resp, "Location");
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        char *p = strstr(uri.query, "authRequestID=");
        p += strlen("authRequestID=");
        req->id = strdup(p);
        char path[256] = {};
        if (!cstr_is_empty(&req->clt->jwt_token_auth)) {
            snprintf(path, sizeof(path),"/oidc/login/ext-jwt?id=%s", req->id);
        } else {
            snprintf(path, sizeof(path),"/oidc/login/cert?id=%s", req->id);
        }
        OIDC_LOG(DEBUG, "login with path[%s] ", path);
        tlsuv_http_set_path_prefix(&req->clt->http, NULL);
        tlsuv_http_req_t *login_req = ziti_json_request(&req->clt->http, "POST", path, login_cb, req);
        if (!cstr_is_empty(&clt->jwt_token_auth)) {
            tlsuv_http_req_header(login_req, "Authorization", cstr_str(&clt->jwt_token_auth));
        }
        tlsuv_http_req_header(login_req, "Content-Type", "application/json");
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


    tlsuv_http_pair query[] = {
            {"client_id",             INTERNAL_CLIENT_ID},
            {"scope",                 INTERNAL_SCOPES},
            {"response_type",         "code"},
            {"redirect_uri",          default_cb_url},
            {"code_challenge",        req->code_challenge},
            {"code_challenge_method", "S256"},
            {"state",                 req->state},
            {"audience",              "openziti"},
    };

    int rc = tlsuv_http_set_url(&clt->http, auth_url);
    if (rc == 0) {
        tlsuv_http_req_t *http_req = ziti_json_request(&clt->http, "POST", NULL, auth_cb, req);
        rc = tlsuv_http_req_query(http_req, sizeof(query) / sizeof(query[0]), query);
    } else {
        OIDC_LOG(ERROR, AUTH_EP "[%s] is an invalid URL", auth_url);
    }

    return rc;
}

static void http_close_cb(tlsuv_http_t *h) {
    oidc_client_t *clt = container_of(h, struct oidc_client_s, http);

    oidc_close_cb cb = clt->close_cb;
    json_object_put(clt->config);
    json_object_put(clt->tokens);
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
        req->clt->token_cb(req->clt, OIDC_TOTP_SUCCESS, NULL);
        req->totp = false;
        const char *redirect = tlsuv_http_resp_header(resp, "Location");
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        tlsuv_http_req(&req->clt->http, "GET", uri.path, code_cb, req);
    } else if (code == 4) {
        OIDC_LOG(WARN, "totp failed: %s", resp->status);
        req->clt->token_cb(req->clt, OIDC_TOTP_FAILED, NULL);
    } else {
        OIDC_LOG(WARN, "totp request failed: %s", resp->status);
        req->clt->token_cb(req->clt, OIDC_TOTP_FAILED, NULL);
    }
}

int oidc_client_token(oidc_client_t *clt, const char *token) {
    cstr_clear(&clt->jwt_token_auth);
    cstr_append_fmt(&clt->jwt_token_auth, "Bearer %s", token);

    if (clt->request) {
        auth_req *req = clt->request;
        tlsuv_http_set_path_prefix(&clt->http, NULL);
        tlsuv_http_req_t *r = ziti_json_request(&clt->http, "POST", "/oidc/login/ext-jwt", login_cb, req);
        tlsuv_http_req_header(r, "Authorization", cstr_str(&clt->jwt_token_auth));
        tlsuv_http_req_form(r, 1, &(tlsuv_http_pair) {"id", req->id});
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
            {"id", req->id},
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

    if (clt->request) {
        failed_auth_req(clt->request, strerror(ECANCELED));
    }

    return 0;
}

static void oidc_client_set_tokens(oidc_client_t *clt, json_object *tok_json) {
    json_object_put(clt->tokens);

    clt->tokens = json_object_get(tok_json);
    if (clt->token_cb) {
        struct json_object *jt = json_object_object_get(clt->tokens, INTERNAL_TOKEN_TYPE);
        if (jt) {
            const char *token = json_object_get_string(jt);
            OIDC_LOG(DEBUG, "using " INTERNAL_TOKEN_TYPE "=%s", jwt_payload(token));
            clt->token_cb(clt, OIDC_TOKEN_OK, token);
        } else {
            OIDC_LOG(ERROR, INTERNAL_TOKEN_TYPE " was not provided by IdP");
            clt->token_cb(clt, OIDC_TOKEN_FAILED, NULL);
        }
    }
    assert(clt->timer && !uv_is_closing((uv_handle_t*)clt->timer));

    struct json_object *ttl = json_object_object_get(clt->tokens, "expires_in");
    if (!ttl) {
        OIDC_LOG(ERROR, "`expires_in` is missing from response");
    }
    if (ttl) {
        int32_t t = json_object_get_int(ttl);
        if (t <= 60) {
            OIDC_LOG(WARN, "token lifetime is too short[%d seconds]. this may cause problems", t);
            t = t / 2;
        } else {
            t = t - 30; // refresh 30 seconds before expiry
        }
        OIDC_LOG(DEBUG, "scheduling token refresh in %d seconds", t);
        uv_timer_start(clt->timer, refresh_time_cb, t * 1000, 0);
    }
}

static void refresh_cb(tlsuv_http_resp_t *http_resp, const char *err, json_object *resp, void *ctx) {
    oidc_client_t *clt = ctx;
    assert(clt->refresh_req == http_resp->req);
    clt->refresh_req = NULL;

    if (http_resp->code == 200 && resp != NULL) {
        OIDC_LOG(DEBUG,  "token refresh success");
        oidc_client_set_tokens(clt, resp);
        return;
    }

    if (http_resp->code >= 0 || http_resp->code == UV_EOF) {
        // controller may abruptly terminate shutdown connection (EOF) if auth has failed
        OIDC_LOG(WARN, "OIDC token refresh failed: %d %s [%s]",
                 http_resp->code, http_resp->status, err);
        if (resp) {
            OIDC_LOG(WARN, "response: %s", json_object_get_string(resp));
        }
        json_object_put(clt->tokens);
        clt->tokens = NULL;

        oidc_client_start(clt, clt->token_cb);
    }

    if (http_resp->code == UV_ECANCELED) {
        OIDC_LOG(DEBUG, "OIDC token refresh was canceled");
        return;
    }

    if (http_resp->code < 0) {  // connection failure, try another refresh
        OIDC_LOG(WARN, "OIDC token refresh failed (trying again): %d/%s", http_resp->code, err);
        uv_timer_start(clt->timer, refresh_time_cb, 5 * 1000, 0);
        return;
    }
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

    OIDC_LOG(DEBUG, "refreshing OIDC token");
    assert(clt->config);
    json_object *tok = json_object_object_get(clt->tokens, "refresh_token");
    if (tok == NULL) {
        OIDC_LOG(DEBUG, "must restart authentication flow: no refresh_token");
        oidc_client_start(clt, clt->token_cb);
        return;
    }

    if (clt->refresh_req) {
        OIDC_LOG(DEBUG, "refresh is already in progress");
        return;
    }

    struct json_object *token_ep = json_object_object_get(clt->config, TOKEN_EP);
    const char *token_url = json_object_get_string(token_ep);

    tlsuv_http_set_url(&clt->http, token_url);
    tlsuv_http_req_t *req = ziti_json_request(&clt->http, "POST", NULL, refresh_cb, clt);
    tlsuv_http_req_header(req, "Authorization", get_basic_auth_header(INTERNAL_CLIENT_ID));
    const char *refresher = json_object_get_string(tok);
    OIDC_LOG(DEBUG, "using refresh_token[%s]", jwt_payload(refresher));
    tlsuv_http_req_form(req, 3, (tlsuv_http_pair[]) {
        {"client_id",     INTERNAL_CLIENT_ID},
        {"grant_type",    "refresh_token"},
        {"refresh_token", refresher},
    });

    clt->refresh_req = req;
}
