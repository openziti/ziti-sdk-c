// Copyright (c) 2023. NetFoundry Inc.
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
#include <json.h>
#include <sodium.h>
#include <ctype.h>
#include "ziti/ziti_log.h"
#include "utils.h"
#include "ziti/errors.h"
#include "ziti/ziti_buffer.h"
#include "ziti/ziti_model.h"

#define code_len 40
#define code_verifier_len sodium_base64_ENCODED_LEN(code_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
#define code_challenge_len sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING)

#define _str(x) #x
#define auth_cb_port 20314 /* 'OZ' */
#define auth_url_path "/auth/callback"
#define cb_url(host,port,path) "http://" host ":" _str(port) path
#define default_cb_url cb_url("localhost",auth_cb_port,auth_url_path)
#define default_scope "openid offline_access"
#define default_auth_header "Basic bmF0aXZlOg==" /* native: */

typedef struct oidc_req oidc_req;

typedef void (*oidc_cb)(oidc_req *, int status, json_object *resp);

static const char *get_endpoint_path(oidc_client_t *clt, const char *key);

static void oidc_client_set_tokens(oidc_client_t *clt, json_object *tok_json);

static void refresh_time_cb(uv_timer_t *t);

struct oidc_req {
    oidc_client_t *client;
    json_tokener *parser;
    oidc_cb cb;
    void *ctx;
};

typedef struct auth_req {
    oidc_client_t *clt;
    char code_verifier[code_verifier_len];
    char code_challenge[code_challenge_len];
    char state[16];
    json_tokener *json_parser;
    char *id;
    bool totp;
} auth_req;

static oidc_req *new_oidc_req(oidc_client_t *clt, oidc_cb cb, void *ctx) {
    oidc_req *res = calloc(1, sizeof(*res));
    res->client = clt;
    res->cb = cb;

    res->parser = json_tokener_new();
    res->ctx = ctx;
    return res;
}

static void complete_oidc_req(oidc_req *req, int err, json_object *obj) {
    req->cb(req, err, obj);
    json_tokener_free(req->parser);
    free(req);
}

static void json_parse_cb(tlsuv_http_req_t *r, char *data, ssize_t len) {
    oidc_req *req = r->data;
    if (req == NULL) {
        return;
    }

    if (len > 0) {
        ZITI_LOG(TRACE, "data: %.*s", (int)len, data);
        json_object *res = json_tokener_parse_ex(req->parser, data, (int) len);
        if (res) {
            int status = r->resp.code == HTTP_STATUS_OK ? 0 : r->resp.code;
            complete_oidc_req(req, status, res);
            r->data = NULL;
        }
        return;
    }

    if (len == UV_EOF) {
        complete_oidc_req(req, UV_EOF, NULL);
        return;
    }
}

static void dump_cb(tlsuv_http_req_t *r, char *data, ssize_t len) {
    if (len > 0) {
        ZITI_LOG(WARN, "unexpected data %.*s", (int)len, data);
    } else {
        oidc_req *req = r->data;
        fprintf(stderr, "status = %zd\n", len);
        complete_oidc_req(req, (int)len, NULL);
    }
}
static void dump_resp(tlsuv_http_resp_t *resp) {
    printf("%s %d %s\n", resp->http_version, resp->code, resp->status);
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &resp->headers, _next) {
        printf("%s: %s\n", h->name, h->value);
    }
}
static void parse_cb(tlsuv_http_resp_t *resp, void *ctx) {
    tlsuv_http_req_t *http_req = resp->req;
    oidc_req *req = http_req->data;

    assert(req != NULL);

    // connection failure
    if (resp->code < 0) {
        req->cb(req, resp->code, NULL);
        free(req);
        return;
    }

    const char *ct = tlsuv_http_resp_header(resp, "Content-Type");
    if (ct && strncmp(ct, "application/json", strlen("application/json")) == 0) {
        resp->body_cb = json_parse_cb;
        return;
    }

    ZITI_LOG(ERROR, "unexpected content-type: %s", ct);
    resp->body_cb = dump_cb;
}

int oidc_client_init(uv_loop_t *loop, oidc_client_t *clt,
                     const ziti_jwt_signer *cfg, tls_context *tls) {
    assert(clt != NULL);
    assert(cfg != NULL);
    assert(cfg->provider_url != NULL);

    clt->config = NULL;
    clt->tokens = NULL;
    clt->config_cb = NULL;
    clt->token_cb = NULL;
    clt->close_cb = NULL;
    clt->link_cb = NULL;
    clt->link_ctx = NULL;

    clt->signer_cfg = cfg;

    int rc = tlsuv_http_init(loop, &clt->http, clt->signer_cfg->provider_url);
    if (rc != 0) {
        return rc;
    }
    tlsuv_http_set_ssl(&clt->http, tls);

    clt->timer = calloc(1, sizeof(*clt->timer));
    uv_timer_init(loop, clt->timer);
    clt->timer->data = clt;
    uv_unref((uv_handle_t *) clt->timer);

    return 0;
}

int oidc_client_set_cfg(oidc_client_t *clt, const ziti_jwt_signer *cfg) {
    clt->signer_cfg = cfg;
    tlsuv_http_set_url(&clt->http, clt->signer_cfg->provider_url);
    return 0;
}

void oidc_client_set_link_cb(oidc_client_t *clt, oidc_ext_link_cb cb, void *ctx) {
    clt->mode = oidc_external;
    clt->link_cb = cb;
    clt->link_ctx = ctx;
}

static void internal_config_cb(oidc_req *req, int status, json_object *resp) {
    oidc_client_t *clt = req->client;

    if (status == 0) {
        assert(json_object_get_type(resp) == json_type_object);
        json_object_put(clt->config);
        clt->config = resp;
    }

    if (clt->config_cb) {
        clt->config_cb(clt, status, NULL);
    }
    clt->config_cb = NULL;
}

int oidc_client_configure(oidc_client_t *clt, oidc_config_cb cb) {
    clt->config_cb = cb;
    oidc_req *req = new_oidc_req(clt, internal_config_cb, NULL);
    tlsuv_http_req(&clt->http, "GET", "/.well-known/openid-configuration", parse_cb, req);
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
    return req;
}

static void free_auth_req(auth_req *req) {
    if (req == NULL) return;

    if (req->json_parser) {
        json_tokener_free(req->json_parser);
        req->json_parser = NULL;
    }
    free(req);
}

static void failed_auth_req(auth_req *req, const char *error) {
    if (req->clt->token_cb) {
        ZITI_LOG(WARN, "OIDC authorization failed: %s", error);
        req->clt->token_cb(req->clt, ZITI_AUTHENTICATION_FAILED, NULL);
    }
    free_auth_req(req);
}

static void parse_token_cb(tlsuv_http_req_t *r, char *body, ssize_t len) {
    auth_req *req = r->data;
    int err;
    if (len > 0) {
        if (req->json_parser) {
            json_object *j = json_tokener_parse_ex(req->json_parser, body, (int) len);

            if (j != NULL) {
                oidc_client_set_tokens(req->clt, j);
                r->data = NULL;
                r->resp.body_cb = NULL;
                free_auth_req(req);
            } else {
                if ((err = json_tokener_get_error(req->json_parser)) != json_tokener_continue) {
                    r->data = NULL;
                    r->resp.body_cb = NULL;
                    failed_auth_req(req, json_tokener_error_desc(err));
                }
            }
        }
        return;
    }

    // error before req is complete
    if (req) {
        failed_auth_req(req, uv_strerror((int) len));
    }
}

static void token_cb(tlsuv_http_resp_t *http_resp, void *ctx) {
    auth_req *req = ctx;
    ZITI_LOG(DEBUG, "%d %s", http_resp->code, http_resp->status);
    if (http_resp->code == 200) {
        req->json_parser = json_tokener_new();
        http_resp->body_cb = parse_token_cb;
    } else {
        dump_resp(http_resp);
        http_resp->body_cb = dump_cb;
        failed_auth_req(req, http_resp->status);
    }
}

static void request_token(auth_req *req, const char *auth_code) {
    ZITI_LOG(INFO, "requesting token auth[%s]", auth_code);
    const char *path = get_endpoint_path(req->clt, "token_endpoint");
    tlsuv_http_req_t *token_req = tlsuv_http_req(&req->clt->http, "POST", path, token_cb, req);
    token_req->data = req;
    tlsuv_http_req_form(token_req, 6, (tlsuv_http_pair[]) {
            {"code",          auth_code},
            {"grant_type",    "authorization_code"},
            {"code_verifier", req->code_verifier},
            {"client_id",     req->clt->signer_cfg->client_id},
            {"redirect_uri",  default_cb_url},
            {"state",         req->state},
    });
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

static void login_parse_cb(tlsuv_http_req_t *hr, char *data, ssize_t len) {
    printf("%zd: %.*s\n", len, (int)len, data);
}
static void login_cb(tlsuv_http_resp_t *http_resp, void *ctx) {
    auth_req *req = ctx;
    if (http_resp->code / 100 == 2) {
        const char *totp = tlsuv_http_resp_header(http_resp, "totp-required");
        if (totp && tolower(totp[0]) == 't') {
            req->totp = true;
            req->clt->request = req;
            req->clt->token_cb(req->clt, OIDC_TOPT_NEEDED, NULL);
        }
    } else if (http_resp->code / 100 == 3) {
        const char *redirect = tlsuv_http_resp_header(http_resp, "Location");
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);

        tlsuv_http_req(&req->clt->http, "GET", uri.path, code_cb, req);
    } else {
        failed_auth_req(req, http_resp->status);
    }
}

static void auth_cb(tlsuv_http_resp_t *http_resp, void *ctx) {
    auth_req *req = ctx;
    if (http_resp->code / 100 == 3) {
        const char *redirect = tlsuv_http_resp_header(http_resp, "Location");
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        char *p = strstr(uri.query, "authRequestID=");
        p += strlen("authRequestID=");
        req->id = strdup(p);

        ZITI_LOG(DEBUG, "logging in with cert auth");
        tlsuv_http_req_t *login_req = tlsuv_http_req(&req->clt->http, "POST", redirect, login_cb, req);
        tlsuv_http_req_form(login_req, 1, &(tlsuv_http_pair) {"id", p});
    } else {
        failed_auth_req(req, http_resp->status);
    }
}

struct ext_link_req {
    uv_work_t wr;
    uv_os_sock_t sock;
    auth_req *req;
    char *code;
};

static void ext_accept(uv_work_t *wr) {
    struct ext_link_req *elr = (struct ext_link_req *) wr;
    uv_os_sock_t clt = accept(elr->sock, NULL, NULL);
    char buf[1024];
    ssize_t c = read(clt, buf, sizeof(buf) - 1);
    buf[c] = 0;

    char *cs = strstr(buf, "code=");
    if (!cs) {
        ZITI_LOG(WARN, "no code parameter found: %s", buf);
        char resp[] = "HTTP/1.1 400 Invalid Request\r\n"
                      "Content-Type: text/html\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "<body>Unexpected auth request:<pre>";
        write(clt, resp, sizeof(resp));
        write(clt, buf, c);
        close(clt);
        return;
    }
    cs += strlen("code=");
    char *ce = strchr(cs, ' ');
    *ce = 0;
    char *amp = strchr(cs, '&');
    if (amp) {
        ce = amp;
    }

    char *code = calloc(1, ce - cs + 1);
    memcpy(code, cs, ce - cs);
    elr->code = code;

    char resp[] = "HTTP/1.1 200 OK\r\n"
                  "Content-Type: text/html\r\n"
                  "\r\n"
                  "<script type=\"text/javascript\">window.close()</script>"
                  "<body onload=\"window.close()\">You may close this window</body>";
    write(clt, resp, sizeof(resp));
    close(clt);
}

static void ext_done(uv_work_t *wr, int status) {
    struct ext_link_req *elr = (struct ext_link_req *) wr;
    close(elr->sock);

    if (elr->code) {
        request_token(elr->req, elr->code);
    } else {
        failed_auth_req(elr->req, "code not received");
    }

    free(elr->code);
    free(elr);
}

static void start_ext_auth(auth_req *req, const char *ep, int qc, tlsuv_http_pair q[]) {
    string_buf_t *buf = new_string_buf();
    string_buf_append(buf, ep);
    for (int i = 0; i < qc; i++) {
        string_buf_append_byte(buf, (i == 0) ? '?' : '&');
        string_buf_append_urlsafe(buf, q[i].name);
        string_buf_append_byte(buf, '=');
        string_buf_append_urlsafe(buf, q[i].value);
    }

    char *url = string_buf_to_string(buf, NULL);
    struct ext_link_req *elr = calloc(1, sizeof(*elr));
    uv_loop_t *loop = req->clt->timer->loop;
    struct sockaddr_in addr = {
            .sin_addr = INADDR_ANY,
            .sin_port = htons(auth_cb_port),
    };
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("sock = %d\n", sock);
    if (bind(sock, (const struct sockaddr *) &addr, sizeof(addr))) {
        perror("bind");
    }
    if (listen(sock, 1)) {
        perror("listen");
    }

    req->clt->link_cb(req->clt, url, req->clt->link_ctx);

    elr->sock = sock;
    elr->req = req;
    uv_queue_work(loop, &elr->wr, ext_accept, ext_done);

    free(url);
    delete_string_buf(buf);
}

int oidc_client_start(oidc_client_t *clt, oidc_token_cb cb) {
    clt->token_cb = cb;
    ZITI_LOG(DEBUG, "requesting authentication code");
    auth_req *req = new_auth_req(clt);

    char scope[256] = default_scope;
    if (clt->signer_cfg->claim) {
        snprintf(scope, sizeof(scope), "%s " default_scope, clt->signer_cfg->claim);
    }

    const char *path = get_endpoint_path(clt, "authorization_endpoint");
    tlsuv_http_pair query[] = {
            {"client_id",             clt->signer_cfg->client_id},
            {"scope",                 scope},
            {"response_type",         "code"},
            {"redirect_uri",          default_cb_url},
            {"code_challenge",        req->code_challenge},
            {"code_challenge_method", "S256"},
            {"audience",              clt->signer_cfg->audience ?
                                      clt->signer_cfg->audience : "openziti"},
    };

    if (clt->mode == oidc_external) {
        struct json_object *cfg = (struct json_object *) clt->config;
        struct json_object *auth = json_object_object_get(cfg, "authorization_endpoint");
        start_ext_auth(req, json_object_get_string(auth), sizeof(query)/sizeof(query[0]), query);
        return 0;
    }

    tlsuv_http_req_t *http_req = tlsuv_http_req(&clt->http, "POST", path, auth_cb, req);
    int rc = tlsuv_http_req_query(http_req, sizeof(query)/sizeof(query[0]), query);
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
static void on_topt(tlsuv_http_resp_t *resp, void *ctx) {
    dump_resp(resp);
    resp->body_cb =  dump_cb;
}

int oidc_client_mfa(oidc_client_t *clt, const char *code) {
    struct auth_req *req = clt->request;
    assert(req);

    tlsuv_http_req_t *r = tlsuv_http_req(&clt->http, "POST", "/oidc/login/totp", on_topt, req);
    tlsuv_http_req_form(r, 2, (tlsuv_http_pair[]){
        {"id", "req->id"},
        {"code", code},
    });
    return 0;
}

int oidc_client_refresh(oidc_client_t *clt) {
    if (clt->timer == NULL || uv_is_closing((const uv_handle_t *) clt->timer)) {
        return UV_EINVAL;
    }

    uv_ref((uv_handle_t *) clt->timer);
    return uv_timer_start(clt->timer, refresh_time_cb, 0, 0);
}

int oidc_client_close(oidc_client_t *clt, oidc_close_cb cb) {
    if (clt->close_cb) {
        return UV_EALREADY;
    }
    clt->token_cb = NULL;
    clt->close_cb = cb;
    tlsuv_http_close(&clt->http, http_close_cb);
    uv_close((uv_handle_t *) clt->timer, (uv_close_cb) free);
    clt->timer = NULL;
    return 0;
}

static void oidc_client_set_tokens(oidc_client_t *clt, json_object *tok_json) {
    if (clt->tokens) {
        json_object_put(clt->tokens);
    }

    clt->tokens = tok_json;
    if (clt->token_cb) {
        struct json_object *access_token = json_object_object_get(clt->tokens, "access_token");
        if (access_token) {
            clt->token_cb(clt, OIDC_TOKEN_OK, json_object_get_string(access_token));
        }
    }
    struct json_object *refresher = json_object_object_get(clt->tokens, "refresh_token");
    struct json_object *ttl = json_object_object_get(clt->tokens, "expires_in");
    if (clt->timer && refresher && ttl) {
        int32_t t = json_object_get_int(ttl);
        ZITI_LOG(DEBUG, "scheduling token refresh in %d seconds", t);
        uv_timer_start(clt->timer, refresh_time_cb, t * 1000, 0);
    }
}

static void refresh_cb(oidc_req *req, int status, json_object *resp) {
    oidc_client_t *clt = req->client;
    if (status == 0) {
        ZITI_LOG(DEBUG,  "token refresh success");
        oidc_client_set_tokens(clt, resp);
    } else if (status < 0) {  // connection failure, try another refresh
        clt->token_cb(clt, status, NULL);
        ZITI_LOG(WARN, "OIDC token refresh failed: %d/%s", status, uv_strerror(status));
        uv_timer_start(clt->timer, refresh_time_cb, 5 * 1000, 0);
    } else {
        ZITI_LOG(WARN, "OIDC token refresh failed: %d[%s]", status, json_object_to_json_string(resp));
        oidc_client_start(clt, clt->token_cb);
        if (resp) {
            json_object_put(resp);
        }
    }
}

static void refresh_time_cb(uv_timer_t *t) {
    uv_unref((uv_handle_t *) t);
    oidc_client_t *clt = t->data;
    ZITI_LOG(DEBUG, "refreshing OIDC token");

    const char *path = get_endpoint_path(clt, "token_endpoint");
    struct json_object *tok = json_object_object_get(clt->tokens, "refresh_token");
    oidc_req *refresh_req = new_oidc_req(clt, refresh_cb, clt);
    
    tlsuv_http_req_t *req = tlsuv_http_req(&clt->http, "POST", path, parse_cb, refresh_req);
    tlsuv_http_req_header(req, "Authorization", default_auth_header);
    const char *refresher = json_object_get_string(tok);
    tlsuv_http_req_form(req, 4, (tlsuv_http_pair[]) {
            {"grant_type",           "urn:ietf:params:oauth:grant-type:token-exchange"},
            {"requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"},
            {"subject_token_type",   "urn:ietf:params:oauth:token-type:refresh_token"},
            {"subject_token",        refresher},
    });
}

static const char *get_endpoint_path(oidc_client_t *clt, const char *key) {
    assert(clt->config);
    struct json_object *json = json_object_object_get(clt->config, key);
    assert(json);
    const char *url = json_object_get_string(json);
    struct tlsuv_url_s u;
    tlsuv_parse_url(&u, url);
    return u.path;
}