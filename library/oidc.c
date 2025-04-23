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

#define TOKEN_EXCHANGE_GRANT "urn:ietf:params:oauth:grant-type:token-exchange"

#define HTTP_RESP_FMT "HTTP/1.0 %d %s\r\n"\
"Connection: close\r\n"\
"Content-Type: text/html\r\n"\
"Content-Length: %zd\r\n"\
"\r\n%s"


#if _WIN32
#define close_socket(s) closesocket(s)
#define sock_error WSAGetLastError()
#else
#define close_socket(s) close(s)
#define sock_error errno
#endif
#define OIDC_ACCEPT_TIMEOUT 30
#define OIDC_REQ_TIMEOUT 5

typedef struct oidc_req oidc_req;

typedef void (*oidc_cb)(oidc_req *, int status, json_object *resp);

static void oidc_client_set_tokens(oidc_client_t *clt, json_object *tok_json);

static void failed_auth_req(struct auth_req *req, const char *error);

static void refresh_time_cb(uv_timer_t *t);

struct oidc_req {
    oidc_client_t *client;
    json_tokener *parser;
    oidc_cb cb;
    void *ctx;
};

struct ext_link_req {
    uv_work_t wr;
    uv_os_sock_t sock;
    struct auth_req *req;
    char *code;
    int err;
};

typedef struct auth_req {
    oidc_client_t *clt;
    char code_verifier[code_verifier_len];
    char code_challenge[code_challenge_len];
    char state[state_code_len];
    json_tokener *json_parser;
    char *id;
    bool totp;
    struct ext_link_req *elr;
} auth_req;

static const char HTTP_SUCCESS_BODY[] =
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "    <title>OpenZiti: Successful Authentication with External Provider.</title>\n"
        "    <script>\n"
        "        function closeWindow() {\n"
        "            setTimeout(function() {\n"
        "                window.close(); // Close the current window\n"
        "            }, 3000);\n"
        "        }\n"
        "    </script>\n"
        "</head>\n"
        "<script type=\"text/javascript\">closeWindow()</script>"
        "<body onload=\"closeWindow()\">\n"
        "    <img height=\"40px\" src=\"https://openziti.io/img/ziti-logo-dark.svg\"/>"
        "    <h2>Successfully authenticated with external provider.</h2><p>You may close this page. It will attempt to close itself in 3 seconds.</p>\n"
        "</body>\n"
        "</html>\n";


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

static void unhandled_body_cb(tlsuv_http_req_t *r, char *data, ssize_t len) {
    if (len > 0) {
        ZITI_LOG(WARN, "%.*s", (int)len, data);
    } else {
        ZITI_LOG(WARN, "status = %zd\n", len);
    }
}

static void handle_unexpected_resp(tlsuv_http_resp_t *resp) {
    ZITI_LOG(WARN, "unexpected OIDC response");
    ZITI_LOG(WARN, "%s %d %s", resp->http_version, resp->code, resp->status);
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &resp->headers, _next) {
        ZITI_LOG(WARN, "%s: %s", h->name, h->value);
    }
    resp->body_cb = unhandled_body_cb;
}
static void parse_cb(tlsuv_http_resp_t *resp, void *ctx) {
    tlsuv_http_req_t *http_req = resp->req;
    oidc_req *req = http_req->data;

    assert(req != NULL);

    // connection failure
    if (resp->code < 0) {
        complete_oidc_req(req, resp->code, NULL);
        return;
    }

    const char *ct = tlsuv_http_resp_header(resp, "Content-Type");
    if (ct && strncmp(ct, "application/json", strlen("application/json")) == 0) {
        resp->body_cb = json_parse_cb;
        return;
    }

    ZITI_LOG(ERROR, "unexpected content-type[%s]: %s", resp->req->path, ct);
    complete_oidc_req(req, UV_EINVAL, NULL);
    resp->req->data = NULL;
    handle_unexpected_resp(resp);
}

int oidc_client_init(uv_loop_t *loop, oidc_client_t *clt,
                     const ziti_jwt_signer *cfg, tls_context *tls) {
    assert(clt != NULL);
    assert(cfg != NULL);
    if (cfg->provider_url == NULL) {
        ZITI_LOG(ERROR, "ziti_jwt_signer.provider_url is missing");
        return ZITI_INVALID_CONFIG;
    }

    clt->config = NULL;
    clt->tokens = NULL;
    clt->config_cb = NULL;
    clt->token_cb = NULL;
    clt->close_cb = NULL;
    clt->link_cb = NULL;
    clt->link_ctx = NULL;

    if (tlsuv_http_init(loop, &clt->http, cfg->provider_url) != 0) {
        ZITI_LOG(ERROR, "ziti_jwt_signer.provider_url[%s] is invalid", cfg->provider_url);
        return ZITI_INVALID_CONFIG;
    }
    int rc = oidc_client_set_cfg(clt, cfg);
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
    free_ziti_jwt_signer(&clt->signer_cfg);

    if (cfg->provider_url == NULL) {
        return ZITI_INVALID_CONFIG;
    }

    clt->signer_cfg.client_id = cfg->client_id ? strdup(cfg->client_id) : NULL;
    clt->signer_cfg.provider_url = strdup(cfg->provider_url);
    clt->signer_cfg.audience = cfg->audience ? strdup(cfg->audience) : NULL;
    clt->signer_cfg.target_token = cfg->target_token;
    const char *scope;
    MODEL_LIST_FOREACH(scope, cfg->scopes) {
        model_list_append(&clt->signer_cfg.scopes, strdup(scope));
    }
    return tlsuv_http_set_url(&clt->http, clt->signer_cfg.provider_url);
}

void oidc_client_set_link_cb(oidc_client_t *clt, oidc_ext_link_cb cb, void *ctx) {
    clt->mode = oidc_external;
    clt->link_cb = cb;
    clt->link_ctx = ctx;
}

static void internal_config_cb(oidc_req *req, int status, json_object *resp) {
    oidc_client_t *clt = req->client;
    if (status == 0) {
        // check expected configuration values are present and valid
        // to avoid surprises later
        if (json_object_get_type(resp) != json_type_object) {
            status = UV_EINVAL;
        } else if (json_object_object_get(resp, AUTH_EP) == NULL ||
                   json_object_object_get(resp, TOKEN_EP) == NULL) {
            ZITI_LOG(ERROR, "invalid OIDC config: %s and %s are required", AUTH_EP, TOKEN_EP);
            status = UV_EINVAL;
        }
    }

    if (status == 0) {
        json_object_put(clt->config);
        clt->config = resp;
        clt->refresh_grant = "refresh_token";
        // config has full URLs, so we can drop the prefix now
        tlsuv_http_set_path_prefix(&clt->http, "");

        struct json_object *grants = json_object_object_get(resp, "grant_types_supported");
        if (grants != NULL && json_object_is_type(grants, json_type_array)) {
            for (int i = 0; i < json_object_array_length(grants); i++) {
                struct json_object *g = json_object_array_get_idx(grants, i);
                const char *name = json_object_get_string(g);
                if (strcmp(name, TOKEN_EXCHANGE_GRANT) == 0) {
                    clt->refresh_grant = name;
                    break;
                }
            }
        }
        if (clt->token_cb != NULL) {
            oidc_client_start(clt, clt->token_cb);
        }
    }

    if (clt->config_cb) {
        clt->config_cb(clt, status, NULL);
    }
    clt->config_cb = NULL;
}

int oidc_client_configure(oidc_client_t *clt, oidc_config_cb cb) {
    clt->config_cb = cb;
    oidc_req *req = new_oidc_req(clt, internal_config_cb, NULL);
    tlsuv_http_req(&clt->http, "GET", OIDC_CONFIG, parse_cb, req);
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
    if (clt && clt->token_cb) {
        ZITI_LOG(WARN, "OIDC authorization failed: %s", error);
        clt->token_cb(clt, ZITI_AUTHENTICATION_FAILED, error);
        clt->request = NULL;
        clt = NULL;
    }

    if (req->elr) {
        req->elr->err = ECANCELED;
        if (uv_cancel((uv_req_t *) &req->elr->wr) == 0) {
            free(req->elr);
        }
    }

    free_auth_req(req);
}

static void parse_token_cb(tlsuv_http_req_t *r, char *body, ssize_t len) {
    auth_req *req = r->data;
    if (req == NULL) return;

    oidc_client_t *clt = req->clt;
    clt->request = NULL;
    int err;
    if (len > 0) {
        if (req->json_parser) {
            json_object *j = json_tokener_parse_ex(req->json_parser, body, (int) len);

            if (j != NULL) {
                oidc_client_set_tokens(clt, j);
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
    r->data = NULL;
    r->resp.body_cb = NULL;
    failed_auth_req(req, uv_strerror((int)len));
}

static void token_cb(tlsuv_http_resp_t *http_resp, void *ctx) {
    auth_req *req = ctx;
    ZITI_LOG(DEBUG, "%d %s", http_resp->code, http_resp->status);
    if (http_resp->code == 200) {
        req->json_parser = json_tokener_new();
        http_resp->body_cb = parse_token_cb;
    } else {
        failed_auth_req(req, http_resp->status);

        http_resp->req->data = NULL;
        handle_unexpected_resp(http_resp);
    }
}

static void request_token(auth_req *req, const char *auth_code) {
    oidc_client_t *clt = req->clt;
    json_object *token_ep = json_object_object_get(clt->config, TOKEN_EP);
    const char *token_url = json_object_get_string(token_ep);
    ZITI_LOG(INFO, "requesting token path[%s] auth[%s]", token_url, auth_code);
    tlsuv_http_set_url(&clt->http, token_url);
    tlsuv_http_req_t *token_req = tlsuv_http_req(&clt->http, "POST", NULL, token_cb, req);
    token_req->data = req;
    tlsuv_http_pair form[] = {
            {"state",         req->state},
            {"code",          auth_code},
            {"grant_type",    "authorization_code"},
            {"code_verifier", req->code_verifier},
            {"client_id",     clt->signer_cfg.client_id},
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

static void login_cb(tlsuv_http_resp_t *http_resp, void *ctx) {
    auth_req *req = ctx;
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

static void auth_cb(tlsuv_http_resp_t *http_resp, void *ctx) {
    auth_req *req = ctx;
    if (http_resp->code / 100 == 3) {
        const char *redirect = tlsuv_http_resp_header(http_resp, "Location");
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        char *p = strstr(uri.query, "authRequestID=");
        p += strlen("authRequestID=");
        req->id = strdup(p);
        const char *path = NULL;
        if (req->clt->jwt_token_auth) {
            path = "/oidc/login/ext-jwt";
        } else {
            path = "/oidc/login/cert";
        }
        ZITI_LOG(DEBUG, "login with path[%s] ", path);
        tlsuv_http_set_path_prefix(&req->clt->http, path);
        tlsuv_http_req_t *login_req = tlsuv_http_req(&req->clt->http, "POST", NULL, login_cb, req);
        if (req->clt->jwt_token_auth) {
            tlsuv_http_req_header(login_req, "Authorization", req->clt->jwt_token_auth);
        }
        tlsuv_http_req_form(login_req, 1, &(tlsuv_http_pair) {"id", p});
    } else {
        failed_auth_req(req, http_resp->status);
    }
}

static int set_blocking(uv_os_sock_t sock) {
    int yes = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
#ifdef _WIN32
    unsigned long mode = 0;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        int err = WSAGetLastError();
        ZITI_LOG(ERROR, "failed to set socket to blocking: %d", err);
        return err;
    }
#else
    int flags = fcntl(sock, F_GETFL, 0);
    flags = flags & ~O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) != 0) {
        int err = errno;
        ZITI_LOG(ERROR, "failed to set socket to blocking: %d/%s", err, strerror(err));
        return err;
    }
#endif
    return 0;
}

static void url_decode(const char *src, size_t src_len, char *dest) {
    char *p = dest;
    const char *end = src + src_len;
    while (src <= end) {
        if (*src == '%' && isxdigit((unsigned char) src[1]) && isxdigit((unsigned char) src[2])) {
            char hex[3] = { src[1], src[2], '\0' };
            *p++ = (char) strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *p++ = ' ';
            src++;
        } else {
            if (*src != '&') {
                *p++ = *src;
            }
            src++;
        }
    }
    *p = '\0';
}

static void ext_accept(uv_work_t *wr) {
    struct ext_link_req *elr = (struct ext_link_req *) wr;

    int rc;
    fd_set fds;
    uint64_t timeout = OIDC_ACCEPT_TIMEOUT;

    while(timeout > 0) {
        FD_ZERO(&fds);
        FD_SET(elr->sock, &fds);
        rc = select(elr->sock + 1, &fds, NULL, NULL, &(struct timeval) {
                .tv_sec = 1,
        });
        if (elr->err == ECANCELED) {
            close_socket(elr->sock);
            elr->sock = (uv_os_sock_t)-1;
            return;
        }
        if (rc == 0) {
            timeout--;
            continue;
        }

        if (rc < 0) {
            elr->err = sock_error;
            return;
        }

        break;
    }

    if (rc == 0) {
        elr->err = ETIMEDOUT;
        ZITI_LOG(WARN, "redirect_uri was not called in time");
        return;
    }

    uv_os_sock_t clt = accept(elr->sock, NULL, NULL);
    FD_ZERO(&fds);
    FD_SET(clt, &fds);
    rc = select(clt + 1, &fds, NULL, NULL, &(struct timeval){
            .tv_sec = OIDC_REQ_TIMEOUT,
    });
    if (rc <= 0) {
        elr->err = rc == 0 ? ETIMEDOUT : sock_error;
        close_socket(clt);
        return;
    }

    char buf[4096];
    ssize_t c;
#if _WIN32
    c = recv(clt, buf, sizeof(buf) -1, 0);
#else
    c = read(clt, buf, sizeof(buf) - 1);
#endif
    if (c < 0) {
        int err = sock_error;
        ZITI_LOG(ERROR, "read failed: %d/%s", err, strerror(err));
        elr->err = err;
        close_socket(clt);
        return;
    }

    buf[c] = 0;

    char *cs = strstr(buf, "code=");
    if (!cs) {
        ZITI_LOG(WARN, "no code parameter found: %s", buf);
        char resp[] = "HTTP/1.1 400 Invalid Request\r\n"
                      "Content-Type: text/html\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "<body>Unexpected auth request:<pre>";
#if _WIN32
        send(clt, resp, sizeof(resp), 0);
        send(clt, buf, c, 0);
#else
        write(clt, resp, sizeof(resp));
        write(clt, buf, c);
#endif
        close_socket(clt);
        return;
    }
    cs += strlen("code=");
    char *ce = strchr(cs, ' ');
    *ce = 0;
    char *amp = strchr(cs, '&');
    if (amp) {
        ce = amp;
    }

    size_t param_len = ce - cs;
    char* decoded_code = calloc(param_len + 1, sizeof(char));
    url_decode(cs, param_len, decoded_code);
    elr->code = decoded_code;

    string_buf_t resp_buf;
    string_buf_init(&resp_buf);

    string_buf_fmt(&resp_buf, HTTP_RESP_FMT, 200, "OK", strlen(HTTP_SUCCESS_BODY), HTTP_SUCCESS_BODY);
    size_t resp_len;
    char *resp = string_buf_to_string(&resp_buf, &resp_len);
    const char *rp = resp;

    while (resp_len > 0) {
        ssize_t wc =
#if _WIN32
                send(clt, rp, resp_len, 0);
#else
                write(clt, rp, resp_len);
#endif
        if (wc < 0) {
            int err =
#if _WIN32
                    WSAGetLastError();
#else
                    errno;
#endif
            ZITI_LOG(WARN, "failed to write HTTP resp: %d/%s", err, strerror(err));
            break;
        }
        resp_len -= wc;
        rp += wc;
    }

    free(resp);
    string_buf_free(&resp_buf);

#if _WIN32
    shutdown(clt, SD_SEND);
#else
    shutdown(clt, SHUT_WR);
#endif
    close_socket(clt);
}

static void ext_done(uv_work_t *wr, int status) {
    struct ext_link_req *elr = (struct ext_link_req *) wr;
    close_socket(elr->sock);
    elr->sock = (uv_os_sock_t)-1;

    if (elr->err) {
        ZITI_LOG(ERROR, "accept failed: %s", strerror(elr->err));
    }

    if (status != UV_ECANCELED && elr->err != ECANCELED) {
        struct auth_req *req = elr->req;
        req->elr = NULL;
        if (elr->code) {
            request_token(req, elr->code);
        } else {
            failed_auth_req(req, elr->err ? strerror(elr->err) : "code not received");
        }
    } else {

    }

    free(elr->code);
    free(elr);
}

static void start_ext_auth(auth_req *req, const char *ep, int qc, tlsuv_http_pair q[]) {
    uv_loop_t *loop = req->clt->timer->loop;
    struct sockaddr_in6 addr = {
            .sin6_family = AF_INET6,
            .sin6_addr = IN6ADDR_LOOPBACK_INIT,
            .sin6_port = htons(auth_cb_port),
    };
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    int off = 0;
    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#if defined(SO_REUSEPORT)
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
#if defined(IPV6_V6ONLY)
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
#endif
    if (bind(sock, (const struct sockaddr *) &addr, sizeof(addr)) || listen(sock, 1)) {
        failed_auth_req(req, strerror(errno));
        close_socket(sock);
        return;
    }
    set_blocking(sock);

    struct ext_link_req *elr = calloc(1, sizeof(*elr));
    elr->sock = sock;
    elr->req = req;
    int rc = uv_queue_work(loop, &elr->wr, ext_accept, ext_done);
    if (rc != 0) {
        free(elr);
        close_socket(sock);
        failed_auth_req(req, uv_strerror(rc));
        return;
    }

    string_buf_t *buf = new_string_buf();
    string_buf_append(buf, ep);
    for (int i = 0; i < qc; i++) {
        string_buf_append_byte(buf, (i == 0) ? '?' : '&');
        string_buf_append_urlsafe(buf, q[i].name);
        string_buf_append_byte(buf, '=');
        string_buf_append_urlsafe(buf, q[i].value);
    }
    char *url = string_buf_to_string(buf, NULL);

    req->elr = elr;
    req->clt->link_cb(req->clt, url, req->clt->link_ctx);

    free(url);
    delete_string_buf(buf);
}

int oidc_client_start(oidc_client_t *clt, oidc_token_cb cb) {
    clt->token_cb = cb;
    if (clt->config == NULL) {
        return 0;
    }
    json_object *cfg = (json_object *) clt->config;
    json_object *auth_ep = json_object_object_get(cfg, AUTH_EP);
    if (auth_ep  == NULL) {
        ZITI_LOG(ERROR, "OIDC configuration is missing `%s'", AUTH_EP);
        return ZITI_INVALID_CONFIG;
    }
    const char *auth_url = json_object_get_string(auth_ep);

    ZITI_LOG(DEBUG, "requesting authentication code from auth_url[%s]", auth_url);
    auth_req *req = new_auth_req(clt);
    clt->request = req;

    string_buf_t *scopes_buf = new_string_buf();
    string_buf_append(scopes_buf, default_scope);
    const char *s;
    MODEL_LIST_FOREACH(s, clt->signer_cfg.scopes) {
        string_buf_append(scopes_buf, " ");
        string_buf_append(scopes_buf, s);
    }

    char *scope = string_buf_to_string(scopes_buf, NULL);
    tlsuv_http_pair query[] = {
            {"client_id",             clt->signer_cfg.client_id},
            {"scope",                 scope},
            {"response_type",         "code"},
            {"redirect_uri",          default_cb_url},
            {"code_challenge",        req->code_challenge},
            {"code_challenge_method", "S256"},
            {"state",                 req->state},
            {"audience",              clt->signer_cfg.audience ?
                                      clt->signer_cfg.audience : "openziti"},
    };

    int rc = 0;
    if (clt->mode == oidc_external) {
        start_ext_auth(req, auth_url, sizeof(query)/sizeof(query[0]), query);
    } else {
        rc = tlsuv_http_set_url(&clt->http, auth_url);
        if (rc == 0) {
            tlsuv_http_req_t *http_req = tlsuv_http_req(&clt->http, "POST", NULL, auth_cb, req);
            rc = tlsuv_http_req_query(http_req, sizeof(query) / sizeof(query[0]), query);
        } else {
            ZITI_LOG(ERROR, AUTH_EP "[%s] is an invalid URL", auth_url);
        }
    }

    free(scope);
    delete_string_buf(scopes_buf);
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
    ZITI_LOG(VERBOSE, "%d:%s", resp->code, resp->status);

    int code = resp->code / 100;
    if (code == 3) {
        req->totp = false;
        const char *redirect = tlsuv_http_resp_header(resp, "Location");
        struct tlsuv_url_s uri;
        tlsuv_parse_url(&uri, redirect);
        tlsuv_http_req(&req->clt->http, "GET", uri.path, code_cb, req);
    } else if (code == 4) {
        ZITI_LOG(WARN, "totp failed: %s", resp->status);
        req->clt->token_cb(req->clt, OIDC_TOTP_FAILED, NULL);
    } else {
        ZITI_LOG(WARN, "totp request failed: %s", resp->status);
        req->clt->token_cb(req->clt, OIDC_TOTP_FAILED, NULL);
    }
}

int oidc_client_token(oidc_client_t *clt, const char *token) {
    string_buf_t *buf = new_string_buf();
    string_buf_fmt(buf, "Bearer %s", token);

    clt->jwt_token_auth = string_buf_to_string(buf, NULL);
    delete_string_buf(buf);
    return 0;
}

int oidc_client_mfa(oidc_client_t *clt, const char *code) {
    struct auth_req *req = clt->request;
    assert(req);

    tlsuv_http_req_t *r = tlsuv_http_req(&clt->http, "POST", "/oidc/login/totp", on_totp, req);
    tlsuv_http_req_form(r, 2, (tlsuv_http_pair[]){
            {"id", req->id},
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
    free_ziti_jwt_signer(&clt->signer_cfg);

    if (clt->request) {
        clt->request->clt = NULL;
        failed_auth_req(clt->request, strerror(ECANCELED));
    }

    return 0;
}

static const char *jwt_payload(const char *jwt) {
    static uint8_t payload[4096];
    size_t payload_len;

    jwt = strchr(jwt, '.');
    if (jwt == NULL) {
        ZITI_LOG(ERROR, "invalid JWT provided");
        return "<invalid JWT>";
    }

    jwt++;
    const char *end;
    if (sodium_base642bin(payload, sizeof(payload), jwt, strlen(jwt), NULL,
                          &payload_len, &end, sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0) {
        payload[payload_len] = '\0';
        return (const char*)payload;
    }
    return "<JWT too long?>";
}

static void oidc_client_set_tokens(oidc_client_t *clt, json_object *tok_json) {
    if (clt->tokens) {
        json_object_put(clt->tokens);
    }

    clt->tokens = tok_json;
    if (clt->token_cb) {
        const char *token_type;
        switch (clt->signer_cfg.target_token) {
            case ziti_target_token_id_token:
                token_type = "id_token";
                break;

            case ziti_target_token_access_token:
            case ziti_target_token_Unknown:
                token_type = "access_token";
                break;
        }

        struct json_object *jt = json_object_object_get(clt->tokens, token_type);
        if (jt) {
            const char *token = json_object_get_string(jt);
            ZITI_LOG(DEBUG, "using %s=%s", token_type, jwt_payload(token));
            clt->token_cb(clt, OIDC_TOKEN_OK, token);
        } else {
            ZITI_LOG(ERROR, "%s was not provided by IdP", token_type);
            clt->token_cb(clt, OIDC_TOKEN_FAILED, NULL);
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
        ZITI_LOG(WARN, "OIDC token refresh failed (trying again): %d/%s", status, uv_strerror(status));
        uv_timer_start(clt->timer, refresh_time_cb, 5 * 1000, 0);
    } else {
        ZITI_LOG(WARN, "OIDC token refresh failed: %d[%s]", status, json_object_to_json_string(resp));
        clt->token_cb(clt, OIDC_RESTART, NULL);
        if (resp) {
            json_object_put(resp);
        }
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
    ZITI_LOG(DEBUG, "refreshing OIDC token");
    struct json_object *tok = json_object_object_get(clt->tokens, "refresh_token");
    if (tok == NULL) {
        ZITI_LOG(DEBUG, "must restart authentication flow: no refresh_token");
        clt->token_cb(clt, OIDC_RESTART, NULL);
        return;
    }

    struct json_object *token_ep = json_object_object_get(clt->config, TOKEN_EP);
    const char *token_url = json_object_get_string(token_ep);
    oidc_req *refresh_req = new_oidc_req(clt, refresh_cb, clt);

    tlsuv_http_set_url(&clt->http, token_url);
    tlsuv_http_req_t *req = tlsuv_http_req(&clt->http, "POST", NULL, parse_cb, refresh_req);
    tlsuv_http_req_header(req, "Authorization",
                          get_basic_auth_header(clt->signer_cfg.client_id));
    const char *refresher = json_object_get_string(tok);
    if (clt->refresh_grant && strcmp(clt->refresh_grant, TOKEN_EXCHANGE_GRANT) == 0) {
        tlsuv_http_req_form(req, 4, (tlsuv_http_pair[]) {
                {"grant_type", TOKEN_EXCHANGE_GRANT},
                {"requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"},
                {"subject_token_type",   "urn:ietf:params:oauth:token-type:refresh_token"},
                {"subject_token",        refresher},
        });
    } else {
        tlsuv_http_req_form(req, 3, (tlsuv_http_pair[]) {
                {"client_id",     clt->signer_cfg.client_id},
                {"grant_type",    "refresh_token"},
                {"refresh_token", refresher},
        });
    }
}
