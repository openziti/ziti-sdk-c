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

#include <oidc.h>
#include <assert.h>
#include <json-c/json.h>
#include <sodium.h>
#include <ctype.h>
#ifdef _WIN32
#include <winsock2.h>
#define poll(fds,n,to) WSAPoll(fds, n, to)
#else
#include <unistd.h>
#include <sys/poll.h>
#endif

#include "ziti/ziti_log.h"
#include "utils.h"
#include "ziti/errors.h"
#include "ziti/ziti_buffer.h"
#include "ext_oidc.h"
#include "ext_oidc_pages.h"
#include "buffer.h"

#define INVALID_SOCK ((uv_os_sock_t) -1)
#define PENDING_WATCHDOG_MS (60 * 1000)

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
#define default_scope "openid offline_access"

#define AUTH_EP "authorization_endpoint"
#define TOKEN_EP "token_endpoint"
#define OIDC_CONFIG ".well-known/openid-configuration"

#define TOKEN_EXCHANGE_GRANT "urn:ietf:params:oauth:grant-type:token-exchange"

#define HTTP_RESP_FMT "HTTP/1.0 %d %s\r\n"\
"Connection: close\r\n"\
"Content-Type: text/html\r\n"\
"Cache-Control: no-store\r\n"\
"X-Content-Type-Options: nosniff\r\n"\
"Content-Length: %zd\r\n"\
"\r\n%s"


#if _WIN32
#define close_socket(s) closesocket(s)
#define sock_error WSAGetLastError()
#else
#define close_socket(s) close(s)
#define sock_error errno
#endif
#define OIDC_ACCEPT_TIMEOUT 60
#define OIDC_REQ_TIMEOUT 5

#define OIDC_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "oidc[%s] " fmt, clt->name, ##__VA_ARGS__)

static void ext_oidc_client_set_tokens(ext_oidc_client_t *clt, json_object *tok_json);

static int ext_oidc_client_set_cfg(ext_oidc_client_t *clt, const ziti_jwt_signer *cfg);

static void failed_auth_req(struct auth_req *req, const char *error);

static void ext_refresh_time_cb(uv_timer_t *t);

static uint64_t ext_oidc_refresh_delay(ext_oidc_client_t *clt);

struct ext_link_req {
    uv_work_t wr;
    uv_os_sock_t sock;
    uv_os_sock_t clt_sock;
    struct auth_req *req;
    char *code;
    int err;
};

typedef struct auth_req {
    ext_oidc_client_t *clt;
    char code_verifier[code_verifier_len];
    char code_challenge[code_challenge_len];
    char state[state_code_len];
    json_tokener *json_parser;
    char *id;
    struct ext_link_req *elr;
    uv_os_sock_t clt_sock;
} auth_req;

// claims with no debugging value that may also be sensitive (session/correlation IDs)
static const char *OPAQUE_CLAIMS[] = { "jti", "sid", "nonce", NULL };

static void append_html_escaped(string_buf_t *buf, const char *s) {
    if (s == NULL) return;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '&':  string_buf_append(buf, "&amp;");  break;
            case '<':  string_buf_append(buf, "&lt;");   break;
            case '>':  string_buf_append(buf, "&gt;");   break;
            case '"':  string_buf_append(buf, "&quot;"); break;
            case '\'': string_buf_append(buf, "&#39;");  break;
            default:   string_buf_append_byte(buf, *p);  break;
        }
    }
}

// Build the failure-page HTML, optionally including a details disclosure with
// the failing step, the error message, and the decoded JWT claims. The JWT
// claim block strips opaque session-correlation fields (see OPAQUE_CLAIMS).
// Caller must free() the returned string.
static char *build_failure_body(const char *step, const char *error, const char *jwt) {
    string_buf_t buf;
    string_buf_init(&buf);

    string_buf_append(&buf, HTTP_FAILURE_HEADER);

    if (step || error || jwt) {
        string_buf_append(&buf, "    <details><summary>Show details</summary>\n");
        string_buf_append(&buf, "      <dl class=\"details-body\">\n");

        if (step) {
            string_buf_append(&buf, "        <dt>Step</dt><dd>");
            append_html_escaped(&buf, step);
            string_buf_append(&buf, "</dd>\n");
        }
        if (error) {
            string_buf_append(&buf, "        <dt>Error</dt><dd>");
            append_html_escaped(&buf, error);
            string_buf_append(&buf, "</dd>\n");
        }
        if (jwt) {
            // jwt_payload returns a pointer to a static buffer that any
            // future jwt_payload() call would clobber - copy it so the
            // pretty-print fallback path remains valid.
            char *raw = strdup(jwt_payload(jwt));
            json_object *parsed = json_tokener_parse(raw);
            if (parsed) {
                for (int i = 0; OPAQUE_CLAIMS[i]; i++) {
                    json_object_object_del(parsed, OPAQUE_CLAIMS[i]);
                }
            }
            const char *pretty = parsed
                ? json_object_to_json_string_ext(parsed, JSON_C_TO_STRING_PRETTY)
                : raw;
            string_buf_append(&buf, "        <dt>Token claims</dt><dd><pre>");
            append_html_escaped(&buf, pretty);
            string_buf_append(&buf, "</pre></dd>\n");
            if (parsed) json_object_put(parsed);
            free(raw);
        }

        string_buf_append(&buf, "      </dl>\n");
        string_buf_append(&buf, "    </details>\n");
    }

    string_buf_append(&buf, HTTP_FAILURE_FOOTER);

    return string_buf_to_string(&buf, NULL);
}


static void handle_unexpected_resp(ext_oidc_client_t *clt, tlsuv_http_resp_t *resp, json_object *body) {
    OIDC_LOG(WARN, "unexpected OIDC response");
    OIDC_LOG(WARN, "%s %d %s", resp->http_version, resp->code, resp->status);
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &resp->headers, _next) {
        OIDC_LOG(WARN, "%s: %s", h->name, h->value);
    }
    OIDC_LOG(WARN, "%s", json_object_get_string(body));
}

int ext_oidc_client_init(uv_loop_t *loop, ext_oidc_client_t *clt,
                     const ziti_jwt_signer *cfg) {
    assert(clt != NULL);
    assert(cfg != NULL);
    if (cfg->provider_url == NULL) {
        ZITI_LOG(ERROR, "ziti_jwt_signer.provider_url is missing");
        return ZITI_INVALID_CONFIG;
    }

    snprintf(clt->name, sizeof(clt->name), "%s", cfg->name ? cfg->name : cfg->provider_url);
    OIDC_LOG(INFO, "initializing with provider[%s]", cfg->provider_url);

    // free previous auth params if re-initializing
    if (clt->auth_params) {
        for (int i = 0; i < clt->auth_params_count; i++) {
            free((void *)clt->auth_params[i].name);
            free((void *)clt->auth_params[i].value);
        }
        free(clt->auth_params);
        clt->auth_params = NULL;
        clt->auth_params_count = 0;
    }

    clt->config = NULL;
    clt->tokens = NULL;
    clt->token_cb = NULL;
    clt->close_cb = NULL;
    clt->link_cb = NULL;
    clt->link_ctx = NULL;

    if (tlsuv_http_init(loop, &clt->http, cfg->provider_url) != 0) {
        OIDC_LOG(ERROR, "ziti_jwt_signer.provider_url[%s] is invalid", cfg->provider_url);
        return ZITI_INVALID_CONFIG;
    }
    int rc = ext_oidc_client_set_cfg(clt, cfg);
    if (rc != 0) {
        return rc;
    }

    tlsuv_http_connect_timeout(&clt->http, 10 * 1000);
    tlsuv_http_idle_keepalive(&clt->http, 0); // no reason to keep idle connections
    tlsuv_http_header(&clt->http, HTTP_ACCEPT, APPLICATION_JSON);

    clt->timer = calloc(1, sizeof(*clt->timer));
    uv_timer_init(loop, clt->timer);
    clt->timer->data = clt;
    uv_unref((uv_handle_t *) clt->timer);

    clt->pending_sock = INVALID_SOCK;
    clt->pending_timer = calloc(1, sizeof(*clt->pending_timer));
    uv_timer_init(loop, clt->pending_timer);
    clt->pending_timer->data = clt;
    uv_unref((uv_handle_t *) clt->pending_timer);

    return 0;
}

int ext_oidc_client_set_cfg(ext_oidc_client_t *clt, const ziti_jwt_signer *cfg) {
    free_ziti_jwt_signer(&clt->signer_cfg);

    clt->signer_cfg.client_id = cfg->client_id ? strdup(cfg->client_id) : NULL;
    clt->signer_cfg.provider_url = strdup(cfg->provider_url);
    clt->signer_cfg.audience = cfg->audience ? strdup(cfg->audience) : NULL;
    clt->signer_cfg.target_token = cfg->target_token;
    clt->signer_cfg.can_token_enroll = cfg->can_token_enroll;
    clt->signer_cfg.can_cert_enroll = cfg->can_cert_enroll;
    const char *scope;
    MODEL_LIST_FOREACH(scope, cfg->scopes) {
        model_list_append(&clt->signer_cfg.scopes, strdup(scope));
    }
    return tlsuv_http_set_url(&clt->http, clt->signer_cfg.provider_url);
}

void ext_oidc_client_set_link_cb(ext_oidc_client_t *clt, ext_oidc_link_cb cb, void *ctx) {
    clt->link_cb = cb;
    clt->link_ctx = ctx;
}

static void internal_config_cb(tlsuv_http_resp_t *r, const char * err, json_object *resp, void *ctx) {
    ext_oidc_client_t *clt = ctx;
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

    if (status == 0) {
        json_object_put(clt->config);
        clt->config = json_object_get(resp);
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
            ext_oidc_client_start(clt, clt->token_cb);
        }
    } else {
        OIDC_LOG(ERROR, "OIDC provider configuration failed: %s", err);
        if (clt->token_cb) {
            clt->token_cb(clt, EXT_OIDC_CONFIG_FAILED, err);
        }
    }
}

int ext_oidc_client_configure(ext_oidc_client_t *clt, oidc_config_cb cb) {
    if (clt->request) return UV_EALREADY;

    OIDC_LOG(DEBUG, "configuring provider[%s]", clt->signer_cfg.provider_url);
    tlsuv_http_set_url(&clt->http, clt->signer_cfg.provider_url);
    ziti_json_request(&clt->http, "GET", OIDC_CONFIG, internal_config_cb, clt);
    return 0;
}

static void send_callback_response(uv_os_sock_t sock, const char *body) {
    if (sock == INVALID_SOCK) return;

    string_buf_t resp_buf;
    string_buf_init(&resp_buf);
    string_buf_fmt(&resp_buf, HTTP_RESP_FMT, 200, "OK", strlen(body), body);

    size_t resp_len;
    char *resp = string_buf_to_string(&resp_buf, &resp_len);
    const char *rp = resp;

    while (resp_len > 0) {
        ssize_t wc =
#if _WIN32
                send(sock, rp, resp_len, 0);
#else
                write(sock, rp, resp_len);
#endif
        if (wc < 0) {
            int err = sock_error;
            ZITI_LOG(WARN, "failed to write HTTP resp: %d/%s", err, strerror(err));
            break;
        }
        resp_len -= wc;
        rp += wc;
    }

    free(resp);
    string_buf_free(&resp_buf);

#if _WIN32
    shutdown(sock, SD_SEND);
#else
    shutdown(sock, SHUT_WR);
#endif
    close_socket(sock);
}

static auth_req *new_auth_req(ext_oidc_client_t *clt) {
    auth_req *req = calloc(1, sizeof(*req));
    req->clt = clt;
    req->clt_sock = INVALID_SOCK;

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
    if (req->clt_sock != INVALID_SOCK) {
        close_socket(req->clt_sock);
        req->clt_sock = INVALID_SOCK;
    }
    FREE(req->id);
    free(req);
}

static void failed_auth_req(auth_req *req, const char *error) {
    if (req->clt_sock != INVALID_SOCK) {
        char *body = build_failure_body("OIDC token exchange", error, NULL);
        send_callback_response(req->clt_sock, body);
        free(body);
        req->clt_sock = INVALID_SOCK;
    }

    ext_oidc_client_t *clt = req->clt;
    if (clt) {
        if (clt->request == req) {
            clt->request = NULL;
        }

        if (clt->token_cb) {
            OIDC_LOG(WARN, "OIDC authorization failed: %s", error);
            clt->token_cb(clt, EXT_OIDC_TOKEN_FAILED, error);
            clt->request = NULL;
            clt = NULL;
        }
    }

    if (req->elr) {
        req->elr->err = ECANCELED;
        if (uv_cancel((uv_req_t *) &req->elr->wr) == 0) {
            free(req->elr);
        }
    }

    free_auth_req(req);
}

static void pending_watchdog_cb(uv_timer_t *t) {
    ext_oidc_client_t *clt = t->data;
    OIDC_LOG(WARN, "controller did not respond within %dms; closing browser callback",
             PENDING_WATCHDOG_MS);
    ext_oidc_client_finalize(clt, false, "controller did not respond in time");
}

static void start_pending_watchdog(ext_oidc_client_t *clt) {
    if (clt->pending_timer == NULL) return;
    uv_ref((uv_handle_t *) clt->pending_timer);
    uv_timer_start(clt->pending_timer, pending_watchdog_cb, PENDING_WATCHDOG_MS, 0);
}

static void stop_pending_watchdog(ext_oidc_client_t *clt) {
    if (clt->pending_timer == NULL) return;
    uv_timer_stop(clt->pending_timer);
    uv_unref((uv_handle_t *) clt->pending_timer);
}

static void token_cb(tlsuv_http_resp_t *http_resp, const char *err, json_object *resp, void *ctx) {
    auth_req *req = ctx;
    ext_oidc_client_t *clt = req->clt;
    OIDC_LOG(DEBUG, "%d %s err[%s]", http_resp->code, http_resp->status, err);
    if (http_resp->code == 200) {
        if (req->clt_sock != INVALID_SOCK) {
            // hold the browser response until the controller verdict
            // (ext_oidc_client_finalize will write success or failure page)
            if (clt->pending_sock != INVALID_SOCK) {
                OIDC_LOG(WARN, "previous browser callback still pending; closing it");
                close_socket(clt->pending_sock);
                stop_pending_watchdog(clt);
            }
            clt->pending_sock = req->clt_sock;
            req->clt_sock = INVALID_SOCK;
            start_pending_watchdog(clt);
        }
        ext_oidc_client_set_tokens(clt, resp);
        clt->request = NULL;
        free_auth_req(req);
    } else {
        failed_auth_req(req, http_resp->status);
        http_resp->req->data = NULL;
        handle_unexpected_resp(clt, http_resp, resp);
    }
}

static void request_token(auth_req *req, const char *auth_code) {
    ext_oidc_client_t *clt = req->clt;
    json_object *token_ep = json_object_object_get(clt->config, TOKEN_EP);
    const char *token_url = json_object_get_string(token_ep);
    ZITI_LOG(INFO, "requesting token path[%s] auth[%s]", token_url, auth_code);
    tlsuv_http_set_url(&clt->http, token_url);
    tlsuv_http_req_t *token_req = ziti_json_request(&clt->http, "POST", NULL, token_cb, req);
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

static void free_body_cb(tlsuv_http_req_t * UNUSED(req), char *body, ssize_t UNUSED(len)) {
    free(body);
}

static int set_blocking(uv_os_sock_t sock) {
    int yes = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *) &yes, sizeof(yes));
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
    while (src < end) {
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

    int rc = 0;
    uint64_t timeout = OIDC_ACCEPT_TIMEOUT;
    struct pollfd pfd = {
        .fd = elr->sock,
        .events = POLLIN,
    };
    while(timeout > 0) {
        rc = poll(&pfd, 1, 1000);
        if (elr->err == ECANCELED) {
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
    if (clt < 0) {
        elr->err = sock_error;
        ZITI_LOG(WARN, "failed to accept callback connection: %d/%s", elr->err, strerror(elr->err));
        return;
    }

    pfd.fd = clt;
    pfd.events = POLLIN;
    rc = poll(&pfd, 1, OIDC_REQ_TIMEOUT * 1000);
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
        if (write(clt, resp, sizeof(resp) - 1) <= 0 ||
            write(clt, buf, c) <= 0) {
            ZITI_LOG(DEBUG, "failed to write error response: %s", strerror(sock_error));
        }
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
    elr->clt_sock = clt;
}

static void ext_done(uv_work_t *wr, int status) {
    struct ext_link_req *elr = (struct ext_link_req *) wr;
    if (elr->sock != -1) {
        close_socket(elr->sock);
    }

    if (elr->err) {
        ZITI_LOG(ERROR, "accept failed: %s", strerror(elr->err));
    }

    if (status != UV_ECANCELED && elr->err != ECANCELED) {
        struct auth_req *req = elr->req;
        req->elr = NULL;
        if (elr->code) {
            req->clt_sock = elr->clt_sock;
            elr->clt_sock = INVALID_SOCK;
            request_token(req, elr->code);
        } else {
            failed_auth_req(req, elr->err ? strerror(elr->err) : "code not received");
        }
    }

    if (elr->clt_sock != INVALID_SOCK) {
        close_socket(elr->clt_sock);
    }
    free(elr->code);
    free(elr);
}

static void ext_start_auth(auth_req *req, const char *ep, int qc, tlsuv_http_pair q[]) {
    uv_loop_t *loop = req->clt->timer->loop;
    struct sockaddr_in6 addr = {
            .sin6_family = AF_INET6,
            .sin6_addr = IN6ADDR_LOOPBACK_INIT,
            .sin6_port = htons(auth_cb_port),
    };
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    int off = 0;
    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
#if defined(SO_REUSEPORT)
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
#if defined(IPV6_V6ONLY)
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &off, sizeof(off));
#endif
    if (bind(sock, (const struct sockaddr *) &addr, sizeof(addr)) || listen(sock, 1)) {
        failed_auth_req(req, strerror(errno));
        close_socket(sock);
        return;
    }
    set_blocking(sock);

    struct ext_link_req *elr = calloc(1, sizeof(*elr));
    elr->sock = sock;
    elr->clt_sock = INVALID_SOCK;
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

int ext_oidc_client_start(ext_oidc_client_t *clt, ext_oidc_token_cb cb) {
    clt->token_cb = cb;
    if (clt->config == NULL) {
        OIDC_LOG(DEBUG, "starting config flow");
        clt->config = json_object_new_object();
        ext_oidc_client_configure(clt, NULL);
        return 0;
    }

    if (json_object_object_length(clt->config) == 0) {
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
        ZITI_LOG(ERROR, "OIDC configuration is missing `%s'", AUTH_EP);
        return ZITI_INVALID_CONFIG;
    }
    const char *auth_url = json_object_get_string(auth_ep);

    OIDC_LOG(DEBUG, "requesting authentication code from auth_url[%s]", auth_url);
    auth_req *req = new_auth_req(clt);
    clt->request = req;

    cstr scope = cstr_from(default_scope);
    const char *s;
    MODEL_LIST_FOREACH(s, clt->signer_cfg.scopes) {
        cstr_append_fmt(&scope, " %s", s);
    }

    tlsuv_http_pair base_query[] = {
            {"client_id",             clt->signer_cfg.client_id},
            {"scope",                 cstr_str(&scope)},
            {"response_type",         "code"},
            {"redirect_uri",          default_cb_url},
            {"code_challenge",        req->code_challenge},
            {"code_challenge_method", "S256"},
            {"state",                 req->state},
            {"audience",              clt->signer_cfg.audience ?
                                      clt->signer_cfg.audience : "openziti"},
    };
    int base_count = sizeof(base_query) / sizeof(base_query[0]);
    int extra_count = clt->auth_params_count;
    int total = base_count + extra_count;

    tlsuv_http_pair *query = calloc(total, sizeof(tlsuv_http_pair));
    memcpy(query, base_query, base_count * sizeof(tlsuv_http_pair));
    int qi = base_count;
    for (int i = 0; i < extra_count; i++) {
        if (clt->auth_params[i].name && clt->auth_params[i].value) {
            query[qi++] = clt->auth_params[i];
        }
    }

    ext_start_auth(req, auth_url, qi, query);
    free(query);
    cstr_drop(&scope);
    return 0;
}

static void http_close_cb(tlsuv_http_t *h) {
    ext_oidc_client_t *clt = container_of(h, struct ext_oidc_client_s, http);

    ext_oidc_close_cb cb = clt->close_cb;
    json_object_put(clt->config);
    json_object_put(clt->tokens);
    if (cb) {
        cb(clt);
    }
}

int ext_oidc_client_refresh(ext_oidc_client_t *clt) {
    if (clt->timer == NULL || uv_is_closing((const uv_handle_t *) clt->timer)) {
        return UV_EINVAL;
    }

    uv_ref((uv_handle_t *) clt->timer);
    return uv_timer_start(clt->timer, ext_refresh_time_cb, 0, 0);
}

void ext_oidc_client_finalize(ext_oidc_client_t *clt, bool ok, const char *error_msg) {
    if (clt == NULL || clt->pending_sock == INVALID_SOCK) return;

    stop_pending_watchdog(clt);

    if (ok) {
        send_callback_response(clt->pending_sock, HTTP_SUCCESS_BODY);
    } else {
        const char *token = NULL;
        if (clt->tokens) {
            const char *token_type =
                clt->signer_cfg.target_token == ziti_target_token_id_token
                    ? "id_token" : "access_token";
            json_object *jt = json_object_object_get(clt->tokens, token_type);
            if (jt) token = json_object_get_string(jt);
        }
        char *body = build_failure_body("Controller authentication", error_msg, token);
        send_callback_response(clt->pending_sock, body);
        free(body);
    }
    clt->pending_sock = INVALID_SOCK;
}

int ext_oidc_client_close(ext_oidc_client_t *clt, ext_oidc_close_cb cb) {
    if (clt->close_cb) {
        return UV_EALREADY;
    }

    OIDC_LOG(DEBUG, "closing");
    clt->token_cb = NULL;
    clt->close_cb = cb;
    tlsuv_http_close(&clt->http, http_close_cb);
    uv_close((uv_handle_t *) clt->timer, (uv_close_cb) free);
    clt->timer = NULL;
    free_ziti_jwt_signer(&clt->signer_cfg);

    ext_oidc_client_finalize(clt, false, "client closed before completion");
    if (clt->pending_timer) {
        uv_close((uv_handle_t *) clt->pending_timer, (uv_close_cb) free);
        clt->pending_timer = NULL;
    }

    if (clt->auth_params) {
        for (int i = 0; i < clt->auth_params_count; i++) {
            free((void *)clt->auth_params[i].name);
            free((void *)clt->auth_params[i].value);
        }
        free(clt->auth_params);
        clt->auth_params = NULL;
        clt->auth_params_count = 0;
    }

    if (clt->request) {
        failed_auth_req(clt->request, strerror(ECANCELED));
    }

    zt_jwt_drop(&clt->current);
    zt_jwt_drop(&clt->refresh_token);

    return 0;
}

static void ext_oidc_client_set_tokens(ext_oidc_client_t *clt, json_object *tok_json) {
    json_object_put(clt->tokens);

    clt->tokens = json_object_get(tok_json);
    if (clt->token_cb) {
        const char *token_type;
        switch (clt->signer_cfg.target_token) {
            case ziti_target_token_id_token:
                token_type = "id_token";
                break;

            case ziti_target_token_access_token:
            case ziti_target_token_Unknown:
            default:
                token_type = "access_token";
                break;
        }

        struct json_object *jt = json_object_object_get(clt->tokens, token_type);
        if (jt) {
            const char *token = json_object_get_string(jt);
            OIDC_LOG(DEBUG, "using %s=%s", token_type, jwt_payload(token));
            clt->token_cb(clt, EXT_OIDC_TOKEN_OK, token);
        } else {
            OIDC_LOG(ERROR, "%s was not provided by IdP", token_type);
            clt->token_cb(clt, EXT_OIDC_TOKEN_FAILED, NULL);
        }
    }
    // parse access_token (or id_token, depending on target_token) as JWT for expiration
    zt_jwt_drop(&clt->current);
    struct json_object *jt_for_exp = json_object_object_get(clt->tokens,
        clt->signer_cfg.target_token == ziti_target_token_id_token ? "id_token" : "access_token");
    if (jt_for_exp) {
        const char *at = json_object_get_string(jt_for_exp);
        if (zt_jwt_parse(at, &clt->current) != 0) {
            // fallback for non-JWT tokens: use expires_in
            struct json_object *ttl = json_object_object_get(clt->tokens, "expires_in");
            if (ttl) {
                uv_timeval64_t now;
                uv_gettimeofday(&now);
                clt->current.expiration = now.tv_sec + json_object_get_int(ttl);
            }
        }
    }

    // parse refresh_token as JWT; fall back to refresh_expires_in if opaque
    zt_jwt_drop(&clt->refresh_token);
    clt->refresh_token_exp = 0;
    struct json_object *refresher = json_object_object_get(clt->tokens, "refresh_token");
    if (refresher) {
        const char *rt = json_object_get_string(refresher);
        if (zt_jwt_parse(rt, &clt->refresh_token) == 0) {
            clt->refresh_token_exp = clt->refresh_token.expiration;
        } else {
            // opaque refresh_token — check refresh_expires_in
            struct json_object *rexp = json_object_object_get(clt->tokens, "refresh_expires_in");
            if (rexp) {
                uv_timeval64_t now;
                uv_gettimeofday(&now);
                clt->refresh_token_exp = now.tv_sec + json_object_get_int(rexp);
            }
            // else: leave at 0 = unknown lifetime
        }
    }

    if (clt->timer && refresher) {
        uint64_t delay = ext_oidc_refresh_delay(clt);
        OIDC_LOG(DEBUG, "scheduling token refresh in %" PRIu64 ".%03" PRIu64 " s",
                 delay / 1000, delay % 1000);
        uv_timer_start(clt->timer, ext_refresh_time_cb, delay, 0);
    }
}

static void refresh_cb(tlsuv_http_resp_t *http_resp, const char *err, json_object *resp, void *ctx) {
    ext_oidc_client_t *clt = ctx;
    assert(clt->refresh_req == http_resp->req);
    clt->refresh_req = NULL;

    if (http_resp->code == 200 && resp != NULL) {
        OIDC_LOG(DEBUG,  "token refresh success");
        clt->refresh_failures = 0;
        ext_oidc_client_set_tokens(clt, resp);
        return;
    }

    if (http_resp->code == UV_ECANCELED) {
        OIDC_LOG(DEBUG, "OIDC token refresh was canceled");
        return;
    }

    clt->refresh_failures++;
    uint64_t delay = ext_oidc_refresh_delay(clt);
    if (ziti_http_error_is_temporary(http_resp, resp) && delay > 0) {
        OIDC_LOG(WARN, "OIDC token refresh failed (%d/%s), attempt %d",
                 http_resp->code, err, clt->refresh_failures);
        OIDC_LOG(DEBUG, "scheduling token refresh retry in %" PRIu64 ".%03" PRIu64 " s",
                 delay / 1000, delay % 1000);
        uv_timer_start(clt->timer, ext_refresh_time_cb, delay, 0);
        return;
    }

    OIDC_LOG(WARN, "OIDC token refresh failed: %d %s [%s] %s",
             http_resp->code, http_resp->status, err, json_object_get_string(resp));
    clt->refresh_failures = 0;
    zt_jwt_drop(&clt->current);
    zt_jwt_drop(&clt->refresh_token);
    clt->refresh_token_exp = 0;
    clt->token_cb(clt, EXT_OIDC_RESTART, NULL);
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

static void ext_refresh_time_cb(uv_timer_t *t) {
    uv_unref((uv_handle_t *) t);
    ext_oidc_client_t *clt = t->data;
    OIDC_LOG(DEBUG, "refreshing OIDC token");
    assert(clt->config);

    if (clt->refresh_req) {
        OIDC_LOG(DEBUG, "refresh is already in progress");
        return;
    }

    json_object *tok = json_object_object_get(clt->tokens, "refresh_token");
    if (tok == NULL) {
        OIDC_LOG(DEBUG, "must restart authentication flow: no refresh_token");
        clt->token_cb(clt, EXT_OIDC_RESTART, NULL);
        return;
    }

    struct json_object *token_ep = json_object_object_get(clt->config, TOKEN_EP);
    const char *token_url = json_object_get_string(token_ep);

    tlsuv_http_set_url(&clt->http, token_url);
    tlsuv_http_req_t *req = ziti_json_request(&clt->http, "POST", NULL, refresh_cb, clt);
    tlsuv_http_req_header(req, HTTP_AUTHORIZATION,
                          get_basic_auth_header(clt->signer_cfg.client_id));
    const char *refresher = json_object_get_string(tok);
    tlsuv_http_req_form(req, 3, (tlsuv_http_pair[]) {
        {"client_id",     clt->signer_cfg.client_id},
        {"grant_type",    "refresh_token"},
        {"refresh_token", refresher},
    });
    clt->refresh_req = req;
}

// calculate delay until next token refresh attempt:
// - if access_token is still valid, schedule before its expiration
// - if access_token is expired, use exponential backoff, giving up when refresh_token expires
//   (for opaque refresh tokens with unknown lifetime, keep retrying with backoff)
static uint64_t ext_oidc_refresh_delay(ext_oidc_client_t *clt) {
    uv_timeval64_t now;
    uv_gettimeofday(&now);

    uint64_t rando = randombytes_random();
    // access_token still valid: schedule between 1/2 and 5/6 of remaining lifetime
    if (clt->current.expiration > now.tv_sec + 15) {
        uint64_t delay = (clt->current.expiration - now.tv_sec) * 1000;
        return delay / 2 + rando % (delay / 3);
    }

    // access_token expired — exponential backoff
    int failures = clt->refresh_failures > 10 ? 10 : clt->refresh_failures;
    uint64_t backoff = 1ULL << failures;  // seconds, max 1024 (~17 min)

    if (clt->refresh_token_exp > 0) {
        // known refresh_token lifetime: give up if backoff would exceed it
        if (now.tv_sec + (int64_t)backoff >= clt->refresh_token_exp) {
            return 0;
        }
    }
    // unknown lifetime (opaque token) — keep retrying with backoff
    backoff *= 1000; // convert to ms
    return backoff / 2 + rando % (backoff / 2);
}
