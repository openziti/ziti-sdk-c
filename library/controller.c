/*
Copyright 2019 Netfoundry, Inc.

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

#include <stdlib.h>
#include <http_parser.h>
#include "controller.h"
#include "utils.h"
#include "zt_internal.h"
#include "strutils.h"
#include "model.h"

#define MJSON_API_ONLY
#include <mjson.h>

#if _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#else
#include <unistd.h>
#define SOCKET int //differences tween windows and posix
#endif

const static char REQ_HTTP[] = "%s %s HTTP/1.1\r\n"
                               "Host: %s\r\n"
                               "Accept: application/json\r\n"
                               "Content-Type: %s\r\n"
                               "Content-Length: %zd\r\n"
                               "%s"
                               "\r\n"
;

struct controller_resp {
    uint status;
    char* msg;
    int complete;
    size_t body_len;
    uint8_t *body;

    const uint8_t *data;
    int data_len;
    enum mjson_tok data_type;
    ziti_error *error;
};

void free_resp(struct controller_resp *r) {
    free(r->msg);
    free(r->body);
    if (r->error != NULL) { free_ziti_error(r->error); }
}

int status_cb(http_parser* p, const char* d, size_t len) {
    struct controller_resp *resp = p->data;
    resp->status = p->status_code;
    resp->msg = zitistrndup(d, len);
    return 0;
}

int body_cb(http_parser* p, const char* b, size_t body_len) {
    struct controller_resp *resp = p->data;
    if (resp->body == NULL) {
        resp->body = malloc(body_len);
        resp->body_len = body_len;
        memcpy(resp->body, b, resp->body_len);
    } else {
        size_t len = resp->body_len;
        resp->body_len += body_len;
        resp->body = realloc(resp->body, resp->body_len);
        memcpy(resp->body + len, b, body_len);
    }
    resp->complete = http_body_is_final(p);
    return 0;
}

int headers_cb(http_parser* p) {
    return 0;
}

int msg_complete(http_parser* p) {
    struct controller_resp *resp = p->data;
    resp->complete = 1;
    return 0;
}

static struct http_parser_settings HTTP_SETTINGS = {
        NULL, // on_message_begine
        NULL, // on_url
        status_cb, // on_status
        NULL, // on_header_field
        NULL, // on_header_value
        headers_cb, // on_headers_complete
        body_cb, // on_body
        msg_complete, // on_message_complete
      //  chunk_header_cb,
      //  chunk_complete_cb,

};

static int ziti_controller_req(struct nf_ctx *ctx, uv_os_sock_t ctrl, tls_engine *ssl,
                               const char *method, const char *path,
                               const char *conttype, const unsigned char *content, size_t content_len,
                               struct controller_resp *resp);

static int code_to_error(const char *code);


int ziti_ctrl_logout(struct nf_ctx *ctx, uv_os_sock_t ctrl, tls_engine *ssl) {
    if (ssl == NULL) {
        return ziti_ctrl_process(ctx, ziti_ctrl_logout, NULL);
    }

    struct controller_resp resp;
    memset(&resp, 0, sizeof(struct controller_resp));
    ziti_controller_req(ctx, ctrl, ssl, "DELETE", "/current-session", NULL, NULL, 0, &resp);
    if (ctx->session != NULL) {
        free_ziti_session(ctx->session);
        ctx->session = NULL;
    }
    free_resp(&resp);
    return ZITI_OK;
}

int ziti_ctrl_version(struct nf_ctx *ctx, uv_os_sock_t ctrl, tls_engine *ssl) {

    if (ssl == NULL) {
        return ziti_ctrl_process(ctx, ziti_ctrl_login, NULL);
    }

    struct controller_resp resp;
    memset(&resp, 0, sizeof(struct controller_resp));
    ziti_controller_req(ctx, ctrl, ssl, "GET", "/version", "application/json", "", 0, &resp);

    if (resp.status == 200) {
        if (resp.data_type == MJSON_TOK_OBJECT) {
            ctrl_version *v = parse_ctrl_version(resp.data, resp.data_len);
            ZITI_LOG(INFO, "connected to controller %s:%d version %s(%s %s)",
                     ctx->controller, ctx->controller_port, v->version, v->revision, v->build_date);
            free_ctrl_version(v);
        }
        else {
            return ZITI_WTF;
        }
    }
    return ZITI_OK;
}

int ziti_ctrl_login(struct nf_ctx *ctx, uv_os_sock_t ctrl, tls_engine *ssl) {
    if (ssl == NULL) {
        return ziti_ctrl_process(ctx, ziti_ctrl_login, NULL);
    }

    uv_utsname_t osInfo;
    uv_os_uname(&osInfo);

    uint8_t *req = NULL;
    int req_len = mjson_printf(&mjson_print_dynamic_buf, &req,
            "{"
            "%Q:{%Q:%Q, %Q:%Q, %Q:%Q, %Q:%Q}, "
            "%Q:{%Q:%Q, %Q:%Q, %Q:%Q, %Q:%Q}"
            "}",
            "sdkInfo",
            "type", "ziti-sdk-c",
            "version", ziti_get_version(0),
            "revision", ziti_git_commit(),
            "branch", ziti_git_branch(),
            "envInfo",
            "os", osInfo.sysname,
            "osRelease", osInfo.release,
            "osVersion", osInfo.version,
            "arch", osInfo.machine);

    struct controller_resp resp;
    memset(&resp, 0, sizeof(struct controller_resp));
    int rc = ziti_controller_req(ctx, ctrl, ssl, "POST", "/authenticate?method=cert", "application/json", req, req_len,
                                 &resp);

    if (rc == ZITI_OK) {
        if (resp.data_type == MJSON_TOK_OBJECT) {
            ctx->session = parse_ziti_session(resp.data, resp.data_len);
        }
        else {
            rc = ZITI_WTF;
        }
    }

    free(req);
    free_resp(&resp);
    return rc;
}

int ziti_ctrl_get_services(struct nf_ctx *ctx, uv_os_sock_t ctrl, tls_engine *ssl) {

    if (ssl == NULL) {
        return ziti_ctrl_process(ctx, ziti_ctrl_get_services, NULL);
    }

    struct controller_resp resp;
    memset(&resp, 0, sizeof(struct controller_resp));
    int rc = ziti_controller_req(ctx, ctrl, ssl, "GET", "/services?limit=100", "", NULL, 0, &resp);

    if (rc == ZITI_OK) {
        if (resp.data_type == MJSON_TOK_ARRAY) {
            // TODO parse directly into list
            ziti_service **arr = parse_ziti_service_array(resp.data, resp.data_len);
            for (ziti_service **it = arr; *it != NULL; it++) {
                SLIST_INSERT_HEAD(&ctx->services, *it, _next);
            }
            free(arr);
        }
        else {
            ZITI_LOG(ERROR, "unexpected response format, expected array of services");
            rc = ZITI_WTF;
        }
    }
    free_resp(&resp);
    return rc;
}

int ziti_ctrl_get_network_sessions(struct nf_ctx *ctx, uv_os_sock_t ctrl, tls_engine *ssl) {

    if (ssl == NULL) {
        return ziti_ctrl_process(ctx, ziti_ctrl_get_network_sessions, NULL);
    }

    PREPF(ziti, ziti_errorstr);
    const char* method = "POST";
    const char* path = "/network-sessions";
    const char* conttype = "application/json";

    ziti_service *s;
    SLIST_FOREACH (s, &ctx->services, _next) {
        struct controller_resp resp;
        memset(&resp, 0, sizeof(resp));

        uint8_t content[128];
        size_t len = (size_t) sprintf((char *) content, "{\"serviceId\":\"%s\",\"hosting\":%s}",
                                      s->id, s->hostable ? "true" : "false");
        int rc = ziti_controller_req(ctx, ctrl, ssl, method, path, conttype, content, len, &resp);

        if (resp.status > 299) {
            ZITI_LOG(WARN, "failed to get network session for [%s]: (%d %s) %s", s->name, resp.status,
                     resp.msg, resp.error->message);
        }

        if (rc == ZITI_OK && resp.data_type == MJSON_TOK_OBJECT) {
            ziti_net_session *ns = parse_ziti_net_session(resp.data, resp.data_len);
            if (ns != NULL) {
                ns->service_id = strdup(s->id);

                SLIST_INSERT_HEAD(&ctx->net_sessions, ns, _next);
            }
        }
        free_resp(&resp);
    }

    CATCH(ziti) {
        return ERR(ziti);
    }
    return 0;
}

static int ziti_controller_req(struct nf_ctx *ctx, uv_os_sock_t ctrl, tls_engine *ssl,
                               const char *method, const char *path,
                               const char *conttype, const unsigned char *content, size_t content_len,
                               struct controller_resp *resp) {
    char sess_hdr[128] = "";
    if (ctx->session != NULL) {
        sprintf(sess_hdr, "zt-session: %s\r\n", ctx->session->token);
    }

    size_t req_size = 1024;
    uint8_t *req = malloc(req_size);
    size_t act_size = 0;
    do {
        act_size = (size_t) snprintf((char *) req, req_size, REQ_HTTP, method, path, ctx->controller,
                                     conttype, content_len, sess_hdr);
        if (act_size > req_size) {
            req_size = act_size;
            req = realloc(req, req_size);
        } else {
            break;
        }
    } while(1);

    ZITI_LOG(DEBUG, "%s %s [%zd bytes]", method, path, content_len);
    ZITI_LOG(TRACE, "===> %*.*s", (uint) content_len, (uint) content_len, content);


    char ssl_out[8 * 1024];
    size_t ssl_bytes;
    int rc = ssl->api->write(ssl->engine, req, act_size, ssl_out, &ssl_bytes, sizeof(ssl_out));
    size_t wrote = send(ctrl, ssl_out, ssl_bytes, 0);
    ZITI_LOG(TRACE, "wrote %zd ssl bytes rc=%d", wrote, rc);
    while (rc == TLS_MORE_AVAILABLE) {
        rc = ssl->api->write(ssl->engine, NULL, 0, ssl_out, &ssl_bytes, sizeof(ssl_out));
        wrote = send(ctrl, ssl_out, ssl_bytes, 0);
        ZITI_LOG(TRACE, "wrote %zd ssl bytes rc=%d", wrote, rc);
    }

    rc = ssl->api->write(ssl->engine, content, content_len, ssl_out, &ssl_bytes, sizeof(ssl_out));
    wrote = send(ctrl, ssl_out, ssl_bytes, 0);
    ZITI_LOG(TRACE, "wrote %zd ssl bytes rc=%d", wrote, rc);
    while (rc == TLS_MORE_AVAILABLE) {
        rc = ssl->api->write(ssl->engine, NULL, 0, ssl_out, &ssl_bytes, sizeof(ssl_out));
        wrote = send(ctrl, ssl_out, ssl_bytes, 0);
        ZITI_LOG(TRACE, "wrote %zd ssl bytes rc=%d", wrote, rc);
    }
    free(req);

    struct http_parser parser;
    http_parser_init(&parser, HTTP_RESPONSE);
    parser.data = resp;

    size_t read = 0;
    char ssl_in[8 * 1024];
    size_t ssl_in_bytes;
    do {
        char respbuff[8 * 1024];
        ssl_in_bytes = recv(ctrl, ssl_in, sizeof(ssl_in), 0);
        ZITI_LOG(TRACE, "read %zd ssl bytes", ssl_in_bytes);
        if (ssl_in_bytes <= 0)
            break;
        rc = ssl->api->read(ssl->engine, ssl_in, ssl_in_bytes, respbuff, &read, sizeof(respbuff));
        ZITI_LOG(TRACE, "read %zd plain bytes rc=%d ", read, rc);
        if (rc == TLS_READ_AGAIN) {
            continue;
        }

        ssize_t parsed = http_parser_execute(&parser, &HTTP_SETTINGS, (const char *) respbuff, read);
        ZITI_LOG(TRACE, "body=%zd parsed=%ld", resp->body_len, parsed);
        while (rc == TLS_MORE_AVAILABLE) {
            rc = ssl->api->read(ssl->engine, NULL, 0, respbuff, &read, sizeof(respbuff));
            ZITI_LOG(TRACE, "read %zd plain bytes rc=%d ", read, rc);

            if (rc == TLS_READ_AGAIN) {
                break;
            }
            parsed = http_parser_execute(&parser, &HTTP_SETTINGS, (const char *) respbuff, read);
            ZITI_LOG(TRACE, "body=%zd parsed=%zd", resp->body_len, parsed);
        }
    } while (!resp->complete);

    ZITI_LOG(DEBUG, "%s %s => %d [%zd bytes]", method, path, parser.status_code, resp->body_len);
    ZITI_LOG(TRACE, ">>> %*.*s\n", (int)resp->body_len, (int)resp->body_len, resp->body);

    if (parser.status_code > 299) {
        const char *p;
        int len;
        if (mjson_find(resp->body, resp->body_len, "$.error", &p, &len) == MJSON_TOK_OBJECT) {
            resp->error = parse_ziti_error(p, len);
            ZITI_LOG(ERROR, "controller returned error: %d %s(%s)", parser.status_code, resp->error->code,
                     resp->error->message);
            return code_to_error(resp->error->code);
        }
        ZITI_LOG(WARN, "unparseable error with code %d", parser.status_code);
        return ZITI_WTF;
    }

    resp->data_type = mjson_find(resp->body, resp->body_len, "$.data", (const char **) &resp->data, &resp->data_len);

    return 0;
}

int sockClose(SOCKET sock)
{
    //a helper to hide the differences between closing a socket in windows vs posix
    int status = 0;
#ifdef _WIN32
    status = shutdown(sock, SD_BOTH);
    if (status == 0) { status = closesocket(sock); }
#else
    status = shutdown(sock, SHUT_RDWR);
    if (status == 0) { status = close(sock); }
#endif
    return status;
}

int ziti_ctrl_process(struct nf_ctx* ctx, ...) {
    int rc = ZITI_OK;

    PREPF(ziti, ziti_errorstr);

    tls_engine *ssl = ctx->tlsCtx->api->new_engine(ctx->tlsCtx->ctx, ctx->controller);
    char port[6];
    sprintf(port, "%d", ctx->controller_port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *address, *ap;
    int r = getaddrinfo(ctx->controller, port, &hints, &address);
    if (r != 0 || address == NULL) {
        /*
        Copyright 2019 Netfoundry, Inc.

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

        ZITI_LOG(ERROR, "failed to resolve controller(%s): %s", ctx->controller, strerror(errno));
        return ZITI_CONTROLLER_UNAVAILABLE;
    }

    uv_os_sock_t sock = socket(AF_INET, SOCK_STREAM, 0);

    // connect
    for (ap = address; ap != NULL; ap = ap->ai_next) {
        char a[32], p[6];
        getnameinfo(ap->ai_addr, ap->ai_addrlen, a, sizeof(a), p, 6, NI_NUMERICHOST | NI_NUMERICSERV);
        ZITI_LOG(DEBUG, "trying to connect to %s:%s", a, p);
        r = connect(sock, ap->ai_addr, ap->ai_addrlen);
        if (r == 0) {
            break;
        }

        ZITI_LOG(WARN, "failed to connect to %s:%s %s", a, p, strerror(errno));
    }

    // do handshake
    char ssl_in[32 * 1024];
    char ssl_out[32 * 1024];
    size_t in_bytes = 0;
    size_t out_bytes = 0;
    do {
        tls_handshake_state state = ssl->api->handshake(ssl->engine, ssl_in, in_bytes, ssl_out, &out_bytes,
                                                        sizeof(ssl_out));
        if (state == TLS_HS_COMPLETE) {
            ZITI_LOG(DEBUG, "handshake completed");
            break;
        }
        else if (state == TLS_HS_ERROR) {
            ZITI_LOG(ERROR, "handshake failed");
            return ZITI_CONTROLLER_UNAVAILABLE;
        }

        if (out_bytes > 0) {
            size_t wrote = send(sock, ssl_out, out_bytes, 0);
        }

        in_bytes = recv(sock, ssl_in, sizeof(ssl_in), 0);
    } while (true);

    // execute requests in order
    va_list argp;
    va_start(argp, ctx);

    ctrl_req req;
    while ((req = va_arg(argp, ctrl_req)) != NULL) {
        TRY(ziti, req(ctx, sock, ssl));
    }
    va_end(argp);

    // close SSL and socket
    ssl->api->close(ssl->engine, ssl_out, &out_bytes, sizeof(ssl_out));
    send(sock, ssl_out, out_bytes, 0);

    sockClose(sock);

    CATCH(ziti) {
        rc = ERR(ziti);
    }

    ctx->tlsCtx->api->free_engine(ssl);
    return rc;
}


static int code_to_error(const char *code) {

#define CODE_MAP(XX) \
XX(NO_ROUTABLE_INGRESS_NODES, ZITI_GATEWAY_UNAVAILABLE) \
XX(NO_EDGE_ROUTERS_AVAILABLE, ZITI_GATEWAY_UNAVAILABLE) \
XX(INVALID_AUTHENTICATION, ZITI_NOT_AUTHORIZED) \
XX(REQUIRES_CERT_AUTH, ZITI_NOT_AUTHORIZED)\
XX(UNAUTHORIZED, ZITI_NOT_AUTHORIZED)\
XX(INVALID_AUTH, ZITI_NOT_AUTHORIZED)

#define CODE_MATCH(c, err) if (strcmp(code,#c) == 0) return err;

    CODE_MAP(CODE_MATCH)

    ZITI_LOG(WARN, "unmapped error code: %s", code);
    return ZITI_WTF;
}