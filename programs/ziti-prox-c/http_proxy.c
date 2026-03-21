// Copyright (c) 2026.  NetFoundry Inc
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

#include "proxy.h"

#include <ziti/ziti_log.h>
#include "utils.h"

#include <llhttp.h>
#include <stc/cstr.h>
#include <uv.h>

#define PROXY_AGENT_HEADER "Proxy-agent: ziti-prox-c/" TO_STRING(ZITI_VERSION) "\r\n\r\n"

#define CONNECTION_ESTABLISHED \
    "HTTP/1.1 200 Connection Established\r\n" \
PROXY_AGENT_HEADER

#define BAD_GATEWAY_RESPONSE \
    "HTTP/1.1 502 Bad Gateway\r\n" \
PROXY_AGENT_HEADER

typedef struct header {
    cstr name;
    cstr value;
} header;

#define header_drop(h) {cstr_drop(&(h)->value); cstr_drop(&(h)->name);}
#define i_keyclass header
#define i_no_clone
#include <stc/list.h>

typedef struct http_proxy_client {
    uv_tcp_t tcp;
    ziti_context ztx;
    ziti_connection ziti_conn;
    llhttp_t parser;
    cstr url;
    list_header headers;
    cstr *body; // leftover request body after parsing request
} http_proxy_client_t;

static void http_proxy_client_drop(http_proxy_client_t *c) {
    list_header_drop(&c->headers);
    cstr_drop(&c->url);
    if (c->body) cstr_drop(c->body);
}

static void proxy_on_close(uv_handle_t *h) {
    http_proxy_client_t *c = (http_proxy_client_t *) h;
    http_proxy_client_drop(c);
    free(c);
}

static void proxy_alloc(uv_handle_t *h, size_t size, uv_buf_t *buf) {
    // this is OK since libuv always calls alloc/read callbacks sequentially, so we won't have concurrent access to the buffer
    static char buffer[8192];
    *buf = uv_buf_init(buffer, sizeof(buffer));
}

static void proxy_read_req(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    http_proxy_client_t *c = (http_proxy_client_t *) s;
    if (nread < 0) {
        if (nread != UV_EOF) {
            ZITI_LOG(WARN, "HTTP proxy client read error: %d/%s", (int)nread, uv_strerror((int)nread));
        }
        uv_close((uv_handle_t *) c, proxy_on_close);
        return;
    }

    llhttp_errno_t err = llhttp_execute(&c->parser, buf->base, nread);
    switch (err) {
    case HPE_OK: // continue reading until header are complete
        break;
    case HPE_PAUSED_UPGRADE:
    case HPE_PAUSED:
        uv_read_stop((uv_stream_t *) c);
        if (c->parser.error_pos != NULL) {
            size_t parsed_len = c->parser.error_pos - buf->base;
            if (parsed_len < (size_t)nread) {
                c->body = calloc(1, sizeof(cstr));
                cstr_assign_n(c->body, buf->base + parsed_len, (int)(nread - parsed_len));
            }
        }
        break;
    default:
        ZITI_LOG(WARN, "HTTP proxy client parse error: %s", llhttp_errno_name(err));
        uv_close((uv_handle_t *) c, proxy_on_close);
    }
}

static void proxy_on_ziti_write(ziti_connection conn, ssize_t status, void *ctx) {
    cstr *request = ctx;
    if (status != ZITI_OK) {
        ZITI_LOG(WARN, "HTTP proxy client failed to write to ziti for url %s: %zd/%s", cstr_str(request), status, ziti_errorstr(status));
    }
    cstr_drop(request);
    free(request);
}

static void proxy_on_ziti_connect(ziti_connection conn, int status) {
    http_proxy_client_t *c = (http_proxy_client_t *) ziti_conn_data(conn);
    if (status != ZITI_OK) {
        ZITI_LOG(WARN, "HTTP proxy client failed to connect to ziti for url %s: %d/%s", cstr_str(&c->url), status, ziti_errorstr(status));
        ziti_close(c->ziti_conn, NULL);
        uv_close((uv_handle_t *) &c->tcp, proxy_on_close);
        return;
    }

    uv_read_stop((uv_stream_t *)&c->tcp);
    if (c->parser.method == HTTP_CONNECT) {
        uv_buf_t proxy_response = uv_buf_init(CONNECTION_ESTABLISHED, sizeof(CONNECTION_ESTABLISHED) - 1);
        uv_try_write((uv_stream_t *)&c->tcp, &proxy_response, 1);
        ZITI_LOG(DEBUG, "HTTP proxy client connected to ziti for url %s", cstr_str(&c->url));
        ziti_conn_bridge(conn, (uv_handle_t *)&c->tcp, proxy_on_close);
    } else {
        struct tlsuv_url_s url;
        tlsuv_parse_url(&url, cstr_str(&c->url));
        cstr *request = calloc(1, sizeof(cstr));
        cstr_append_fmt(request, "%s %s HTTP/1.1\r\n", llhttp_method_name(c->parser.method), url.path);
        ZITI_LOG(DEBUG, "HTTP proxy client request line: %s", cstr_str(request));
        c_foreach(it, list_header, c->headers) {
            cstr_append_fmt(request, "%s: %s\r\n", cstr_str(&it.ref->name), cstr_str(&it.ref->value));
        }
        cstr_append(request, "\r\n");

        ziti_write(c->ziti_conn, (uint8_t *)cstr_str(request), cstr_size(request), proxy_on_ziti_write, request);
        if (c->body && !cstr_is_empty(c->body)) {
            ziti_write(c->ziti_conn, (uint8_t *)cstr_str(c->body), cstr_size(c->body), proxy_on_ziti_write, c->body);
            c->body = NULL;
        }
        ziti_conn_bridge(c->ziti_conn, (uv_handle_t *)&c->tcp, proxy_on_close);
    }
}

static int proxy_on_headers_complete(llhttp_t *parser) {
    http_proxy_client_t *c = (http_proxy_client_t *) parser->data;
    ZITI_LOG(DEBUG, "HTTP proxy headers complete: method=%s", llhttp_method_name(parser->method));
    struct tlsuv_url_s url;
    tlsuv_parse_url(&url, cstr_str(&c->url));
    if (url.port == 0) {
        url.port = 80;
    }
    char peer_host[32] = {0};
    struct sockaddr_in6 peer;
    int peer_len = sizeof(peer);
    uv_tcp_getpeername(&c->tcp, (struct sockaddr *)&peer, &peer_len);
    int peer_port = (peer.sin6_family == AF_INET6) ? ntohs(peer.sin6_port) : ntohs(((struct sockaddr_in *)&peer)->sin_port);
    void *addr = (peer.sin6_family == AF_INET6) ? (void*)&peer.sin6_addr : &((struct sockaddr_in*)&peer)->sin_addr;
    uv_inet_ntop(peer.sin6_family, addr, peer_host, sizeof(peer_host));

    cstr host = cstr_with_n(url.hostname, (int)url.hostname_len);
    ziti_dial_opts dial = {0};
    const ziti_service *s = ziti_dial_opts_for_addr(&dial, c->ztx, ziti_protocol_tcp, cstr_str(&host), url.port, peer_host, peer_port);
    if (!s) {
        ZITI_LOG(WARN, "no service found for HTTP CONNECT to %s:%d", cstr_str(&host), url.port);
        uv_buf_t resp = uv_buf_init(BAD_GATEWAY_RESPONSE, sizeof(BAD_GATEWAY_RESPONSE) - 1);
        uv_try_write((uv_stream_t*)&c->tcp, &resp, 1);
        uv_close((uv_handle_t *)&c->tcp, proxy_on_close);
    } else {
        ZITI_LOG(DEBUG, "connecting to service[%s] for HTTP %s to %s:%d", s->name,
                 llhttp_method_name(c->parser.method), cstr_str(&host), url.port);

        ziti_conn_init(c->ztx, &c->ziti_conn, c);
        int rc = ziti_dial_with_options(c->ziti_conn, s->name, &dial, proxy_on_ziti_connect, NULL);
        if (rc != ZITI_OK) {
            ziti_close(c->ziti_conn, NULL);
            ZITI_LOG(WARN, "failed to dial ziti service[%s] for HTTP %s to %s:%d: %d/%s",
                     s->name, llhttp_method_name(c->parser.method),
                     cstr_str(&host), url.port, rc, ziti_errorstr(rc));
            uv_buf_t resp = uv_buf_init(BAD_GATEWAY_RESPONSE, sizeof(BAD_GATEWAY_RESPONSE) - 1);
            uv_try_write((uv_stream_t *)&c->tcp, &resp, 1);
            uv_close((uv_handle_t *)&c->tcp, proxy_on_close);
        }
    }
    ziti_dial_opts_free(&dial);
    cstr_drop(&host);

    return HPE_PAUSED;
}

static int proxy_on_url(llhttp_t *parser, const char *at, size_t length) {
    http_proxy_client_t *c = (http_proxy_client_t *) parser->data;
    cstr_assign_n(&c->url, at, (int)length);
    return 0;
}

static int proxy_on_header_name(llhttp_t *parser, const char *at, size_t length) {
    http_proxy_client_t *c = (http_proxy_client_t *) parser->data;
    list_header_push_back(&c->headers,
                          (header) { .name = cstr_with_n(at, (int)length), });
    return 0;
}

static int proxy_on_header_val(llhttp_t *parser, const char *at, size_t length) {
    http_proxy_client_t *c = (http_proxy_client_t *) parser->data;
    list_header_value *h = list_header_back_mut(&c->headers);
    if (h) {
        cstr_assign_n(&h->value, at, (int)length);
        ZITI_LOG(DEBUG, "HTTP proxy header field: %s => %s", cstr_str(&h->name), cstr_str(&h->value));
        return 0;
    }
    return HPE_INVALID_HEADER_TOKEN;
}

void on_proxy_client(uv_stream_t *server, int status) {
    static llhttp_settings_t http_proc = {
        .on_url = proxy_on_url,
        .on_header_field = proxy_on_header_name,
        .on_header_value = proxy_on_header_val,
        .on_headers_complete = proxy_on_headers_complete,
    };

    if (status < 0) {
        ZITI_LOG(WARN, "HTTP proxy client connection error: %d/%s", status, uv_strerror(status));
        return;
    }

    int rc;
    http_proxy_client_t *c = calloc(1, sizeof(*c));
    c->ztx = server->data;
    llhttp_init(&c->parser, HTTP_REQUEST, &http_proc);
    c->parser.data = c;
    if ((rc = uv_tcp_init(server->loop, &c->tcp)) ||
        (rc = uv_accept(server, (uv_stream_t *)c))) {
        ZITI_LOG(WARN, "HTTP proxy client accept error: %d/%s", rc, uv_strerror(rc));
        free(c);
        return;
    }

    uv_read_start((uv_stream_t *)&c->tcp, proxy_alloc, proxy_read_req);
}

int run_http_proxy(uv_loop_t *loop, int port, ziti_context ztx) {
    static uv_tcp_t http_proxy_server;

    int rc;
    struct sockaddr_in http_proxy_addr = {
        .sin_port = htons(port),
        .sin_family = AF_INET
    };

    uv_tcp_init(loop, &http_proxy_server);
    http_proxy_server.data = ztx;
    uv_unref((uv_handle_t *)&http_proxy_server);

    if ((rc = uv_tcp_bind(&http_proxy_server, (const struct sockaddr *) &http_proxy_addr, 0)) ||
        (rc = uv_listen((uv_stream_t *) &http_proxy_server, 5, on_proxy_client))) {
        ZITI_LOG(WARN, "failed to start HTTP proxy listener: %d/%s", rc, uv_strerror(rc));
    } else {
        ZITI_LOG(INFO, "HTTP proxy listening on port %d", port);
    }
    return rc;
}
