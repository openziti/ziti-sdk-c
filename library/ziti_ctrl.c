/*
Copyright 2019 NetFoundry, Inc.

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
#include "utils.h"
#include "zt_internal.h"
#include "strutils.h"
#include <ziti_ctrl.h>
#include <uv_mbed/um_http.h>

#define MJSON_API_ONLY
#include <mjson.h>

#if _WIN32

#define strcasecmp _stricmp
#define strncasecmp _strnicmp

#endif

int code_to_error(const char *code) {

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

struct ctrl_resp {
    int status;
    char *body;
    size_t received;
    bool resp_chunked;
    bool resp_text_plain;

    void* (*body_parse_func)(const char*, int);
    void (*resp_cb)(void*, ziti_error*, void*);
    void *ctx;

    ziti_controller *ctrl;
    void (*ctrl_cb)(void*, ziti_error*, struct ctrl_resp*);
};

static void ctrl_default_cb (void *s, ziti_error *e, struct ctrl_resp *resp);

static void ctrl_resp_cb(um_http_req_t *req, int code, um_header_list *headers) {
    struct ctrl_resp *resp = req->data;
    resp->status = code;
    if (code < 0) {
        NEWP(err, ziti_error);
        err->code = strdup("CONTROLLER_UNAVAILABLE");
        err->message = strdup(uv_strerror(code));
        ctrl_default_cb(NULL, err, resp);
    } else {
        um_http_hdr *h;
        LIST_FOREACH(h, headers, _next) {
            if (strcasecmp(h->name, "Content-Length") == 0) {
                resp->body = calloc(1, atol(h->value) + 1);
                break;
            }
            if (strcasecmp(h->name, "Transfer-Encoding") == 0 && strcmp(h->value, "chunked") == 0) {
                resp->resp_chunked = true;
                resp->body = malloc(0);
            }
        }
    }
}

static void ctrl_default_cb (void *s, ziti_error *e, struct ctrl_resp *resp) {
    if (resp->resp_cb) {
        resp->resp_cb(s, e, resp->ctx);
    }

    free(resp);
}

static void ctrl_login_cb(ziti_session *s, ziti_error *e, struct ctrl_resp *resp) {
    if (e) {
        ZITI_LOG(ERROR, "%s(%s)", e->code, e->message);
        FREE(resp->ctrl->session);
        um_http_header(&resp->ctrl->client, "zt-session", NULL);
    }

    if (s) {
        FREE(resp->ctrl->session);
        resp->ctrl->session = strdup(s->token);
        um_http_header(&resp->ctrl->client, "zt-session", s->token);
    }
    ctrl_default_cb(s, e, resp);
}

static void ctrl_logout_cb(void *s, ziti_error *e, struct ctrl_resp *resp) {
    FREE(resp->ctrl->session);
    um_http_header(&resp->ctrl->client, "zt-session", NULL);
    ctrl_default_cb(s, e, resp);
}

static void ctrl_service_cb(ziti_service **services, ziti_error *e, struct ctrl_resp *resp) {
    ziti_service *s = services != NULL ? services[0] : NULL;
    ctrl_default_cb(s, e, resp);
    free(services);
}

static void free_body_cb(um_http_req_t *req, const char *body, ssize_t len) {
    free(body);
}

static void ctrl_body_cb(um_http_req_t *req, const char* b, ssize_t len) {
    struct ctrl_resp *resp = req->data;

    if (len > 0) {
        if (resp->resp_chunked) {
            resp->body = realloc(resp->body, resp->received + len);
        }
        memcpy(resp->body + resp->received, b, len);
        resp->received += len;
    } else if (len == UV_EOF) {
        const char* data = NULL;
        int data_len;
        void *resp_obj = NULL;
        ziti_error *err = NULL;

        if (resp->status > 299) {
            mjson_find(resp->body, resp->received, "$.error", (const char **) &data, &data_len);
            err = parse_ziti_error(data, data_len);
        } else if (resp->resp_text_plain) {
            resp_obj = calloc(1, resp->received + 1);
            memcpy(resp_obj, resp->body, resp->received);
        } else {
            mjson_find(resp->body, resp->received, "$.data", (const char **) &data, &data_len);
            resp_obj = resp->body_parse_func ? resp->body_parse_func(data, data_len) : NULL;
        }
        free(resp->body);
        resp->body = NULL;

        resp->ctrl_cb(resp_obj, err, resp);
    } else {
        ZITI_LOG(ERROR, "Unexpeced ERROR: %zd", len);
    }
}

int ziti_ctrl_init(uv_loop_t *loop, ziti_controller *ctrl, const char *url, tls_context *tls) {
    um_http_init(loop, &ctrl->client, url);
    um_http_set_ssl(&ctrl->client, tls);
    um_http_idle_keepalive(&ctrl->client, 0);
    ctrl->session = NULL;

    return ZITI_OK;
}

int ziti_ctrl_close(ziti_controller *ctrl) {
    if (ctrl->session != NULL) {
        FREE(ctrl->session);
        um_http_close(&ctrl->client);
    }
    return ZITI_OK;
}

void ziti_ctrl_get_version(ziti_controller *ctrl, void(*cb)(ctrl_version *, ziti_error *err, void* ctx), void *ctx) {
    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/version");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (void *(*)(const char *, int)) parse_ctrl_version;
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    req->data = resp;
}

void ziti_ctrl_login(ziti_controller *ctrl, void(*cb)(ziti_session*, ziti_error*, void*), void *ctx) {
    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/authenticate?method=cert");
    um_http_req_header(req, "Content-Type", "application/json");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    uv_utsname_t osInfo;
    uv_os_uname(&osInfo);

    const char *body = NULL;
    int body_len = mjson_printf(&mjson_print_dynamic_buf, &body,
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
    um_http_req_data(req, body, body_len, free_body_cb);

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (void *(*)(const char *, int)) parse_ziti_session;
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_login_cb;

    req->data = resp;
}

void ziti_ctrl_current_api_session(ziti_controller *ctrl, void(*cb)(ziti_session*, ziti_error*, void*), void *ctx) {
    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/current-api-session");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (void *(*)(const char *, int)) parse_ziti_session;
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_login_cb;

    req->data = resp;
}

void ziti_ctrl_logout(ziti_controller *ctrl, void(*cb)(void*, ziti_error*, void*), void *ctx) {
    um_http_req_t *req = um_http_req(&ctrl->client, "DELETE", "/current-api-session");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL; /* no body */
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_logout_cb;

    req->data = resp;
}

void ziti_ctrl_get_services(ziti_controller *ctrl, void (*cb)(ziti_service *, ziti_error*, void*), void* ctx) {

    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/services");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (void *(*)(const char *, int)) parse_ziti_service_array;
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_service_cb;

    req->data = resp;
}

void ziti_ctrl_get_service(ziti_controller *ctrl, const char* service_name, void (*cb)(ziti_service *, ziti_error*, void*), void* ctx) {
    char path[1024];
    snprintf(path, sizeof(path), "/services?filter=name=\"%s\"", service_name);

    um_http_req_t *req = um_http_req(&ctrl->client, "GET", path);
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (void *(*)(const char *, int)) parse_ziti_service_array;
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_service_cb;

    req->data = resp;
}

void ziti_ctrl_get_net_session(
        ziti_controller *ctrl, ziti_service *service, const char* type,
        void (*cb)(ziti_net_session *, ziti_error*, void*), void* ctx) {

    char *content = NULL;
    size_t len = mjson_printf(&mjson_print_dynamic_buf, &content,
            "{%Q: %Q, %Q: %Q}",
            "serviceId", service->id,
            "type", type);

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/sessions");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, content, len, free_body_cb);

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (void *(*)(const char *, int)) parse_ziti_net_session;
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    req->data = resp;
}

void ziti_ctrl_get_net_sessions(
        ziti_controller *ctrl, void (*cb)(ziti_net_session **, ziti_error*, void*), void* ctx) {

    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/sessions");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (void *(*)(const char *, int)) parse_ziti_net_session_array;
    resp->resp_cb = (void (*)(void *, ziti_error*, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    req->data = resp;
}

void ziti_ctrl_enroll(ziti_controller *ctrl, enroll_cfg *ecfg, void (*cb)(nf_config*, ziti_error*), void *ctx) {
    char *content = strdup(ecfg->x509_csr_pem);

    char path[1024];
    snprintf(path, sizeof(path), "/enroll?method=%s&token=%s", ecfg->zej->method, ecfg->zej->token);

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", path);

    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;
    um_http_req_header(req, "Content-Type", "text/plain");
    um_http_req_data(req, content, strlen(content), free_body_cb);

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->resp_text_plain = true;   // Make no attempt in ctrl_resp_cb to parse response as JSON
    resp->body_parse_func = NULL;   //   "  "  "  
    resp->resp_cb = (void (*)(nf_config*, ziti_error*)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    req->data = resp;
}

void ziti_ctrl_get_well_known_certs(ziti_controller *ctrl, enroll_cfg *ecfg, void (*cb)(nf_config*, ziti_error*), void *ctx) {
    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/.well-known/est/cacerts");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->resp_text_plain = true;   // Make no attempt in ctrl_resp_cb to parse response as JSON
    resp->body_parse_func = NULL;   //   "  "  "  
    resp->resp_cb = (void (*)(nf_config*, ziti_error*)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    req->data = resp;
}

void ziti_ctrl_get_public_cert(ziti_controller *ctrl, enroll_cfg *ecfg, void (*cb)(nf_config*, ziti_error*), void *ctx) {
    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/");
    req->resp_cb = ctrl_resp_cb;
    req->body_cb = ctrl_body_cb;

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->resp_text_plain = true;   // Make no attempt in ctrl_resp_cb to parse response as JSON
    resp->body_parse_func = NULL;   //   "  "  "  
    resp->resp_cb = (void (*)(nf_config*, ziti_error*)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    req->data = resp;
}
