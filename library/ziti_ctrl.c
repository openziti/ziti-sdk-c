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
#include <ziti_ctrl.h>
#include <uv_mbed/um_http.h>


#define DEFAULT_PAGE_SIZE 25
#define ZITI_CTRL_KEEPALIVE 0
#define ZITI_CTRL_TIMEOUT 15000

const char *const PC_DOMAIN_TYPE = "DOMAIN";
const char *const PC_OS_TYPE = "OS";
const char *const PC_PROCESS_TYPE = "PROCESS";
const char *const PC_MAC_TYPE = "MAC";

#undef MODEL_API
#define MODEL_API static

#define PAGINATION_MODEL(XX, ...) \
XX(limit, int, none, limit, __VA_ARGS__) \
XX(offset, int, none, offset, __VA_ARGS__) \
XX(total, int, none, totalCount, __VA_ARGS__) \

DECLARE_MODEL(resp_pagination, PAGINATION_MODEL)

#define RESP_META_MODEL(XX, ...) \
XX(pagination,resp_pagination,none,pagination, __VA_ARGS__)

DECLARE_MODEL(resp_meta, RESP_META_MODEL)

#define API_RESP_MODEL(XX, ...) \
XX(meta, resp_meta, none, meta, __VA_ARGS__) \
XX(data, json, none, data, __VA_ARGS__) \
XX(error, ziti_error, ptr, error, __VA_ARGS__)

DECLARE_MODEL(api_resp, API_RESP_MODEL)

IMPL_MODEL(resp_pagination, PAGINATION_MODEL)

IMPL_MODEL(resp_meta, RESP_META_MODEL)

IMPL_MODEL(api_resp, API_RESP_MODEL)

int code_to_error(const char *code) {

#define CODE_MAP(XX) \
XX(CONTROLLER_UNAVAILABLE, ZITI_CONTROLLER_UNAVAILABLE) \
XX(NO_ROUTABLE_INGRESS_NODES, ZITI_GATEWAY_UNAVAILABLE) \
XX(NO_EDGE_ROUTERS_AVAILABLE, ZITI_GATEWAY_UNAVAILABLE) \
XX(INVALID_AUTHENTICATION, ZITI_NOT_AUTHORIZED)         \
XX(REQUIRES_CERT_AUTH, ZITI_NOT_AUTHORIZED)             \
XX(UNAUTHORIZED, ZITI_NOT_AUTHORIZED)                   \
XX(INVALID_POSTURE, ZITI_INVALID_POSTURE)               \
XX(INVALID_AUTH, ZITI_NOT_AUTHORIZED)                   \
XX(MFA_INVALID_TOKEN, ZITI_MFA_INVALID_TOKEN)           \
XX(MFA_EXISTS, ZITI_MFA_EXISTS)                         \
XX(MFA_NOT_ENROLLED, ZITI_MFA_NOT_ENROLLED)


#define CODE_MATCH(c, err) if (strcmp(code,#c) == 0) return err;

    if (code == NULL) { return ZITI_OK; }

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

    bool paging;
    const char *base_path;
    int limit;
    int total;
    int recd;
    void **resp_array;

    int (*body_parse_func)(void *, const char *, size_t);

    void (*resp_cb)(void *, ziti_error *, void *);

    void *ctx;

    ziti_controller *ctrl;

    void (*ctrl_cb)(void *, ziti_error *, struct ctrl_resp *);
};

static void ctrl_paging_req(struct ctrl_resp *resp);

static char *str_array_to_json(const char **arr);

static void ctrl_default_cb(void *s, ziti_error *e, struct ctrl_resp *resp);

static void ctrl_body_cb(um_http_req_t *req, const char *b, ssize_t len);

static void ctrl_resp_cb(um_http_resp_t *r, void *data) {
    struct ctrl_resp *resp = data;
    resp->status = r->code;
    if (r->code < 0) {
        NEWP(err, ziti_error);
        err->err = ZITI_CONTROLLER_UNAVAILABLE;
        err->code = strdup("CONTROLLER_UNAVAILABLE");
        err->message = strdup(uv_strerror(r->code));
        ctrl_default_cb(NULL, err, resp);
    } else {
        r->body_cb = ctrl_body_cb;
        um_http_hdr *h;
        LIST_FOREACH(h, &r->headers, _next) {
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

static void ctrl_default_cb(void *s, ziti_error *e, struct ctrl_resp *resp) {
    if (resp->resp_cb) {
        resp->resp_cb(s, e, resp->ctx);
    }

    free(resp);
}

static void ctrl_version_cb(ziti_version *v, ziti_error *e, struct ctrl_resp *resp) {
    if (e) {
        ZITI_LOG(ERROR, "%s(%s)", e->code, e->message);
    }

    if (v) {
        resp->ctrl->version.version = strdup(v->version);
        resp->ctrl->version.revision = strdup(v->revision);
        resp->ctrl->version.build_date = strdup(v->build_date);
    }
    ctrl_default_cb(v, e, resp);
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

static void ctrl_services_cb(ziti_service **services, ziti_error *e, struct ctrl_resp *resp) {
    ctrl_default_cb(services, e, resp);
}

static void free_body_cb(um_http_req_t *req, const char *body, ssize_t len) {
    free((char *) body);
}

static void ctrl_body_cb(um_http_req_t *req, const char *b, ssize_t len) {
    struct ctrl_resp *resp = req->data;

    if (len > 0) {
        if (resp->resp_chunked) {
            resp->body = realloc(resp->body, resp->received + len);
        }
        memcpy(resp->body + resp->received, b, len);
        resp->received += len;
    } else if (len == UV_EOF) {
        void *resp_obj = NULL;

        api_resp cr = {0};
        if (resp->resp_text_plain && resp->status < 300) {
            resp_obj = calloc(1, resp->received + 1);
            memcpy(resp_obj, resp->body, resp->received);
        } else {
            int rc = parse_api_resp(&cr, resp->body, resp->received);
            if (rc < 0) {
                ZITI_LOG(ERROR, "failed to parse controller response of req[%s]", req->path);
                cr.error = alloc_ziti_error();
                cr.error->err = ZITI_WTF;
                cr.error->code = strdup("INVALID_CONTROLLER_RESPONSE");
                cr.error->message = strdup(req->resp.status);
            }
            else if (resp->body_parse_func && cr.data != NULL) {
                if (resp->body_parse_func(&resp_obj, cr.data, strlen(cr.data)) != 0) {
                    ZITI_LOG(ERROR, "error parsing result of req[%s]", req->path);
                }

                if (resp->paging) {
                    bool last_page = cr.meta.pagination.total <= cr.meta.pagination.offset + cr.meta.pagination.limit;
                    if (cr.meta.pagination.total > resp->total) {
                        resp->total = cr.meta.pagination.total;
                        resp->resp_array = realloc(resp->resp_array, (resp->total + 1) * sizeof(void *));
                    }
                    // empty result
                    if (resp->resp_array == NULL) {
                        resp->resp_array = calloc(1, sizeof(void *));
                    }

                    void **chunk = resp_obj;
                    while (*chunk != NULL) {
                        resp->resp_array[resp->recd++] = *chunk++;
                    }
                    resp->resp_array[resp->recd] = NULL;
                    FREE(resp_obj);
                    resp->received = 0;
                    FREE(resp->body);

                    free_api_resp(&cr);
                    if (!last_page) {
                        ctrl_paging_req(resp);
                        return;
                    }
                    resp_obj = resp->resp_array;
                }
            }
        }

        if (cr.error) {
            cr.error->err = code_to_error(cr.error->code);
            cr.error->http_code = req->resp.code;
        }

        free_resp_meta(&cr.meta);
        FREE(cr.data);
        FREE(resp->body);

        resp->ctrl_cb(resp_obj, cr.error, resp);
    } else {
        ZITI_LOG(ERROR, "Unexpected ERROR: %zd", len);
    }
}

int ziti_ctrl_init(uv_loop_t *loop, ziti_controller *ctrl, const char *url, tls_context *tls) {
    um_http_init(loop, &ctrl->client, url);
    um_http_set_ssl(&ctrl->client, tls);
    um_http_idle_keepalive(&ctrl->client, ZITI_CTRL_KEEPALIVE);
    um_http_connect_timeout(&ctrl->client, ZITI_CTRL_TIMEOUT);
    um_http_header(&ctrl->client, "Accept", "application/json");
    ctrl->session = NULL;

    return ZITI_OK;
}

int ziti_ctrl_close(ziti_controller *ctrl) {
    if (ctrl->session != NULL) {
        FREE(ctrl->session);
        free_ziti_version(&ctrl->version);
        um_http_close(&ctrl->client);
    }
    return ZITI_OK;
}

void ziti_ctrl_get_version(ziti_controller *ctrl, void(*cb)(ziti_version *, ziti_error *err, void *ctx), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_version_ptr;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_version_cb;

    um_http_req(&ctrl->client, "GET", "/version", ctrl_resp_cb, resp);
}

void ziti_ctrl_login(
        ziti_controller *ctrl,
        const char **cfg_types,
        void(*cb)(ziti_session *, ziti_error *, void *),
        void *ctx) {

    uv_utsname_t osInfo;
    uv_os_uname(&osInfo);

    ziti_auth_req authreq = {
            .sdk_info = {
                    .type = "ziti-sdk-c",
                    .version = (char *) ziti_get_build_version(0),
                    .revision = (char *) ziti_git_commit(),
                    .branch = (char *) ziti_git_branch(),
                    .app_id = (char *) APP_ID,
                    .app_version = (char *) APP_VERSION,
            },
            .env_info = {
                    .os = osInfo.sysname,
                    .os_release = osInfo.release,
                    .os_version = osInfo.version,
                    .arch = osInfo.machine,
            },
            .config_types = (string_array) cfg_types,
    };

    size_t body_len;
    char *body = ziti_auth_req_to_json(&authreq, 0, &body_len);

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_session_ptr;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_login_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/authenticate?method=cert", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_current_api_session(ziti_controller *ctrl, void(*cb)(ziti_session *, ziti_error *, void *), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_session_ptr;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_login_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/current-api-session", ctrl_resp_cb, resp);
}

void ziti_ctrl_logout(ziti_controller *ctrl, void(*cb)(void *, ziti_error *, void *), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL; /* no body */
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_logout_cb;

    um_http_req(&ctrl->client, "DELETE", "/current-api-session", ctrl_resp_cb, resp);
}

void ziti_ctrl_get_services_update(ziti_controller *ctrl, void (*cb)(ziti_service_update*, ziti_error*, void*), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_service_update_ptr;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req(&ctrl->client, "GET", "/current-api-session/service-updates", ctrl_resp_cb, resp);
}

void ziti_ctrl_get_services(ziti_controller *ctrl, void (*cb)(ziti_service_array, ziti_error *, void *), void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_service_array;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_services_cb;

    resp->paging = true;
    resp->base_path = "/services";
    ctrl_paging_req(resp);
}

void ziti_ctrl_current_edge_routers(ziti_controller *ctrl, void (*cb)(ziti_edge_router_array, ziti_error *, void *),
                                    void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_edge_router_array;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    resp->paging = true;
    resp->base_path = "/current-identity/edge-routers";
    ctrl_paging_req(resp);
}

void
ziti_ctrl_get_service(ziti_controller *ctrl, const char *service_name, void (*cb)(ziti_service *, ziti_error *, void *),
                      void *ctx) {
    char path[1024];
    snprintf(path, sizeof(path), "/services?filter=name=\"%s\"", service_name);

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_service_array;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_service_cb;

    um_http_req(&ctrl->client, "GET", path, ctrl_resp_cb, resp);
}

void ziti_ctrl_get_net_session(
        ziti_controller *ctrl, const char *service_id, const char *type,
        void (*cb)(ziti_net_session *, ziti_error *, void *), void *ctx) {

    char *content = malloc(128);
    size_t len = snprintf(content, 128,
                          "{\"serviceId\": \"%s\", \"type\": \"%s\"}",
                          service_id, type);

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_net_session_ptr;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/sessions", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, content, len, free_body_cb);
}

void ziti_ctrl_get_sessions(
        ziti_controller *ctrl, void (*cb)(ziti_net_session **, ziti_error *, void *), void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_net_session_array;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    resp->paging = true;
    resp->base_path = "/sessions";
    ctrl_paging_req(resp);
}

static void enroll_pem_cb(void *body, ziti_error *err, struct ctrl_resp *resp) {
    ziti_enrollment_resp *er = alloc_ziti_enrollment_resp();
    er->cert = (char *) body;
    if (resp->resp_cb) {
        resp->resp_cb(er, err, resp->ctx);
    }
}

static void ctrl_enroll_http_cb(um_http_resp_t *http_resp, void *data) {
    if (http_resp->code < 0) {
        ctrl_resp_cb(http_resp, data);
    } else {
        const char *content_type = um_http_resp_header(http_resp, "content-type");
        if (content_type != NULL && strcasecmp("application/x-pem-file", content_type) == 0) {
            struct ctrl_resp *resp = data;
            resp->resp_text_plain = true;
            resp->ctrl_cb = enroll_pem_cb;
        }
        ctrl_resp_cb(http_resp, data);
    }
}

void
ziti_ctrl_enroll(ziti_controller *ctrl, const char *method, const char *token, const char *csr,
                 void (*cb)(ziti_enrollment_resp *, ziti_error *, void *),
                 void *ctx) {
    char path[1024];
    snprintf(path, sizeof(path), "/enroll?method=%s", method);

    if (token) {
        strcat(path, "&token=");
        strcat(path, token);
    }

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_enrollment_resp_ptr;   //   "  "  "
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", path, ctrl_enroll_http_cb, resp);
    um_http_req_header(req, "Content-Type", "text/plain");
    if (csr) {
        um_http_req_data(req, csr, strlen(csr), NULL);
    }
}

void
ziti_ctrl_get_well_known_certs(ziti_controller *ctrl, void (*cb)(char *, ziti_error *, void *), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->resp_text_plain = true;   // Make no attempt in ctrl_resp_cb to parse response as JSON
    resp->body_parse_func = NULL;   //   "  "  "  
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/.well-known/est/cacerts", ctrl_resp_cb, resp);
    um_http_req_header(req, "Accept", "application/pkcs7-mime");
}

void ziti_ctrl_get_public_cert(ziti_controller *ctrl, enroll_cfg *ecfg, void (*cb)(ziti_config *, ziti_error *, void *),
                               void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->resp_text_plain = true;   // Make no attempt in ctrl_resp_cb to parse response as JSON
    resp->body_parse_func = NULL;   //   "  "  "  
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req(&ctrl->client, "GET", "/", ctrl_resp_cb, resp);
}

static char *str_array_to_json(const char **arr) {
    if (arr == NULL) {
        return strdup("null");
    }

    size_t json_len = 3; //"[]"
    const char **p = arr;
    while (*p != NULL) {
        json_len += strlen(*p) + 3;
        p++;
    }

    p = arr;
    char *json = malloc(json_len);
    char *outp = json;
    *outp++ = '[';
    while (*p != NULL) {
        *outp++ = '"';
        strcpy(outp, *p);
        outp += strlen(*p);
        *outp++ = '"';
        if (*(++p) != NULL) {
            *outp++ = ',';
        }
    }
    *outp++ = ']';
    *outp = '\0';
    return json;
}

void ziti_pr_post(ziti_controller *ctrl, char *body, size_t body_len,
                  void(*cb)(void *, ziti_error *, void *), void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/posture-response", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_pr_post_bulk(ziti_controller *ctrl, char *body, size_t body_len,
                  void(*cb)(void *, ziti_error *, void *), void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/posture-response-bulk", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, body, body_len, free_body_cb);
}

static void ctrl_paging_req(struct ctrl_resp *resp) {
    if (resp->limit == 0) {
        resp->limit = DEFAULT_PAGE_SIZE;
    }
    char query = strchr(resp->base_path, '?') ? '&' : '?';
    char path[128];
    snprintf(path, sizeof(path), "%s%climit=%d&offset=%d", resp->base_path, query, resp->limit, resp->recd);
    ZITI_LOG(VERBOSE, "requesting %s", path);
    um_http_req(&resp->ctrl->client, "GET", path, ctrl_resp_cb, resp);
}



void ziti_ctrl_login_mfa(ziti_controller *ctrl, char* body, size_t body_len ,void(*cb)(void *, ziti_error *, void *), void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/authenticate/mfa", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_post_mfa(ziti_controller *ctrl,void(*cb)(void *, ziti_error *, void *), void *ctx){
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/current-identity/mfa", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, NULL, 0, free_body_cb);
}

void ziti_ctrl_get_mfa(ziti_controller *ctrl, void(*cb)(ziti_mfa_enrollment *, ziti_error *, void *), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_mfa_enrollment_ptr;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/current-identity/mfa", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
}

void ziti_ctrl_delete_mfa(ziti_controller *ctrl, char* code, void(*cb)(void *, ziti_error *, void *), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "DELETE", "/current-identity/mfa", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_header(req, "mfa-validation-code", code);
}

void ziti_ctrl_post_mfa_verify(ziti_controller *ctrl, char* body, size_t body_len, void(*cb)(void *, ziti_error *, void *), void *ctx){
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/current-identity/mfa/verify", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_get_mfa_recovery_codes(ziti_controller *ctrl, char* code, void(*cb)(ziti_mfa_recovery_codes *, ziti_error *, void *), void *ctx){
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_mfa_recovery_codes_ptr;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "GET", "/current-identity/mfa/recovery-codes", ctrl_resp_cb, resp);
    um_http_req_header(req, "mfa-validation-code", code);
    um_http_req_header(req, "Content-Type", "application/json");
}

void ziti_ctrl_post_mfa_recovery_codes(ziti_controller *ctrl, char* body, size_t body_len, void(*cb)(void *,ziti_error *, void *), void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = NULL;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req_t *req = um_http_req(&ctrl->client, "POST", "/current-identity/mfa/recovery-codes", ctrl_resp_cb, resp);
    um_http_req_header(req, "Content-Type", "application/json");
    um_http_req_data(req, body, body_len, free_body_cb);
}