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

#if _WIN32

#define strcasecmp _stricmp
#define strncasecmp _strnicmp

#endif

const char *const PC_DOMAIN_TYPE = "DOMAIN";
const char *const PC_OS_TYPE = "OS";
const char *const PC_PROCESS_TYPE = "PROCESS";
const char *const PC_MAC_TYPE = "MAC";

#define CTRL_REQ_MODEL(XX, ...) \
XX(meta, json, none, meta, __VA_ARGS__) \
XX(data, json, none, data, __VA_ARGS__) \
XX(error, ziti_error, ptr, error, __VA_ARGS__)

#define MODEL_API static
DECLARE_MODEL(ctrl_resp, CTRL_REQ_MODEL)

IMPL_MODEL(ctrl_resp, CTRL_REQ_MODEL)

int code_to_error(const char *code) {

#define CODE_MAP(XX) \
XX(CONTROLLER_UNAVAILABLE, ZITI_CONTROLLER_UNAVAILABLE) \
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

    int (*body_parse_func)(void *, const char *, size_t);

    void (*resp_cb)(void *, ziti_error *, void *);

    void *ctx;

    ziti_controller *ctrl;

    void (*ctrl_cb)(void *, ziti_error *, struct ctrl_resp *);
};

static char *str_array_to_json(const char **arr);

static void ctrl_default_cb(void *s, ziti_error *e, struct ctrl_resp *resp);

static void ctrl_body_cb(um_http_req_t *req, const char *b, ssize_t len);

static void ctrl_resp_cb(um_http_resp_t *r, void *data) {
    struct ctrl_resp *resp = data;
    resp->status = r->code;
    if (r->code < 0) {
        NEWP(err, ziti_error);
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

        ctrl_resp cr = {0};
        if (resp->resp_text_plain && resp->status < 300) {
            resp_obj = calloc(1, resp->received + 1);
            memcpy(resp_obj, resp->body, resp->received);
        } else {
            int rc = parse_ctrl_resp(&cr, resp->body, resp->received);
            if (rc < 0) {
                ZITI_LOG(ERROR, "failed to parse controller response of req[%s]", req->path);
                cr.error = alloc_ziti_error();
                cr.error->code = strdup("INVALID_CONTROLLER_RESPONSE");
                cr.error->message = strdup(req->resp.status);
            } else if (resp->body_parse_func && cr.data != NULL) {
                if (resp->body_parse_func(&resp_obj, cr.data, strlen(cr.data)) != 0) {
                    ZITI_LOG(ERROR, "error parsing result of req[%s]", req->path);
                }
            }
        }
        FREE(cr.meta);
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
    um_http_idle_keepalive(&ctrl->client, 0);
    um_http_header(&ctrl->client, "Accept", "application/json");
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
            },
            .env_info = {
                    .os = osInfo.sysname,
                    .os_release = osInfo.release,
                    .os_version = osInfo.version,
                    .arch = osInfo.machine,
            },
            .config_types = (string_array) cfg_types,
    };

    char *body = malloc(1024);
    size_t body_len;
    json_from_ziti_auth_req(&authreq, body, 1024, &body_len);

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

void ziti_ctrl_get_services(ziti_controller *ctrl, void (*cb)(ziti_service_array, ziti_error *, void *), void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_service_array;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = (void (*)(void *, ziti_error *, struct ctrl_resp *)) ctrl_services_cb;

    um_http_req(&ctrl->client, "GET", "/services?limit=1000", ctrl_resp_cb, resp);
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
        ziti_controller *ctrl, ziti_service *service, const char *type,
        void (*cb)(ziti_net_session *, ziti_error *, void *), void *ctx) {

    char *content = malloc(128);
    size_t len = snprintf(content, 128,
                          "{\"serviceId\": \"%s\", \"type\": \"%s\"}",
                          service->id, type);

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

void ziti_ctrl_get_net_sessions(
        ziti_controller *ctrl, void (*cb)(ziti_net_session **, ziti_error *, void *), void *ctx) {

    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = (int (*)(void *, const char *, size_t)) parse_ziti_net_session_array;
    resp->resp_cb = (void (*)(void *, ziti_error *, void *)) cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;

    um_http_req(&ctrl->client, "GET", "/sessions", ctrl_resp_cb, resp);
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

void ziti_ctrl_pr_post_domain(ziti_controller *ctrl, char *id, char *domain,
                              void (*cb)(void *, ziti_error *, void *),
                              void *ctx) {
    ziti_pr_domain_req domain_req = {
            .id = id,
            .domain = domain,
            .typeId = PC_DOMAIN_TYPE,
    };

    char *body = malloc(1024);
    size_t body_len;

    json_from_ziti_pr_domain_req(&domain_req, body, 1024, &body_len);

    ziti_pr_post(ctrl, body, body_len, cb, ctx);
}

void ziti_ctrl_pr_post_mac(ziti_controller *ctrl, char *id, char **mac_addresses, int num_addresses,
                           void (*cb)(void *, ziti_error *, void *),
                           void *ctx) {

    size_t arr_size = sizeof(char (**));
    char **addresses = calloc((num_addresses + 1), arr_size);

    memcpy(addresses, mac_addresses, (num_addresses) * arr_size);

    ziti_pr_mac_req mac_req = {
            .id = id,
            .typeId = PC_MAC_TYPE,
            .mac_addresses = addresses,
    };

    char *body = malloc(1024);
    size_t body_len;

    json_from_ziti_pr_mac_req(&mac_req, body, 1024, &body_len);

    ziti_pr_post(ctrl, body, body_len, cb, ctx);

    free(addresses);
}

void ziti_ctrl_pr_post_os(ziti_controller *ctrl, char *id, char *os_type, char *os_version, char *os_build,
                          void (*cb)(void *, ziti_error *, void *),
                          void *ctx) {
    ziti_pr_os_req os_req = {
            .id = id,
            .typeId = PC_OS_TYPE,
            .type = os_type,
            .version = os_version,
            .build = os_build
    };

    char *body = malloc(1024);
    size_t body_len;

    json_from_ziti_pr_os_req(&os_req, body, 1024, &body_len);

    ziti_pr_post(ctrl, body, body_len, cb, ctx);
}

void ziti_ctrl_pr_post_process(ziti_controller *ctrl, char *id, bool is_running, char *sha_512_hash, char **signers,
                               int num_signers,
                               void (*cb)(void *, ziti_error *, void *),
                               void *ctx) {

    size_t arr_size = sizeof(char (**));
    char **null_term_signers = calloc((num_signers + 1), arr_size);
    memcpy(null_term_signers, signers, num_signers * arr_size);

    ziti_pr_process_req process_req = {
            .id = id,
            .typeId = PC_PROCESS_TYPE,
            .is_running = is_running,
            .hash = sha_512_hash,
            .signers = null_term_signers,
    };

    char *body = malloc(1024);
    size_t body_len;

    json_from_ziti_pr_process_req(&process_req, body, 1024, &body_len);

    ziti_pr_post(ctrl, body, body_len, cb, ctx);

    free(null_term_signers);
}
