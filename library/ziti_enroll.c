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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include <ziti/ziti.h>
#include "utils.h"
#include "zt_internal.h"


struct ziti_enroll_req {
    ziti_enroll_opts opts;

    ziti_enroll_cb enroll_cb;
    void *ctx;

    ziti_enrollment_jwt_header jwt_header;
    ziti_enrollment_jwt enrollment;
    char *sig;
    size_t sig_len;

    ziti_config cfg;

    uv_loop_t *loop;
    tls_context *tls;
    tlsuv_private_key_t pk;
    tlsuv_certificate_t cert;
    ziti_controller controller;
};

static int fetch_network_token(struct ziti_enroll_req * er);

static int start_enrollment(struct ziti_enroll_req * er);


static void well_known_certs_cb(char *base64_encoded_pkcs7, const ziti_error *err, void *req);

static void enroll_cb(ziti_enrollment_resp *resp, const ziti_error *err, void *ctx);

static void free_enroll_req(struct ziti_enroll_req *er);

int verify_controller_jwt(const struct tlsuv_certificate_s *cert, void *ctx) {
    ZITI_LOG(DEBUG, "verifying JWT signature");

    struct ziti_enroll_req *er = ctx;
    enum hash_algo md;
    switch (er->jwt_header.alg) {
        case jwt_sig_method_RS256:
        case jwt_sig_method_ES256:
            md = hash_SHA256;
            break;
        case jwt_sig_method_ES384:
            md = hash_SHA384;
            break;
        case jwt_sig_method_ES512:
            md = hash_SHA512;
            break;
        case jwt_sig_method_Unknown:
        default:
            ZITI_LOG(ERROR, "unsupported signature algo");
            return -1;
    }

    int rc = cert->verify(cert, md, er->opts.token,
                          strlen(er->opts.token),
                          er->sig, er->sig_len);
    if (rc != 0) {
        ZITI_LOG(ERROR, "failed to verify JWT signature");
    }
    else {
        ZITI_LOG(DEBUG, "JWT verification succeeded!");
    }
    return rc;
}

#define s_copy(s) ((s) ? strdup(s) : NULL)


int ziti_enroll(const ziti_enroll_opts *opts, uv_loop_t *loop,
                ziti_enroll_cb enroll_cb, void *enroll_ctx) {

    if (enroll_cb == NULL) {
        return ZITI_INVALID_STATE;
    }

    if (opts->token == NULL && opts->url == NULL) {
        ZITI_LOG(ERROR, "enrollment JWT or verifiable controller URL is required");
        return ZITI_JWT_INVALID;
    }

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    char time_str[32];
    ziti_fmt_time(time_str, sizeof(time_str), &start_time);

    ZITI_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting enrollment at (%s.%03d)",
             ziti_get_build_version(false), ziti_git_commit(), ziti_git_branch(),
             time_str, start_time.tv_usec / 1000);


    NEWP(er, struct ziti_enroll_req);
    er->opts.url = s_copy(opts->url);
    er->opts.cert = s_copy(opts->cert);
    er->opts.key = s_copy(opts->key);
    er->opts.name = s_copy(opts->name);
    er->opts.use_keychain = opts->use_keychain;

    er->loop = loop;
    er->ctx = enroll_ctx;
    er->enroll_cb = enroll_cb;

    int rc;

    if (opts->token == NULL) {
        rc = fetch_network_token(er);
    } else {
        char buf[4096];
        size_t len = sizeof(buf);
        char *p = buf;
        int r = load_file(opts->token, strlen(opts->token), &p, &len);
        if (r == 0) {
            er->opts.token = calloc(1, len + 1);
            memcpy((char*)er->opts.token, buf, len);
        } else if (r == UV_EBADF) {

        } else {
            er->opts.token = strdup(opts->token);
        }

        rc = start_enrollment(er);
    }

    if (rc != ZITI_OK) {
        free_enroll_req(er);
    }
    return rc;
}

static void network_jwt_cb(ziti_network_jwt_array arr, const ziti_error *err, void *ctx) {
    struct ziti_enroll_req *er = ctx;
    if (err) {
        er->enroll_cb(NULL, err->err, err->message, er->ctx);
        free_enroll_req(er);
        return;
    }

    er->opts.token = strdup(arr[0]->token);
    free_ziti_network_jwt_array(&arr);

    int rc = start_enrollment(er);
    if (rc != ZITI_OK) {
        er->enroll_cb(NULL, rc, ziti_errorstr(rc), er->ctx);
        free_enroll_req(er);
    }
}

int fetch_network_token(struct ziti_enroll_req *er) {

    struct tlsuv_url_s url;
    int rc = tlsuv_parse_url(&url, er->opts.url);
    if (rc != 0) {
        ZITI_LOG(ERROR, "URL[%s] is invalid", er->opts.url);
        return ZITI_INVALID_CONFIG;
    }

    er->tls = default_tls_context(NULL, 0);

    model_list ctrls = {};

    if (url.query != NULL) {
        // TODO magic URL
    } else {
        // controller URL must be verifiable with default/OS cert bundle
        model_list_append(&ctrls, er->opts.url);
        rc = ziti_ctrl_init(er->loop, &er->controller, &ctrls, er->tls);
        if (rc == ZITI_OK) {
            ziti_ctrl_get_network_jwt(&er->controller, network_jwt_cb, er);
        }
    }

    model_list_clear(&ctrls, NULL);
    return rc;
}

static int start_enrollment(struct ziti_enroll_req *er) {

    if (er->tls) {
        er->tls->free_ctx(er->tls);
        er->tls = NULL;
    }
    ziti_ctrl_close(&er->controller);

    if (parse_enrollment_jwt(er->opts.token, &er->jwt_header, &er->enrollment, &er->sig, &er->sig_len) != ZITI_OK) {
        return ZITI_JWT_INVALID;
    }

    er->tls = default_tls_context("", 0); // no default CAs
    er->tls->set_cert_verify(er->tls, verify_controller_jwt, er);

    // check key/cert if provided
    if (er->opts.key != NULL) {
        if (load_key_internal(er->tls, &er->pk, er->opts.key) != 0) {
            if (strncmp(er->opts.key, "pkcs11://", strlen("pkcs11://")) != 0) {
                ZITI_LOG(ERROR, "failed to load provided key");
                return ZITI_KEY_LOAD_FAILED;
            }

            ZITI_LOG(INFO, "pkcs11 key not found. trying to generate");
            int rc = gen_p11_key_internal(er->tls, &er->pk, er->opts.key);
            if (rc != 0) {
                ZITI_LOG(ERROR, "failed to load or generate pkcs11 key: %s", ziti_errorstr(rc));
                return ZITI_KEY_LOAD_FAILED;
            }
        }
    }
    er->cfg.id.key = s_copy(er->opts.key);


    if (er->enrollment.method == ziti_enrollment_method_ottca ||
        er->enrollment.method == ziti_enrollment_method_ca) {
        if (er->pk == NULL) {
            ZITI_LOG(ERROR, "key is required");
            return ZITI_INVALID_CERT_KEY_PAIR;
        }

        int rc = 0;
        if (er->opts.cert != NULL) {
            rc = er->tls->load_cert(&er->cert, er->opts.cert, strlen(er->opts.cert)) ? ZITI_INVALID_AUTHENTICATOR_CERT : ZITI_OK;
        } else if (er->pk->get_certificate) {
            rc = er->pk->get_certificate(er->pk, &er->cert) ? ZITI_ENROLLMENT_CERTIFICATE_REQUIRED : ZITI_OK;
        } else {
            rc = ZITI_ENROLLMENT_CERTIFICATE_REQUIRED;
        }
        if (rc != ZITI_OK) {
            return rc;
        }
        er->cfg.id.cert = s_copy(er->opts.cert);
    }

    er->cfg.controller_url = strdup(er->enrollment.controller);
    model_list_append(&er->cfg.controllers, strdup(er->enrollment.controller));
    ziti_ctrl_init(er->loop, &er->controller, &er->cfg.controllers, er->tls);

    ziti_ctrl_get_well_known_certs(&er->controller, well_known_certs_cb, er);
    return ZITI_OK;
}

static void free_enroll_req(struct ziti_enroll_req * er) {
    if (er) {
        if (er->controller.loop) {
            ziti_ctrl_close(&er->controller);
        }
        if (er->tls) er->tls->free_ctx(er->tls);
        if (er->pk != NULL) { er->pk->free(er->pk); }
        if (er->cert != NULL) { er->cert->free(er->cert); }

        free_ziti_enrollment_jwt_header(&er->jwt_header);
        free_ziti_enrollment_jwt(&er->enrollment);
        free(er->sig);
        free_ziti_config(&er->cfg);
        free((char*)er->opts.key);
        free((char*)er->opts.cert);
        free((char*)er->opts.token);
        free((char*)er->opts.name);
        free((char*)er->opts.url);
        free(er);
    }
}

static void complete_request(struct ziti_enroll_req *er, int err) {
    if (err == ZITI_OK) {
        er->enroll_cb(&er->cfg, err, NULL, er->ctx);
    } else {
        er->enroll_cb(NULL, err, ziti_errorstr(err), er->ctx);
    }

    free_enroll_req(er);
}

static void enroll_network(struct ziti_enroll_req *er) {
    complete_request(er, ZITI_OK);
}

static void enroll_ott(struct ziti_enroll_req *er) {
    size_t len;
    int rc = 0;
    if (er->opts.key == NULL) {
        if (er->opts.use_keychain && er->tls->generate_keychain_key) {
            struct tlsuv_url_s url;
            tlsuv_parse_url(&url, er->enrollment.controller);

            string_buf_t *keyname_buf = new_string_buf();
            string_buf_fmt(keyname_buf, "keychain:ziti://%s@%.*s:%d",
                           er->enrollment.subject,
                           (int)url.hostname_len, url.hostname, url.port);
            char *keyname_ref = string_buf_to_string(keyname_buf, NULL);
            delete_string_buf(keyname_buf);

            char *keyname = strchr(keyname_ref, ':') + 1;

            rc = er->tls->generate_keychain_key(&er->pk, keyname);
            if (rc != 0) {
                complete_request(er, ZITI_KEY_GENERATION_FAILED);
                return;
            }
            er->cfg.id.key = keyname_ref;
        } else {
            if (er->tls->generate_key(&er->pk) != 0 ||
                er->pk->to_pem( er->pk, (char **) &er->cfg.id.key, &len)) {
                complete_request(er, ZITI_KEY_GENERATION_FAILED);
                return;
            }
        }
    } else if (er->pk == NULL) {
        // key should've been loaded already
        complete_request(er, ZITI_KEY_LOAD_FAILED);
        return;
    }

    char *csr = NULL;
    if (er->tls->generate_csr_to_pem(er->pk, &csr, &len,
                                     "O", "OpenZiti",
                                     "DC", er->enrollment.controller,
                                     "CN", er->enrollment.subject,
                                     NULL) != 0) {
        complete_request(er, ZITI_CSR_GENERATION_FAILED);
        return;
    }

    ziti_ctrl_enroll(&er->controller, er->enrollment.method, er->enrollment.token, csr, er->opts.name, enroll_cb, er);
    free(csr);
}

static void enroll_ca(struct ziti_enroll_req *er) {
    assert(er->pk != NULL);
    assert(er->cert != NULL);
    if (er->tls->set_own_cert(er->tls, er->pk, er->cert) != 0) {
        complete_request(er, ZITI_INVALID_CERT_KEY_PAIR);
        return;
    }

    ziti_ctrl_enroll(&er->controller, er->enrollment.method, er->enrollment.token, NULL, er->opts.name, enroll_cb, er);
}

static void well_known_certs_cb(char *base64_encoded_pkcs7, const ziti_error *err, void *req) {
    struct ziti_enroll_req *er = req;
    if (err != NULL) {
        ZITI_LOG_ERROR(ERROR, err, "failed to fetch CA bundle");
        complete_request(er, (int)err->err);
        return;
    }

    ZITI_LOG(VERBOSE, "base64_encoded_pkcs7 is: %s", base64_encoded_pkcs7);
    tlsuv_certificate_t chain = NULL;

    size_t total_pem_len = 0;
    char *ca_pem = NULL;
    if (er->tls->parse_pkcs7_certs(&chain, base64_encoded_pkcs7, strlen(base64_encoded_pkcs7)) != 0 ||
        chain->to_pem(chain, 1, &ca_pem, &total_pem_len) != 0) {
        free(base64_encoded_pkcs7);
        complete_request(er, ZITI_PKCS7_ASN1_PARSING_FAILED);
        return;
    }
    free(base64_encoded_pkcs7);
    chain->free(chain);
    er->cfg.id.ca = ca_pem;

    ZITI_LOG(DEBUG, "CA PEM len = %zd", total_pem_len);
    ZITI_LOG(TRACE, "CA PEM:\n%s", er->cfg.id.ca);

    ziti_ctrl_close(&er->controller);
    er->tls->free_ctx(er->tls);

    er->tls = default_tls_context(er->cfg.id.ca, strlen(er->cfg.id.ca));
    ziti_ctrl_init(er->loop, &er->controller, &er->cfg.controllers, er->tls);

    switch (er->enrollment.method) {
    case ziti_enrollment_method_network:
        enroll_network(er);
        break;
    case ziti_enrollment_method_ott:
        enroll_ott(er);
        break;
    case ziti_enrollment_method_ottca:
    case ziti_enrollment_method_ca:
        enroll_ca(er);
        break;
    case ziti_enrollment_method_Unknown:
    default:
        ZITI_LOG(ERROR, "unknown enrollment method");
        er->enroll_cb(NULL, ZITI_OK, NULL, er->ctx);
        free_enroll_req(er);
        break;
    }

}

static void enroll_cb(ziti_enrollment_resp *resp, const ziti_error *err, void *enroll_ctx) {
    assert(enroll_ctx);
    struct ziti_enroll_req *er = enroll_ctx;

    if (err != NULL) {
        ZITI_LOG_ERROR(ERROR, err, "failed to enroll with controller: %s", er->controller.url);
        complete_request(er, (int)err->err);
        return;
    }

    ZITI_LOG(DEBUG, "successfully enrolled with controller %s", er->controller.url);
    er->cfg.id.cert = resp->cert ? strdup(resp->cert) : strdup(er->opts.cert);

    complete_request(er, ZITI_OK);
    free_ziti_enrollment_resp_ptr(resp);
}


int parse_enrollment_jwt(const char *token, ziti_enrollment_jwt_header *zejh, ziti_enrollment_jwt *zej, char **sig, size_t *sig_len) {
    char *header = NULL;
    char *body = NULL;

    const char *dot1 = strchr(token, '.');
    if (NULL == dot1) {
        ZITI_LOG(ERROR, "jwt input lacks a dot");
        return ZITI_JWT_INVALID_FORMAT;
    }

    char *dot2 = strchr(dot1 + 1, '.');
    if (NULL == dot2) {
        ZITI_LOG(ERROR, "jwt input lacks a second dot");
        return ZITI_JWT_INVALID_FORMAT;
    }

    size_t header_len;
    tlsuv_base64url_decode(token, &header, &header_len);

    if (parse_ziti_enrollment_jwt_header(zejh, header, header_len) < 0) {
        free_ziti_enrollment_jwt_header(zejh);
        free(header);
        return ZITI_JWT_INVALID_FORMAT;
    }
    free(header);

    size_t blen;
    tlsuv_base64url_decode(dot1 + 1, &body, &blen);

    if (parse_ziti_enrollment_jwt(zej, body, blen) < 0) {
        free_ziti_enrollment_jwt(zej);
        free(body);
        return ZITI_JWT_INVALID_FORMAT;
    }
    free(body);

    *dot2 = 0;
    ZITI_LOG(DEBUG, "jwt signature is: %s", dot2 + 1);
    tlsuv_base64url_decode(dot2 + 1, sig, sig_len);


    return ZITI_OK;
}