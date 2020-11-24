/*
Copyright 2019-2020 NetFoundry, Inc.

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
#include <string.h>

#include <ziti/ziti.h>
#include <uv.h>
#include "utils.h"
#include "zt_internal.h"
#include "ziti_enroll.h"

#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#elif _WIN32
#define MAXPATHLEN 260
#else
#define MAXPATHLEN 4096
#endif
#endif

#if _WIN32
#define strncasecmp _strnicmp
#endif

static void well_known_certs_cb(char *base64_encoded_pkcs7, ziti_error *err, void *req);

static void enroll_cb(ziti_enrollment_resp *er, ziti_error *err, void *ctx);

static void async_connects(uv_async_t *ar) {
    ziti_context ztx = ar->data;
    ziti_process_connect_reqs(ztx);
}

int verify_controller_jwt(tls_cert cert, void *ctx) {
    ZITI_LOG(INFO, "verifying JWT signature");

    enroll_cfg *ecfg = ctx;
    enum hash_algo md;
    if (strcmp(ecfg->zejh->alg, "RS256") == 0) {
        md = hash_SHA256;
    }
    else if (strcmp(ecfg->zejh->alg, "ES256") == 0) {
        md = hash_SHA256;
    }
    else if (strcmp(ecfg->zejh->alg, "ES384") == 0) {
        md = hash_SHA384;
    }
    else if (strcmp(ecfg->zejh->alg, "ES512") == 0) {
        md = hash_SHA512;
    }
    else {
        ZITI_LOG(ERROR, "unsupported signature algo `%s'", ecfg->zejh->alg);
        return -1;
    }

    int rc = ecfg->tls->api->verify_signature(cert, md, (char *) ecfg->jwt_signing_input,
                                              strlen((char *) ecfg->jwt_signing_input),
                                              ecfg->jwt_sig, ecfg->jwt_sig_len);
    if (rc != 0) {
        ZITI_LOG(ERROR, "failed to verify JWT signature");
    }
    else {
        ZITI_LOG(DEBUG, "JWT verification succeeded!");
    }
    return rc;
}

static int check_cert_required(enroll_cfg *ecfg) {
    if (strcmp(ecfg->zej->method, "ca") == 0 || strcmp(ecfg->zej->method, "ottca") == 0) {
        if (ecfg->own_cert == NULL || ecfg->private_key == 0) {
            return ZITI_ENROLLMENT_CERTIFICATE_REQUIRED;
        }
    }
    return ZITI_OK;
}

int ziti_enroll(ziti_enroll_opts *opts, uv_loop_t *loop, ziti_enroll_cb enroll_cb, void *enroll_ctx) {
    init_debug(loop);

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    char time_str[32];
    ziti_fmt_time(time_str, sizeof(time_str), &start_time);

    ZITI_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting enrollment at (%s.%03d)",
             ziti_get_build_version(false), ziti_git_commit(), ziti_git_branch(),
             time_str, start_time.tv_usec / 1000);

    tls_context *tls = default_tls_context("", 0); // no default CAs
    PREPF(ziti, ziti_errorstr);
    PREPF(TLS, tls->api->strerror);

    NEWP(ecfg, enroll_cfg);
    ecfg->external_enroll_cb = enroll_cb;
    ecfg->external_enroll_ctx = enroll_ctx;
    ecfg->tls = tls;
    ecfg->tls->api->set_cert_verify(ecfg->tls, verify_controller_jwt, ecfg);
    ecfg->own_cert = opts->enroll_cert;
    ecfg->private_key = opts->enroll_key;

    TRY(ziti, load_jwt(opts->jwt, ecfg, &ecfg->zejh, &ecfg->zej));
    if (DEBUG <= ziti_debug_level) {
        dump_ziti_enrollment_jwt_header(ecfg->zejh, 0);
        dump_ziti_enrollment_jwt(ecfg->zej, 0);
    }
    TRY(ziti, check_cert_required(ecfg));

    NEWP(ctrl, ziti_controller);
    ecfg->ctrl = ctrl;
    ziti_ctrl_init(loop, ctrl, ecfg->zej->controller, ecfg->tls);

    NEWP(enroll_req, struct ziti_enroll_req);
    enroll_req->enroll_cb = enroll_cb;
    enroll_req->loop = loop;
    enroll_req->ecfg = ecfg;
    ziti_ctrl_get_well_known_certs(ctrl, well_known_certs_cb, enroll_req);

    CATCH(TLS) {
        TRY(ziti, ZITI_INVALID_CONFIG);
    }

    CATCH(ziti) {
        if (enroll_cb) {
            enroll_cb(NULL, ERR(ziti), "enroll failed", enroll_ctx);
        }
    }

    return ERR(ziti);
}

static void well_known_certs_cb(char *base64_encoded_pkcs7, ziti_error *err, void *req) {
    ZITI_LOG(DEBUG, "base64_encoded_pkcs7 is: %s", base64_encoded_pkcs7);

    int ziti_err;
    struct ziti_enroll_req *enroll_req = req;
    if ((NULL == base64_encoded_pkcs7) || (NULL != err)) {
        ZITI_LOG(DEBUG, "err->message is: %s", err->message);
        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, ZITI_JWT_VERIFICATION_FAILED, err->code, enroll_req->external_enroll_ctx);
        }
        return;
    }

    PREPF(TLS, enroll_req->ecfg->tls->api->strerror);
    tls_cert chain = NULL;
    ziti_err = ZITI_PKCS7_ASN1_PARSING_FAILED;
    TRY(TLS, enroll_req->ecfg->tls->api->parse_pkcs7_certs(
            &chain, base64_encoded_pkcs7, strlen(base64_encoded_pkcs7)));

    char *ca = NULL;
    size_t total_pem_len = 0;

    ziti_err = ZITI_INVALID_CONFIG;
    TRY(TLS, enroll_req->ecfg->tls->api->write_cert_to_pem(chain, 1, &ca, &total_pem_len));

    ZITI_LOG(DEBUG, "CA PEM len = %zd", total_pem_len);
    ZITI_LOG(TRACE, "CA PEM:\n%s", ca);

    tls_context *tls = default_tls_context(ca, (strlen(ca) + 1));

    if (strcmp("ott", enroll_req->ecfg->zej->method) == 0) {
        size_t len;
        if (enroll_req->ecfg->private_key == NULL) {
            ziti_err = ZITI_KEY_GENERATION_FAILED;
            TRY(TLS, tls->api->generate_key(&enroll_req->ecfg->pk));
            TRY(TLS, tls->api->write_key_to_pem(enroll_req->ecfg->pk, &enroll_req->ecfg->private_key, &len));
        }
        else {
            ziti_err = ZITI_KEY_LOAD_FAILED;
            TRY(TLS, tls->api->load_key(&enroll_req->ecfg->pk, enroll_req->ecfg->private_key,
                                        strlen(enroll_req->ecfg->private_key) + 1));
        }

        ziti_err = ZITI_CSR_GENERATION_FAILED;
        TRY(TLS, tls->api->generate_csr_to_pem(enroll_req->ecfg->pk, &enroll_req->ecfg->csr_pem, &len,
                                               "C", "US",
                                               "ST", "NY",
                                               "O", "OpenZiti",
                                               "DC", enroll_req->ecfg->zej->controller,
                                               "CN", enroll_req->ecfg->zej->subject,
                                               NULL));
    }
    else if (strcmp("ottca", enroll_req->ecfg->zej->method) == 0 || strcmp("ca", enroll_req->ecfg->zej->method) == 0) {
        ziti_err = ZITI_KEY_LOAD_FAILED;
        TRY(TLS, tls->api->set_own_cert(tls->ctx,
                                        enroll_req->ecfg->own_cert, strlen(enroll_req->ecfg->own_cert),
                                        enroll_req->ecfg->private_key, strlen(enroll_req->ecfg->private_key)));
    }

    enroll_req->ecfg->CA = ca;

    NEWP(enroll_req2, struct ziti_enroll_req);
    enroll_req2->enroll_cb = enroll_req->ecfg->external_enroll_cb;
    enroll_req2->external_enroll_ctx = enroll_req->ecfg->external_enroll_ctx;
    enroll_req2->loop = enroll_req->loop;
    enroll_req2->controller = calloc(1, sizeof(ziti_controller));
    ziti_ctrl_init(enroll_req2->loop, enroll_req2->controller, enroll_req->ecfg->zej->controller, tls);
    enroll_req2->ecfg = enroll_req->ecfg;

    ziti_ctrl_enroll(enroll_req2->controller, enroll_req->ecfg->zej->method, enroll_req->ecfg->zej->token,
                     enroll_req->ecfg->csr_pem, enroll_cb, enroll_req2);

    ziti_err = 0;
    CATCH(TLS) {
        if (enroll_req->enroll_cb) {
            static char err[1024];
            snprintf(err, sizeof(err), "%s[%d]: %s", ziti_errorstr(ziti_err), ziti_err, tls->api->strerror(ERR(TLS)));
            enroll_req->enroll_cb(NULL, ziti_err, err, enroll_req->external_enroll_ctx);
        }
    }
}

static void enroll_cb(ziti_enrollment_resp *er, ziti_error *err, void *enroll_ctx) {
    struct ziti_enroll_req *enroll_req = enroll_ctx;
    ziti_controller *ctrl = enroll_req->controller;

    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to enroll with controller: %s:%s %s (%s)",
                 ctrl->client.host, ctrl->client.port, err->code, err->message);

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, ZITI_JWT_INVALID, err->code, enroll_req->external_enroll_ctx);
        }

        free_ziti_error(err);
    }
    else {
        ZITI_LOG(DEBUG, "successfully enrolled with controller %s:%s",
                 ctrl->client.host, ctrl->client.port);

        ziti_config cfg;
        cfg.controller_url = strdup(enroll_req->ecfg->zej->controller);
        cfg.id.ca = strdup(enroll_req->ecfg->CA);
        cfg.id.key = strdup(enroll_req->ecfg->private_key);
        cfg.id.cert = er->cert ? strdup(er->cert) : strdup(enroll_req->ecfg->own_cert);

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(&cfg, ZITI_OK, NULL, enroll_req->external_enroll_ctx);
        }

        free_ziti_config(&cfg);
    }

    FREE(enroll_req);
}
