// Copyright (c) 2023.  NetFoundry Inc.
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

static void well_known_certs_cb(char *base64_encoded_pkcs7, const ziti_error *err, void *req);

static void enroll_cb(ziti_enrollment_resp *er, const ziti_error *err, void *ctx);

int verify_controller_jwt(tls_cert cert, void *ctx) {
    ZITI_LOG(DEBUG, "verifying JWT signature");

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

    int rc = ecfg->tls->verify_signature(cert, md, (char *) ecfg->jwt_signing_input,
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
    if (ecfg->zej->method == ziti_enrollment_methods.ca || ecfg->zej->method == ziti_enrollment_methods.ottca) {
        if (ecfg->own_cert == NULL || ecfg->private_key == 0) {
            return ZITI_ENROLLMENT_CERTIFICATE_REQUIRED;
        }
    }
    return ZITI_OK;
}

int ziti_enroll(ziti_enroll_opts *opts, uv_loop_t *loop, ziti_enroll_cb enroll_cb, void *enroll_ctx) {
    ziti_log_init(loop, ZITI_LOG_DEFAULT_LEVEL, NULL);

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    char time_str[32];
    ziti_fmt_time(time_str, sizeof(time_str), &start_time);

    ZITI_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting enrollment at (%s.%03d)",
             ziti_get_build_version(false), ziti_git_commit(), ziti_git_branch(),
             time_str, start_time.tv_usec / 1000);

    tls_context *tls = default_tls_context("", 0); // no default CAs
    PREPF(ziti, ziti_errorstr);

    NEWP(ecfg, enroll_cfg);
    ecfg->external_enroll_cb = enroll_cb;
    ecfg->external_enroll_ctx = enroll_ctx;
    ecfg->tls = tls;
    ecfg->tls->set_cert_verify(ecfg->tls, verify_controller_jwt, ecfg);
    ecfg->own_cert = opts->enroll_cert;
    ecfg->private_key = opts->enroll_key;
    ecfg->name = opts->enroll_name;

    if (opts->jwt) {
        TRY(ziti, load_jwt(opts->jwt, ecfg, &ecfg->zejh, &ecfg->zej));
    } else {
        ecfg->raw_jwt = opts->jwt_content;
        TRY(ziti, load_jwt_content(ecfg, &ecfg->zejh, &ecfg->zej));
    }
    TRY(ziti, check_cert_required(ecfg));

    NEWP(ctrl, ziti_controller);
    ecfg->ctrl = ctrl;
    TRY(ziti, ziti_ctrl_init(loop, ctrl, ecfg->zej->controller, ecfg->tls));

    NEWP(enroll_req, struct ziti_enroll_req);
    enroll_req->enroll_cb = enroll_cb;
    enroll_req->external_enroll_ctx = enroll_ctx;
    enroll_req->loop = loop;
    enroll_req->ecfg = ecfg;
    ziti_ctrl_get_well_known_certs(ctrl, well_known_certs_cb, enroll_req);

    CATCH(ziti) {
        if (enroll_cb) {
            enroll_cb(NULL, ERR(ziti), "enroll failed", enroll_ctx);
        }
    }

    return ERR(ziti);
}

static void well_known_certs_cb(char *base64_encoded_pkcs7, const ziti_error *err, void *req) {
    PREPF(ziti, ziti_errorstr);

    int ziti_err;
    struct ziti_enroll_req *enroll_req = req;
    if ((NULL == base64_encoded_pkcs7) || (NULL != err)) {
        ZITI_LOG(DEBUG, "err->message is: %s", err->message);
        TRY(ziti, ZITI_JWT_VERIFICATION_FAILED);
    }

    ZITI_LOG(VERBOSE, "base64_encoded_pkcs7 is: %s", base64_encoded_pkcs7);
    PREPF(TLS, enroll_req->ecfg->tls->strerror);
    tls_cert chain = NULL;
    ziti_err = ZITI_PKCS7_ASN1_PARSING_FAILED;
    TRY(TLS, enroll_req->ecfg->tls->parse_pkcs7_certs(
            &chain, base64_encoded_pkcs7, strlen(base64_encoded_pkcs7)));

    char *ca = NULL;
    size_t total_pem_len = 0;

    ziti_err = ZITI_INVALID_CONFIG;
    TRY(TLS, enroll_req->ecfg->tls->write_cert_to_pem(chain, 1, &ca, &total_pem_len));

    ZITI_LOG(DEBUG, "CA PEM len = %zd", total_pem_len);
    ZITI_LOG(TRACE, "CA PEM:\n%s", ca);

    tls_context *tls = default_tls_context(ca, (strlen(ca) + 1));
    if (enroll_req->ecfg->private_key != NULL) {
        ziti_err = ZITI_KEY_LOAD_FAILED;
        if (load_key_internal(tls, &enroll_req->ecfg->pk, enroll_req->ecfg->private_key) != 0) {
            ZITI_LOG(WARN, "failed to load private key[%s]", enroll_req->ecfg->private_key);
            if (enroll_req->ecfg->zej->method == ziti_enrollment_methods.ott &&
                strncmp(enroll_req->ecfg->private_key, "pkcs11://", strlen("pkcs11://")) == 0) {
                ZITI_LOG(INFO, "attempting to generate pkcs11 key");
                TRY(TLS, gen_p11_key_internal(tls, &enroll_req->ecfg->pk, enroll_req->ecfg->private_key));
            }
        }
    }

    if (enroll_req->ecfg->zej->method == ziti_enrollment_methods.ott) {
        size_t len;
        if (enroll_req->ecfg->private_key == NULL) {
            ziti_err = ZITI_KEY_GENERATION_FAILED;
            TRY(TLS, tls->generate_key(&enroll_req->ecfg->pk));
            TRY(TLS,
                enroll_req->ecfg->pk->to_pem(enroll_req->ecfg->pk, (char **) &enroll_req->ecfg->private_key, &len));
        }
        else {
        }

        ziti_err = ZITI_CSR_GENERATION_FAILED;
        TRY(TLS, tls->generate_csr_to_pem(enroll_req->ecfg->pk, &enroll_req->ecfg->csr_pem, &len,
                                               "C", "US",
                                               "ST", "NY",
                                               "O", "OpenZiti",
                                               "DC", enroll_req->ecfg->zej->controller,
                                               "CN", enroll_req->ecfg->zej->subject,
                                               NULL));
    }
    else if (enroll_req->ecfg->zej->method == ziti_enrollment_methods.ottca ||
             enroll_req->ecfg->zej->method == ziti_enrollment_methods.ca) {
        ziti_err = ZITI_KEY_LOAD_FAILED;
        TRY(TLS, tls->set_own_key(tls, enroll_req->ecfg->pk));
        tls_cert cert;
        TRY(TLS, tls->load_cert(&cert, enroll_req->ecfg->own_cert, strlen(enroll_req->ecfg->own_cert)));
        TRY(TLS, tls->set_own_cert(tls, cert));
    }

    enroll_req->ecfg->CA = ca;

    NEWP(enroll_req2, struct ziti_enroll_req);
    enroll_req2->enroll_cb = enroll_req->ecfg->external_enroll_cb;
    enroll_req2->external_enroll_ctx = enroll_req->ecfg->external_enroll_ctx;
    enroll_req2->loop = enroll_req->loop;
    enroll_req2->controller = calloc(1, sizeof(ziti_controller));
    TRY(ziti, ziti_ctrl_init(enroll_req2->loop, enroll_req2->controller, enroll_req->ecfg->zej->controller, tls));
    enroll_req2->ecfg = enroll_req->ecfg;

    ziti_ctrl_enroll(enroll_req2->controller, enroll_req->ecfg->zej->method, enroll_req->ecfg->zej->token,
                     enroll_req->ecfg->csr_pem, enroll_req->ecfg->name, enroll_cb, enroll_req2);

    ziti_err = 0;
    CATCH(TLS) {
        if (enroll_req->enroll_cb) {
            static char err[1024];
            snprintf(err, sizeof(err), "%s[%d]: %s", ziti_errorstr(ziti_err), ziti_err, tls->strerror(ERR(TLS)));
            enroll_req->enroll_cb(NULL, ziti_err, err, enroll_req->external_enroll_ctx);
        }
    }

    CATCH(ziti) {
        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, ERR(ziti), err ? err->code : "enroll failed", enroll_req->ecfg->external_enroll_ctx);
        }
    }
}

static void enroll_cb(ziti_enrollment_resp *er, const ziti_error *err, void *enroll_ctx) {
    struct ziti_enroll_req *enroll_req = enroll_ctx;
    ziti_controller *ctrl = enroll_req->controller;

    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to enroll with controller: %s %s (%s)",
                 ctrl->url, err->code, err->message);

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, ZITI_JWT_INVALID, err->code, enroll_req->external_enroll_ctx);
        }
    }
    else {
        ZITI_LOG(DEBUG, "successfully enrolled with controller %s", ctrl->url);

        ziti_config cfg = {0};
        cfg.controller_url = strdup(enroll_req->ecfg->zej->controller);
        cfg.id.ca = strdup(enroll_req->ecfg->CA);
        cfg.id.key = strdup(enroll_req->ecfg->private_key);

        tls_cert c = NULL;
        if (enroll_req->ecfg->tls->load_cert(&c, er->cert, strlen(er->cert)) == 0 &&
            enroll_req->ecfg->pk->store_certificate != NULL &&
            enroll_req->ecfg->pk->store_certificate(enroll_req->ecfg->pk, c) == 0) {
            ZITI_LOG(INFO, "stored certificate to PKCS#11 token");
        }
        else {
            cfg.id.cert = er->cert ? strdup(er->cert) : strdup(enroll_req->ecfg->own_cert);
        }

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(&cfg, ZITI_OK, NULL, enroll_req->external_enroll_ctx);
        }

        free_ziti_config(&cfg);
    }

    FREE(enroll_req);
}
