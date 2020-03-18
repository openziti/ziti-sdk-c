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

#include <nf/ziti.h>
#include <uv.h>
#include "utils.h"
#include "zt_internal.h"
#include "ziti_enroll.h"
#include <http_parser.h>


#include <mbedtls/ssl.h>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>
#include "mbedtls/md.h"
#include <utils.h>

#define MJSON_API_ONLY
#include <mjson.h>

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


struct nf_init_req {
    nf_context nf;
    int init_status;
    nf_init_cb init_cb;
    void* init_ctx;
};

struct nf_enroll_req {
    nf_enroll_cb enroll_cb;
    struct nf_ctx * enroll_ctx;
    enroll_cfg *ecfg;
};

int code_to_error(const char *code);
static void version_cb(ctrl_version* v, ziti_error* err, void* ctx);
static void session_cb(ziti_session *session, ziti_error *err, void *ctx);
static void well_known_certs_cb(char *cert, ziti_error *err, void *req);
static void enroll_cb(char *cert, ziti_error *err, void *ctx);

#define CONN_STATES(XX) \
XX(Initial)\
    XX(Connecting)\
    XX(Connected)\
    XX(Binding)\
    XX(Bound)\
    XX(Accepting) \
    XX(Closed)

static const char* strstate(enum conn_state st) {
#define state_case(s) case s: return #s;

    switch (st) {

        CONN_STATES(state_case)

        default: return "<unknown>";
    }
#undef state_case
}

static size_t parse_ref(const char *val, const char **res) {
    size_t len = 0;
    *res = NULL;
    if (val != NULL) {
        if (strncmp("file:", val, 5) == 0) {
            // load file
            *res = val + strlen("file://");
            len = strlen(*res) + 1;
        }
        else if (strncmp("pem:", val, 4) == 0) {
            // load inline PEM
            *res = val + 4;
            len = strlen(val + 4) + 1;
        }
    }
    return len;
}

static int parse_getopt(const char *q, const char *opt, char *out, size_t maxout) {
    int optlen = strlen(opt);
    do {
        // found it
        if (strncasecmp(q, opt, optlen) == 0 && (q[optlen] == '=' || q[optlen] == 0)) {
            const char *val = q + optlen + 1;
            char *end = strchr(val, '&');
            int vlen = (int)(end == NULL ? strlen(val) : end - val);
            snprintf(out, maxout, "%*.*s", vlen, vlen, val);
            return ZITI_OK;

        }
        else { // skip to next '&'
            q = strchr(q, '&');
            if (q == NULL) {
                break;
            }
            q += 1;
        }
    } while (q != NULL);
    out[0] = '\0';
    return ZITI_INVALID_CONFIG;
}

static void async_connects(uv_async_t *ar) {
    nf_context nf = ar->data;
    ziti_process_connect_reqs(nf);
}

int load_tls(nf_config *cfg, tls_context **ctx) {
     PREP(ziti);

    // load ca from nf config if present
    const char *ca, *cert;
    size_t ca_len = parse_ref(cfg->ca, &ca);
    size_t cert_len = parse_ref(cfg->cert, &cert);
    tls_context *tls = default_tls_context(ca, ca_len);

    if (strncmp(cfg->key, "pkcs11://", strlen("pkcs11://")) == 0) {
        char path[MAXPATHLEN] = {0};
        char pin[32] = {0};
        char slot[32] = {0};
        char id[32] = {0};

        char *p = cfg->key + strlen("pkcs11://");
        char *endp = strchr(p, '?');
        char *q = endp + 1;
        if (endp == NULL) {
            TRY(ziti, ("invalid pkcs11 key specification", ZITI_INVALID_CONFIG));
        }
        sprintf(path, "%*.*s", (int)(endp - p), (int)(endp - p), p);

        TRY(ziti, parse_getopt(q, "pin", pin, sizeof(pin)));
        TRY(ziti, parse_getopt(q, "slot", slot, sizeof(slot)));
        TRY(ziti, parse_getopt(q, "id", id, sizeof(id)));

        tls->api->set_own_cert_pkcs11(tls->ctx, cert, cert_len, path, pin, slot, id);
    } else {
        const char *key;
        size_t key_len = parse_ref(cfg->key, &key);
        tls->api->set_own_cert(tls->ctx, cert, cert_len, key, key_len);
    }

     CATCH(ziti) {
        return ERR(ziti);
    }

    *ctx = tls;
    return ZITI_OK;
}

int NF_enroll(const char* jwt_file, uv_loop_t* loop, nf_enroll_cb external_enroll_cb) {
    init_debug();

    int ret;
    struct enroll_cfg_s *ecfg = NULL;
    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    struct tm *start_tm = gmtime((const time_t)&start_time.tv_sec);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%FT%T", start_tm);

    ZITI_LOG(INFO, "ZitiSDK version %s @%s(%s) starting at (%s.%03d)",
            ziti_get_version(false), ziti_git_commit(), ziti_git_branch(),
            time_str, start_time.tv_usec/1000);

    PREP(ziti);
    
    nf_config *cfg = NULL;
    tls_context *tls = NULL;

    ecfg = calloc(1, sizeof(enroll_cfg));
    ecfg->external_enroll_cb = external_enroll_cb;

    TRY(ziti, load_jwt(jwt_file, &ecfg->zejh, &ecfg->zej));
    if (DEBUG <= ziti_debug_level) {
        dump_ziti_enrollment_jwt_header(ecfg->zejh, 0);
        dump_ziti_enrollment_jwt(ecfg->zej, 0);
    }

    // JWT validation start
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    uint32_t flags;
    const char *pers = "ziti-sdk-c";

    // Initialize the RNG and the session data
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ctr_drbg_seed returned -0x%04x", -ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    struct http_parser_url controller_url;
    http_parser_url_init(&controller_url);
    http_parser_parse_url(ecfg->zej->controller, strlen(ecfg->zej->controller), 0, &controller_url);
    char host[128];
    char port[16];
    int hostlen = controller_url.field_data[UF_HOST].len;
    int hostoffset = controller_url.field_data[UF_HOST].off;
    snprintf(host, sizeof(host), "%*.*s", hostlen, hostlen, ecfg->zej->controller + hostoffset);
    sprintf(port, "%d", controller_url.port);

    // Start the connection
    ZITI_LOG(DEBUG, "Connecting to tcp/%s/%s...", host, port);
    if( ( ret = mbedtls_net_connect( &server_fd, host, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_net_connect returned %d", ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ssl_config_defaults returned %d", ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    // mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ssl_setup returned %d", ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, host ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ssl_set_hostname returned %d", ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    // Handshake
    ZITI_LOG(DEBUG, "Performing the SSL/TLS handshake...");
    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 ) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            ZITI_LOG(ERROR, "mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            return ZITI_KEY_GENERATION_FAILED;
        }
    }

    // Verify the server certificate
    ZITI_LOG(DEBUG, "Verifying peer X.509 certificate...");
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 ) {
        char vrfy_buf[512];
        ZITI_LOG(ERROR, "X.509 certificate failed verification");
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
        ZITI_LOG(ERROR, "%s", vrfy_buf);
        return ZITI_KEY_GENERATION_FAILED;
    }
    else {
        ZITI_LOG(DEBUG, "X.509 certificate is OK");
    }

    const mbedtls_x509_crt *peerCert = mbedtls_ssl_get_peer_cert( &ssl );

    size_t olen;
    mbedtls_base64_encode( NULL, 0, &olen, peerCert->raw.p, peerCert->raw.len );  // determine size of buffer we need to allocate
    char *peerCertString = calloc(1, olen + 1);
    mbedtls_base64_encode( peerCertString, olen, &olen, peerCert->raw.p, peerCert->raw.len );


    if (strcmp(ecfg->zejh->alg, "RS256") == 0) {

        // TODO... perform the necessary mbedtls_pk_verify() magic here...

    }
    else /* default: */
    {
        ZITI_LOG(ERROR, "JWT signing algorithm '%s' is not supported", ecfg->zejh->alg);
        return ZITI_JWT_SIGNING_ALG_UNSUPPORTED;
    }






    TRY(ziti, gen_key(&ecfg->pk_context));

    ecfg->PrivateKey = calloc(1, 16000);
    if( ( ret = mbedtls_pk_write_key_pem( &ecfg->pk_context, ecfg->PrivateKey, 16000 ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_pk_write_key_pem returned -0x%04x", -ret);
        return ZITI_KEY_GENERATION_FAILED;
    }

    gen_csr(ecfg);

    if (strcmp(ecfg->zej->method, "ott") == 0)
    { 
        // Set up an empty tls context, and here's the important part... also turn off SSL verification.
        // Otherwise we'll get an SSL handshake error.
        //
        // We'll be doing an "insecure" call to the controller to fetch its well-known certs.
        // We'll use the received CA chain later, during the call to do enrollment.
        tls_context *tls = default_tls_context(NULL, 0);
        mbedtls_ssl_conf_authmode( tls->ctx, MBEDTLS_SSL_VERIFY_NONE ); // <-- a.k.a. "insecure"

        NEWP(fetch_cert_ctx, struct nf_ctx);
        fetch_cert_ctx->tlsCtx = tls;
        fetch_cert_ctx->loop = loop;
        fetch_cert_ctx->ziti_timeout = NF_DEFAULT_TIMEOUT;
        LIST_INIT(&fetch_cert_ctx->connect_requests);

        uv_async_init(loop, &fetch_cert_ctx->connect_async, async_connects);
        uv_unref((uv_handle_t *) &fetch_cert_ctx->connect_async);

        ziti_ctrl_init(loop, &fetch_cert_ctx->controller, ecfg->zej->controller, tls);

        NEWP(enroll_req, struct nf_enroll_req);
        enroll_req->enroll_cb = external_enroll_cb;
        enroll_req->enroll_ctx = fetch_cert_ctx;
        enroll_req->ecfg = ecfg;

        ziti_ctrl_get_well_known_certs(&fetch_cert_ctx->controller, ecfg, well_known_certs_cb, enroll_req);
    } 
    else if (strcmp(ecfg->zej->method, "ottca") == 0)
    {
        //TODO
        ZITI_LOG(ERROR, "enrollment method '%s' is not supported", ecfg->zej->method);
        return ZITI_ENROLLMENT_METHOD_UNSUPPORTED;
    }
    else if (strcmp(ecfg->zej->method, "ca") == 0)
    {
        //TODO
        ZITI_LOG(ERROR, "enrollment method '%s' is not supported", ecfg->zej->method);
        return ZITI_ENROLLMENT_METHOD_UNSUPPORTED;
    }
    else /* default: */
    {
        ZITI_LOG(ERROR, "enrollment method '%s' is not supported", ecfg->zej->method);
        return ZITI_ENROLLMENT_METHOD_UNSUPPORTED;
    }

    CATCH(ziti);

    return ERR(ziti);
}

int NF_init(const char* config, uv_loop_t* loop, nf_init_cb init_cb, void* init_ctx) {
    init_debug();

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    struct tm *start_tm = gmtime(&start_time.tv_sec);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%FT%T", start_tm);

    ZITI_LOG(INFO, "ZitiSDK version %s @%s(%s) starting at (%s.%03d)",
            ziti_get_version(false), ziti_git_commit(), ziti_git_branch(),
            time_str, start_time.tv_usec/1000);

    PREP(ziti);
    nf_config *cfg = NULL;
    tls_context *tls = NULL;

    TRY(ziti, load_config(config, &cfg));
    TRY(ziti, load_tls(cfg, &tls));
    TRY(ziti, NF_init_with_tls(cfg->controller_url, tls, loop, init_cb, init_ctx));

    CATCH(ziti);

    free_nf_config(cfg);

    return ERR(ziti);
}

int
NF_init_with_tls(const char *ctrl_url, tls_context *tls_context, uv_loop_t *loop, nf_init_cb init_cb, void *init_ctx) {
    init_debug();
    ZITI_LOG(INFO, "ZitiSDK version %s @%s(%s)", ziti_get_version(false), ziti_git_commit(), ziti_git_branch());

    if (tls_context == NULL) {
        ZITI_LOG(ERROR, "tls context is required");
        return ZITI_INVALID_CONFIG;
    }

    NEWP(ctx, struct nf_ctx);
    ctx->tlsCtx = tls_context;
    ctx->loop = loop;
    ctx->ziti_timeout = NF_DEFAULT_TIMEOUT;
    LIST_INIT(&ctx->connect_requests);

    uv_async_init(loop, &ctx->connect_async, async_connects);
    uv_unref((uv_handle_t *) &ctx->connect_async);

    ziti_ctrl_init(loop, &ctx->controller, ctrl_url, tls_context);
    ziti_ctrl_get_version(&ctx->controller, version_cb, &ctx->controller);

    uv_timer_init(loop, &ctx->session_timer);
    uv_unref((uv_handle_t *) &ctx->session_timer);
    ctx->session_timer.data = ctx;

    NEWP(init_req, struct nf_init_req);
    init_req->init_cb = init_cb;
    init_req->init_ctx = init_ctx;
    init_req->nf = ctx;
    ziti_ctrl_login(&ctx->controller, session_cb, init_req);

    return ZITI_OK;
}

int NF_set_timeout(nf_context ctx, int timeout) {
    if (timeout > 0) {
        ctx->ziti_timeout = timeout;
    }
    else {
        ctx->ziti_timeout = NF_DEFAULT_TIMEOUT;
    }
    return ZITI_OK;
}

int NF_shutdown(nf_context ctx) {
    ZITI_LOG(INFO, "Ziti is shutting down");

    free_ziti_session(ctx->session);

    uv_timer_stop(&ctx->session_timer);
    ziti_ctrl_close(&ctx->controller);
    ziti_close_channels(ctx);

    ziti_ctrl_logout(&ctx->controller, NULL, NULL);

    return ZITI_OK;
}

int NF_free(nf_context *ctxp) {
    if ((*ctxp)->tlsCtx != NULL) {
        (*ctxp)->tlsCtx->api->free_ctx((*ctxp)->tlsCtx);
    }
    free(*ctxp);
    *ctxp = NULL;

    ZITI_LOG(INFO, "shutdown is complete\n");
    return ZITI_OK;
}

void NF_dump(nf_context ctx) {
    printf("\n=================\nSession:\n");
    dump_ziti_session(ctx->session, 0);

    printf("\n=================\nServices:\n");
    ziti_service *zs;
    LIST_FOREACH(zs, &ctx->services, _next) {
        dump_ziti_service(zs, 0);
    }

    printf("\n==================\nNet Sessions:\n");
    ziti_net_session *it;
    LIST_FOREACH(it, &ctx->net_sessions, _next) {
        dump_ziti_net_session(it, 0);
    }

    printf("\n==================\nChannels:\n");
    ziti_channel_t *ch;
    LIST_FOREACH(ch, &ctx->channels, next) {
        printf("ch[%d](%s)\n", ch->id, ch->ingress);
        nf_connection conn;
        LIST_FOREACH(conn, &ch->connections, next) {
            printf("\tconn[%d]: state[%s] service[%s] session[%s]\n", conn->conn_id, strstate(conn->state),
                    "TODO", "TODO"); // TODO
        }
    }
}

int NF_conn_init(nf_context nf_ctx, nf_connection *conn, void *data) {
    struct nf_ctx *ctx = nf_ctx;
    NEWP(c, struct nf_conn);
    c->nf_ctx = nf_ctx;
    c->data = data;
    c->channel = NULL;
    c->state = Initial;
    c->timeout = ctx->ziti_timeout;
    c->edge_msg_seq = 1;
    c->conn_id = nf_ctx->conn_seq++;

    *conn = c;
    return ZITI_OK;
}

void *NF_conn_data(nf_connection conn) {
    return conn->data;
}

int NF_dial(nf_connection conn, const char *service, nf_conn_cb conn_cb, nf_data_cb data_cb) {
    return ziti_dial(conn, service, conn_cb, data_cb);
}

int NF_close(nf_connection *conn) {
    struct nf_conn *c = *conn;

    ziti_disconnect(c);

    *conn = NULL;

    return ZITI_OK;
}

int NF_write(nf_connection conn, uint8_t* data, size_t length, nf_write_cb write_cb, void* write_ctx) {

    NEWP(req, struct nf_write_req);
    req->conn = conn;
    req->buf = data;
    req->len = length;
    req->cb = write_cb;
    req->ctx = write_ctx;

    return ziti_write(req);
}

struct service_req_s {
    struct nf_ctx *nf;
    char *service;
    nf_service_cb cb;
    void *cb_ctx;
};

static void service_cb (ziti_service *s, ziti_error *err, void *ctx) {
    struct service_req_s *req = ctx;
    int rc = ZITI_SERVICE_UNAVAILABLE;

    if (s != NULL) {
        for (int i = 0; s->permissions[i] != NULL; i++) {
            if (strcmp(s->permissions[i], "Dial") == 0) {
                 s->perm_flags |= ZITI_CAN_DIAL;
            }
            if (strcmp(s->permissions[i], "Bind") == 0) {
                s->perm_flags |= ZITI_CAN_BIND;
            }
        }
        LIST_INSERT_HEAD(&req->nf->services, s, _next);
        rc = ZITI_OK;
    }

    req->cb(req->nf, req->service, rc, s ? s->perm_flags : 0, req->cb_ctx);
    FREE(req->service);
    free(req);
}

int NF_service_available(nf_context nf, const char *service, nf_service_cb cb, void *ctx) {
    ziti_service *s;
    LIST_FOREACH (s, &nf->services, _next) {
        if (strcmp(service, s->name) == 0) {
            cb(nf, service, ZITI_OK, s->perm_flags, ctx);
        }
    }

    NEWP(req, struct service_req_s);
    req->nf = nf;
    req->service = strdup(service);
    req->cb = cb;
    req->cb_ctx = ctx;

    ziti_ctrl_get_service(&nf->controller, service, service_cb, req);
    return ZITI_OK;
}

extern int NF_listen(nf_connection serv_conn, const char *service, nf_listen_cb lcb, nf_client_cb cb) {
    return ziti_bind(serv_conn, service, lcb, cb);
}

extern int NF_accept(nf_connection clt, nf_conn_cb cb, nf_data_cb data_cb) {
    return ziti_accept(clt, cb, data_cb);
}

static void session_refresh(uv_timer_t *t) {
    nf_context nf = t->data;
    struct nf_init_req *req = calloc(1, sizeof(struct nf_init_req));
    req->nf = nf;

    ZITI_LOG(DEBUG, "refreshing API session");
    ziti_ctrl_current_api_session(&nf->controller, session_cb, req);
}

static void session_cb(ziti_session *session, ziti_error *err, void *ctx) {
    struct nf_init_req *init_req = ctx;
    nf_context nf = init_req->nf;

    int errCode = err ? code_to_error(err->code) : ZITI_OK;

    if (session) {
        ZITI_LOG(DEBUG, "%s successfully => api_session[%s]", nf->session ? "refreshed" : "logged in", session->id);
        free_ziti_session(nf->session);
        nf->session = session;

        if (session->expires) {
            uv_timeval64_t now;
            uv_gettimeofday(&now);
            ZITI_LOG(DEBUG, "ziti API session expires in %ld seconds", (long)(session->expires->tv_sec - now.tv_sec));
            long delay = (session->expires->tv_sec - now.tv_sec) * 3 / 4;
            uv_timer_start(&nf->session_timer, session_refresh, delay * 1000, 0);
        }
    } else {
        ZITI_LOG(ERROR, "failed to login: %s[%d](%s)", err->code, errCode, err->message);
    }

    if (init_req->init_cb) {
        init_req->init_cb(nf, errCode, init_req->init_ctx);
    }

    free_ziti_error(err);
    FREE(init_req);
}

static void version_cb(ctrl_version *v, ziti_error *err, void *ctx) {
    ziti_controller *ctrl = ctx;
    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to get controller version from %s:%s %s(%s)",
                 ctrl->client.host, ctrl->client.port, err->code, err->message);
        free_ziti_error(err);
    }
    else {
        ZITI_LOG(INFO, "connected to controller %s:%s version %s(%s %s)",
                 ctrl->client.host, ctrl->client.port, v->version, v->revision, v->build_date);
        free_ctrl_version(v);
    }
}

#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define OID_PKCS7_DATA OID_PKCS7 "\x02"
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x01"

static void well_known_certs_cb(char *base64_encoded_pkcs7, ziti_error *err, void *req) {
    struct nf_enroll_req *enroll_req = req;
    size_t der_len;
    unsigned char *p;
    unsigned char *end;
    mbedtls_x509_crt *cp;
    mbedtls_x509_crt certs={0};
    unsigned char *cert_buf;

    int rc = mbedtls_base64_decode( NULL, 0, &der_len, base64_encoded_pkcs7, strlen(base64_encoded_pkcs7)); // determine necessary buffer size
    char *base64_decoded_pkcs7 = calloc(1, der_len + 1);
    rc = mbedtls_base64_decode( base64_decoded_pkcs7, der_len, &der_len, base64_encoded_pkcs7, strlen(base64_encoded_pkcs7));

    unsigned char *der = (unsigned char*)base64_decoded_pkcs7;

    p = der;
    end = der + der_len;
    size_t len;
    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID);

    mbedtls_asn1_buf oid;
    oid.p = p;
    oid.len = len;
    if (!MBEDTLS_OID_CMP(OID_PKCS7_SIGNED_DATA, &oid)) {
        ZITI_LOG(ERROR, "invalid pkcs7 signed data");
        return;
    }
    p += len;

    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);

    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

    int ver;
    mbedtls_asn1_get_int(&p, end, &ver);

    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID);
    oid.p = p;
    oid.len = len;
    if (!MBEDTLS_OID_CMP(OID_PKCS7_DATA, &oid)) {
        ZITI_LOG(ERROR, "invalid pkcs7 data");
        return;
    }
    p += len;

    mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);

    cert_buf = p;

    do {
        size_t cert_len;
        unsigned char *cbp = cert_buf;
        rc = mbedtls_asn1_get_tag(&cbp, end, &cert_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (rc != 0) break;
        cert_len += (cbp - cert_buf);
        rc = mbedtls_x509_crt_parse(&certs, cert_buf, cert_len);
        cert_buf += cert_len;
    } while (rc == 0);

    cp = &certs;

    do {

        size_t olen;
        mbedtls_base64_encode( NULL, 0, &olen, cp->raw.p, cp->raw.len );  // determine size of buffer we need to allocate
        enroll_req->ecfg->CA = calloc(1, olen + 1);
        mbedtls_base64_encode( enroll_req->ecfg->CA, olen, &olen, cp->raw.p, cp->raw.len );

        char dn[1024];
        int dn_len = mbedtls_x509_dn_gets(dn, sizeof(dn), &cp->subject);
        ZITI_LOG(DEBUG, "subj: %.*s", dn_len, dn);
        dn_len = mbedtls_x509_dn_gets(dn, sizeof(dn), &cp->issuer);
        ZITI_LOG(DEBUG, "issr: %.*s", dn_len, dn);
        cp = cp->next;

    } while(cp != NULL);

    tls_context *tls = NULL;

    char cbeg[] = "-----BEGIN CERTIFICATE-----\n";
    char cend[] = "\n-----END CERTIFICATE-----";

    char *ca = calloc(1, (strlen(cbeg) + strlen(enroll_req->ecfg->CA) + strlen(cend) + 1));

    strcpy(ca, cbeg);
    strcat(ca, enroll_req->ecfg->CA);
    strcat(ca, cend);

    tls = default_tls_context(ca, (strlen(ca) + 2));
    ZITI_LOG(DEBUG, "ca:\n%s", ca);
    ZITI_LOG(DEBUG, "ca_len: %d", strlen(ca));

    NEWP(enroll_ctx, struct nf_ctx);
    enroll_ctx->tlsCtx = tls;
    enroll_ctx->loop = enroll_req->enroll_ctx->loop;
    enroll_ctx->ziti_timeout = NF_DEFAULT_TIMEOUT;
    LIST_INIT(&enroll_ctx->connect_requests);

    ziti_ctrl_init(enroll_ctx->loop, &enroll_ctx->controller, enroll_req->ecfg->zej->controller, tls);

    NEWP(enroll_req2, struct nf_enroll_req);
    enroll_req2->enroll_cb = enroll_req->ecfg->external_enroll_cb;
    enroll_req2->enroll_ctx = enroll_ctx;
    enroll_req2->ecfg = enroll_req->ecfg;

    ziti_ctrl_enroll(&enroll_ctx->controller, enroll_req->ecfg, enroll_cb, enroll_req);
}


static void enroll_cb(char *cert, ziti_error *err, void *enroll_ctx) {
    struct nf_enroll_req *enroll_req = enroll_ctx;
    struct nf_ctx *ctx = enroll_req->enroll_ctx;

    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to enroll with controller: %s:%s %s(%s)",
                 ctx->controller.client.host, ctx->controller.client.port, err->code, err->message);

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, 0, err->code);
        }

        free_ziti_error(err);
    }
    else {
        ZITI_LOG(DEBUG, "successfully enrolled with controller %s:%s",
                 ctx->controller.client.host, ctx->controller.client.port);

        char *content = NULL;
        size_t len = mjson_printf(
            &mjson_print_dynamic_buf, 
            &content,
            "{\n\t\"ztAPI\": %Q, \n\t\"id\": {\n\t\t\"key\": \"pem:%s\", \n\t\t\"cert\": \"pem:%s\", \n\t\t\"ca\": \"pem:pem:-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\"\n\t}\n}",
            enroll_req->ecfg->zej->controller,
            enroll_req->ecfg->PrivateKey,
            cert,
            enroll_req->ecfg->CA
        );

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(content, strlen(content), ZITI_OK);
        }

        FREE(content);
    }

    FREE(enroll_req);
}
