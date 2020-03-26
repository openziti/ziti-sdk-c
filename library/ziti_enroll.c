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


#define ZITI_MD_MAX_SIZE_256 32  /* longest known is SHA256 or less */
#define ZITI_MD_MAX_SIZE_512 64  /* longest known is SHA512 */

static void well_known_certs_cb(char *cert, ziti_error *err, void *req);
static void enroll_cb(char *cert, ziti_error *err, void *ctx);
int extract_well_known_certs(char *base64_encoded_pkcs7, void *req);

static void async_connects(uv_async_t *ar) {
    nf_context nf = ar->data;
    ziti_process_connect_reqs(nf);
}

int verify_rs256(struct enroll_cfg_s *ecfg, mbedtls_pk_context *ctx) {
    int ret;
    unsigned char hash[ZITI_MD_MAX_SIZE_256];
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(md_info, ecfg->jwt_signing_input, strlen(ecfg->jwt_signing_input), hash);
    ZITI_LOG(DEBUG, "ecfg->jwt_sig_len is: %d", ecfg->jwt_sig_len);
    if( ( ret = mbedtls_pk_verify( ctx, MBEDTLS_MD_SHA256, hash, 0, ecfg->jwt_sig, ecfg->jwt_sig_len ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_pk_verify returned -0x%x\n\n", -ret);
        return ZITI_JWT_VERIFICATION_FAILED;
    }
    return ZITI_OK;
}

typedef int32_t psa_status_t;
#define PSA_BITS_TO_BYTES(bits) (((bits) + 7) / 8)
#define PSA_BYTES_TO_BITS(bytes) ((bytes) * 8)

static int psa_ecdsa_verify( mbedtls_ecp_keypair *ecp,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length )
{
    int ret;
    mbedtls_mpi r, s;
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( signature_length != 2 * curve_bytes )
        return( ZITI_JWT_VERIFICATION_FAILED );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r,
                                              signature,
                                              curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &s,
                                              signature + curve_bytes,
                                              curve_bytes ) );

    ret = mbedtls_ecdsa_verify( &ecp->grp, hash, hash_length,
                                &ecp->Q, &r, &s );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    return( ret );
}

int verify_es256(struct enroll_cfg_s *ecfg, mbedtls_pk_context *ctx) {
    int ret;
    unsigned char hash[ZITI_MD_MAX_SIZE_256];
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(md_info, ecfg->jwt_signing_input, strlen(ecfg->jwt_signing_input), hash);
    ZITI_LOG(DEBUG, "ecfg->jwt_sig_len is: %d", ecfg->jwt_sig_len);
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( *ctx );
    if( ( ret = psa_ecdsa_verify( ecp, hash, ZITI_MD_MAX_SIZE_256, ecfg->jwt_sig, ecfg->jwt_sig_len) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_pk_verify returned -0x%x\n\n", -ret);
        return ZITI_JWT_VERIFICATION_FAILED;
    }
    return ZITI_OK;

}

int verify_es384(struct enroll_cfg_s *ecfg, mbedtls_pk_context *ctx) {
    int ret;
    unsigned char hash[ZITI_MD_MAX_SIZE_512];
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    mbedtls_md(md_info, ecfg->jwt_signing_input, strlen(ecfg->jwt_signing_input), hash);
    ZITI_LOG(DEBUG, "ecfg->jwt_sig_len is: %d", ecfg->jwt_sig_len);
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( *ctx );
    if( ( ret = psa_ecdsa_verify( ecp, hash, ZITI_MD_MAX_SIZE_512, ecfg->jwt_sig, ecfg->jwt_sig_len) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_pk_verify returned -0x%x\n\n", -ret);
        return ZITI_JWT_VERIFICATION_FAILED;
    }
    return ZITI_OK;
}

int verify_es512(struct enroll_cfg_s *ecfg, mbedtls_pk_context *ctx) {
    int ret;
    unsigned char hash[ZITI_MD_MAX_SIZE_512];
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    mbedtls_md(md_info, ecfg->jwt_signing_input, strlen(ecfg->jwt_signing_input), hash);
    ZITI_LOG(DEBUG, "ecfg->jwt_sig_len is: %d", ecfg->jwt_sig_len);
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( *ctx );
    if( ( ret = psa_ecdsa_verify( ecp, hash, ZITI_MD_MAX_SIZE_512, ecfg->jwt_sig, ecfg->jwt_sig_len) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_pk_verify returned -0x%x\n\n", -ret);
        return ZITI_JWT_VERIFICATION_FAILED;
    }
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
    
    ecfg = calloc(1, sizeof(enroll_cfg));
    ecfg->external_enroll_cb = external_enroll_cb;

    TRY(ziti, load_jwt(jwt_file, ecfg, &ecfg->zejh, &ecfg->zej));
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
        return ZITI_JWT_VERIFICATION_FAILED;
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
        return ZITI_JWT_VERIFICATION_FAILED;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ssl_config_defaults returned %d", ret);
        return ZITI_JWT_VERIFICATION_FAILED;
    }

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    // mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ssl_setup returned %d", ret);
        return ZITI_JWT_VERIFICATION_FAILED;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, host ) ) != 0 ) {
        ZITI_LOG(ERROR, "mbedtls_ssl_set_hostname returned %d", ret);
        return ZITI_JWT_VERIFICATION_FAILED;
    }

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    // Handshake
    ZITI_LOG(DEBUG, "Performing the SSL/TLS handshake...");
    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 ) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
            ZITI_LOG(ERROR, "mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            return ZITI_JWT_VERIFICATION_FAILED;
        }
    }

    // Verify the server certificate
    ZITI_LOG(DEBUG, "Verifying peer X.509 certificate...");
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 ) {
        char vrfy_buf[512];
        ZITI_LOG(ERROR, "X.509 certificate failed verification");
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
        ZITI_LOG(ERROR, "%s", vrfy_buf);
        return ZITI_JWT_VERIFICATION_FAILED;
    }
    else {
        ZITI_LOG(DEBUG, "X.509 certificate is OK");
    }

    const mbedtls_x509_crt *peerCert = mbedtls_ssl_get_peer_cert( &ssl );

    size_t olen;
    mbedtls_base64_encode( NULL, 0, &olen, peerCert->raw.p, peerCert->raw.len );  // determine size of buffer we need to allocate
    char *peerCertString = calloc(1, olen + 1);
    mbedtls_base64_encode( peerCertString, olen, &olen, peerCert->raw.p, peerCert->raw.len );
    ZITI_LOG(DEBUG, "peer X.509 certificate is: %s", peerCertString);

    unsigned char output_buf[16000];
    mbedtls_pk_write_pubkey_pem( &peerCert->pk, output_buf, 16000 );
    ZITI_LOG(DEBUG, "peer X.509 public key is: %s", output_buf);

    if (strcmp(ecfg->zejh->alg, "RS256") == 0) {

        if( ( ret = verify_rs256( ecfg, &peerCert->pk ) ) != 0 ) return ret;

    }
    else if (strcmp(ecfg->zejh->alg, "ES256") == 0) {

        if( ( ret = verify_es256( ecfg, &peerCert->pk ) ) != 0 ) return ret;

    }
    else if (strcmp(ecfg->zejh->alg, "ES384") == 0) {

        if( ( ret = verify_es384( ecfg, &peerCert->pk ) ) != 0 ) return ret;

    }
    else if (strcmp(ecfg->zejh->alg, "ES512") == 0) {

        if( ( ret = verify_es512( ecfg, &peerCert->pk ) ) != 0 ) return ret;

    }
    else /* default: */
    {
        ZITI_LOG(ERROR, "JWT signing algorithm '%s' is not supported", ecfg->zejh->alg);
        return ZITI_JWT_SIGNING_ALG_UNSUPPORTED;
    }

    ZITI_LOG(DEBUG, "JWT verification succeeded !");

    // JWT validation end




    TRY(ziti, gen_key(&ecfg->pk_context));

    ecfg->private_key = calloc(1, 16000);
    if( ( ret = mbedtls_pk_write_key_pem( &ecfg->pk_context, ecfg->private_key, 16000 ) ) != 0 ) {
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


#define OID_PKCS7 MBEDTLS_OID_PKCS "\x07"
#define OID_PKCS7_DATA OID_PKCS7 "\x02"
#define OID_PKCS7_SIGNED_DATA OID_PKCS7 "\x01"

static void well_known_certs_cb(char *base64_encoded_pkcs7, ziti_error *err, void *req) {
    ZITI_LOG(DEBUG, "base64_encoded_pkcs7 is: %s", base64_encoded_pkcs7);

    struct nf_enroll_req *enroll_req = req;
    int rc;

    if ( (NULL == base64_encoded_pkcs7) || (NULL != err)) {
        ZITI_LOG(DEBUG, "err->message is: %s", err->message);
        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, 0, err->code);
        }
        return;
    }

    if( ( rc = extract_well_known_certs( base64_encoded_pkcs7, req ) ) != 0 ) {
        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, ZITI_PKCS7_ASN1_PARSING_FAILED, "cannot extract well-known certs");
        }
        return;
    }

    struct wellknown_cert *wc;

    char *ca = NULL;
    char *pem_ptr = NULL;
    size_t total_pem_len = 0;

    char cbeg[] = "-----BEGIN CERTIFICATE-----\n";
    char cend[] = "\n-----END CERTIFICATE-----\n";

    LIST_FOREACH (wc, &enroll_req->ecfg->wk_certs, _next) {

        size_t pem_len =  (strlen(cbeg) + strlen(wc->cert) + strlen(cend));

        if (NULL == ca) {
            ca = calloc(1, pem_len + 1);
            pem_ptr = ca;
            total_pem_len = pem_len;

        } else {
            ca = realloc(ca, (total_pem_len + pem_len + 1));
            pem_ptr = ca + total_pem_len;
            total_pem_len += pem_len;
        }

        strcpy(pem_ptr, cbeg);
        strcat(pem_ptr, wc->cert);
        strcat(pem_ptr, cend);

        ZITI_LOG(DEBUG, "CA: \n%s\n", ca);

    }

    tls_context *tls = NULL;

    tls = default_tls_context(ca, (strlen(ca) + 1 ));
    
    ZITI_LOG(DEBUG, "CA: \n%s\n", ca);
    ZITI_LOG(DEBUG, "CA len: %d", strlen(ca));

    enroll_req->ecfg->CA = ca;

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
        ZITI_LOG(ERROR, "failed to enroll with controller: %s:%s %s (%s)",
                 ctx->controller.client.host, ctx->controller.client.port, err->code, err->message);

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(NULL, ZITI_JWT_INVALID, err->code);
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
            "{\n\t\"ztAPI\": %Q, \n\t\"id\": {\n\t\t\"key\": \"pem:%s\", \n\t\t\"cert\": \"pem:%s\", \n\t\t\"ca\": \"pem:-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\"\n\t}\n}",
            enroll_req->ecfg->zej->controller,
            enroll_req->ecfg->private_key,
            cert,
            enroll_req->ecfg->CA
        );

        if (enroll_req->enroll_cb) {
            enroll_req->enroll_cb(content, strlen(content), NULL);
        }

        FREE(content);
    }

    FREE(enroll_req);
}
