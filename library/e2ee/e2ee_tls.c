//
//

#include <tlsuv/tls_engine.h>
#include "buffer.h"
#include "crypto.h"
#include "e2ee_common.h"

struct e2ee_tls {
    e2ee_t api;
    tls_context *tls;
    tlsuv_engine_t engine;
    bool server;

    char *out_buffer;
    char *out_p;
    size_t out_buffer_len;

    char *in_buffer;
    char *in_p;
    size_t in_buffer_len;

};

#define ee_log(l, fmt, ...) \
    ZITI_LOG(l, "ee[%s] " fmt, e->server ? "server" : "client", ##__VA_ARGS__)

static void e2ee_tls_free(e2ee_t *e) {
    struct e2ee_tls *e2ee = (struct e2ee_tls *)e;
    e2ee->engine->free(e2ee->engine);
    e2ee->tls->free_ctx(e2ee->tls);
    free(e2ee);
}

e2ee_pub_t e2ee_tls_pub(e2ee_t * e2ee) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(INFO, "getting pub");
    if (e->server) {
        const uint8_t *hello = NULL;
        size_t hello_len = 0;
        if (e->out_p != e->out_buffer) {
            hello = (uint8_t*)e->out_buffer;
            hello_len = e->out_p - e->out_buffer;
            e->out_p = e->out_buffer;
        }
        return (e2ee_pub_t){ .key = hello, .key_len = hello_len };
    }

    if (e->engine->handshake_state(e->engine) == TLS_HS_BEFORE) {
        tls_handshake_state st = e->engine->handshake(e->engine);
        size_t out_len = e->out_p - e->out_buffer;
        e->out_p = e->out_buffer;
        return (e2ee_pub_t){ .key = (const uint8_t*)e->out_buffer, .key_len = out_len};
    }
}
int e2ee_tls_init(e2ee_t *e2ee, const uint8_t * hello, size_t hello_len, bool server) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(INFO, "init hello[%zd]", hello_len);
    if (e->server) {
        memcpy(e->in_p, hello, hello_len);
        e->in_p += hello_len;
        tls_handshake_state st = e->engine->handshake(e->engine);
    } else {
        memcpy(e->in_p, hello, hello_len);
        e->in_p += hello_len;
        tls_handshake_state st = e->engine->handshake(e->engine);
    }
    return 0;
}

static ssize_t e2ee_tls_get_header(e2ee_t *e2ee, uint8_t header[E2EE_MAX_HEADER_LEN]) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(INFO, "getting header");
    if (e->server)
        return 0;

    if (e->out_p > e->out_buffer) {
        ssize_t len = e->out_p - e->out_buffer;
        memcpy(header, e->out_buffer, len);
        e->out_p = e->out_buffer;
        ee_log(INFO, "header %zd bytes", len);
        return len;
    }
    return 0;
}

static ssize_t e2ee_tls_encrypt(e2ee_t * e2ee, const uint8_t *plaintext, size_t plaintext_len, uint8_t * ciphertext, size_t ciphertext_len) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(INFO, "encrypt");
    enum tls_handshake_st hs = e->engine->handshake(e->engine);
    int wrc = e->engine->write(e->engine, (char*)plaintext, plaintext_len);
    size_t out_len = e->out_p - e->out_buffer;
    memcpy(ciphertext, e->out_buffer, out_len);
    e->out_p = e->out_buffer;

    ee_log(INFO, "encrypted %zd bytes", out_len);
    return (ssize_t)out_len;
}

ssize_t e2ee_tls_decrypt(e2ee_t *e2ee, const uint8_t * ciphertext, size_t ciphertext_len, uint8_t * plaintext, size_t plaintext_len) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(INFO, "decrypt %zd bytes", ciphertext_len);
    memcpy(e->in_p, ciphertext, ciphertext_len);
    e->in_p += ciphertext_len;

    size_t plen = 0;
    tls_handshake_state st = e->engine->handshake_state(e->engine);
    if (st == TLS_HS_CONTINUE) {
        st = e->engine->handshake(e->engine);
    }
    int rrc = e->engine->read(e->engine, (char*)plaintext, &plen, plaintext_len);
    if (rrc == TLS_AGAIN) {
        return 0;
    }
    if (rrc == 0) {
        ee_log(INFO, "decrypted %zd bytes", plen);
        return (ssize_t)plen;
    }
    return -1;
}

static e2ee_t e2ee_tls_impl = {
    .method = ziti_crypto_aes_gcm,
    .clone = NULL,
    .pub = e2ee_tls_pub,
    .init = e2ee_tls_init,
    .get_header = e2ee_tls_get_header,
    .encrypt = e2ee_tls_encrypt,
    .decrypt = e2ee_tls_decrypt,
    .free = e2ee_tls_free,
};

static long engine_out(void *ctx, const char* data, size_t len) {
    struct e2ee_tls *e = (struct e2ee_tls*)ctx;
    ee_log(INFO, "output %zd bytes", len);
    memcpy(e->out_p, data, len);
    e->out_p += len;
    return (long)len;
}

static long engine_in(void *ctx, char *buf, size_t buf_len) {
    struct e2ee_tls *e = (struct e2ee_tls*)ctx;
    ee_log(INFO, "reading %zd bytes", buf_len);
    size_t len = MIN(buf_len, e->in_p - e->in_buffer);
    if (len == 0) {
        return TLS_AGAIN;
    }

    memcpy(buf, (const uint8_t*)e->in_buffer, len);
    size_t rest = e->in_p - e->in_buffer - len;

    if (rest == 0) {
        e->in_p = e->in_buffer;
    } else {
        memmove(e->in_buffer, e->in_buffer + len, rest);
        e->in_p = e->in_buffer + rest;
    }

    ee_log(INFO, "read %zd bytes", len);
    return (long)len;
}

e2ee_t *new_tls_e2ee(bool server, zt_x509 *creds, const char *ca) {
    struct e2ee_tls *e2ee = calloc(1, sizeof(*e2ee));
    e2ee->api = e2ee_tls_impl;
    e2ee->in_buffer = malloc(16 * 1024);
    e2ee->in_buffer_len = 16 * 1024;
    e2ee->in_p = e2ee->in_buffer;

    e2ee->out_buffer = malloc(16 * 1024);
    e2ee->out_buffer_len = 16 * 1024;
    e2ee->out_p = e2ee->out_buffer;

    size_t ca_len = ca ? strlen(ca) : 0;
    e2ee->tls = default_tls_context(ca, ca_len);
    e2ee->server = server;
    if (server) {
        e2ee->tls->set_own_cert(e2ee->tls, creds->key, creds->cert);
        e2ee->engine = e2ee->tls->new_server_engine(e2ee->tls);
    } else {
        e2ee->engine = e2ee->tls->new_engine(e2ee->tls, NULL);
    }

    e2ee->engine->set_io(e2ee->engine, e2ee, engine_in, engine_out);

    return (e2ee_t*)e2ee;
}


