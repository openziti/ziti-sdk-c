//
//

#include "buffer.h"
#include "crypto.h"
#include "e2ee_common.h"
#include <string.h>
#include <tlsuv/tls_engine.h>

struct e2ee_tls {
    e2ee_t api;
    tlsuv_engine_t engine;
    bool server;
    // set when output could not be buffered. the engine still thinks the records went out
    bool failed;

    char *out_buffer;
    char *out_p;
    size_t out_buffer_len;

    char *in_buffer;
    char *in_p;
    size_t in_buffer_len;

};

#define BUF_INIT_CAP (16 * 1024)

#define ee_log(l, fmt, ...) \
    ZITI_LOG(l, "ee[%s] " fmt, e->server ? "server" : "client", ##__VA_ARGS__)

// make sure `*buf` can hold `used + extra` bytes, growing it in BUF_INIT_CAP increments.
// `*p` is the current write position and is adjusted if the buffer is moved.
static bool ensure_capacity(char **buf, char **p, size_t *cap, size_t extra) {
    size_t used = *p - *buf;
    if (used + extra <= *cap) {
        return true;
    }

    size_t increase = ((used + extra - *cap) / BUF_INIT_CAP + 1) * BUF_INIT_CAP;
    size_t new_len = *cap + increase;
    char *new_buffer = realloc(*buf, new_len);
    if (new_buffer == NULL) {
        return false;
    }

    *buf = new_buffer;
    *p = new_buffer + used;
    *cap = new_len;
    return true;
}

static void e2ee_tls_free(e2ee_t *e) {
    struct e2ee_tls *e2ee = (struct e2ee_tls *)e;
    e2ee->engine->free(e2ee->engine);
    free(e2ee->out_buffer);
    free(e2ee->in_buffer);
    free(e2ee);
}

static e2ee_pub_t e2ee_tls_pub(e2ee_t * e2ee) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(VERBOSE, "getting pub");
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

    return (e2ee_pub_t){ .key = NULL, .key_len = 0 };
}

static int buffer_input(struct e2ee_tls *e, const uint8_t *b, size_t len) {
    if (!ensure_capacity(&e->in_buffer, &e->in_p, &e->in_buffer_len, len)) {
        ee_log(ERROR, "failed to buffer %zd bytes of input: out of memory", len);
        return -1;
    }
    memcpy(e->in_p, b, len);
    e->in_p += len;
    return 0;
}

static int e2ee_tls_init(e2ee_t *e2ee, const uint8_t * hello, size_t hello_len, bool server) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(VERBOSE, "init hello[%zd]", hello_len);
    if (buffer_input(e, hello, hello_len) != 0) {
        return -1;
    }
    tls_handshake_state st = e->engine->handshake(e->engine);
    if (st == TLS_HS_ERROR) {
        ee_log(ERROR, "handshake failed");
        return -1;
    }
    return 0;
}

static ssize_t e2ee_tls_get_header(e2ee_t *e2ee, uint8_t header[E2EE_MAX_HEADER_LEN]) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(VERBOSE, "getting header");
    // a server can be left with handshake output after taking the client's flight:
    // under TLS 1.2 its ChangeCipherSpec and Finished, which the client needs first
    if (e->out_p > e->out_buffer) {
        ssize_t len = e->out_p - e->out_buffer;
        if (len > E2EE_MAX_HEADER_LEN) {
            ee_log(ERROR, "pending handshake output[%zd] exceeds header limit[%d]", len, E2EE_MAX_HEADER_LEN);
            return -1;
        }
        memcpy(header, e->out_buffer, len);
        e->out_p = e->out_buffer;
        ee_log(VERBOSE, "header %zd bytes", len);
        return len;
    }
    return 0;
}

static ssize_t e2ee_tls_encrypt(e2ee_t * e2ee, const uint8_t *plaintext, size_t plaintext_len, uint8_t * ciphertext, size_t ciphertext_len) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(TRACE, "encrypt");
    if (e->failed) {
        return -1;
    }
    enum tls_handshake_st hs = e->engine->handshake(e->engine);
    if (hs == TLS_HS_ERROR) {
        ee_log(ERROR, "handshake failed");
        return -1;
    }

    // an engine may take less than the whole payload per call (Schannel encrypts one
    // record at a time), so keep writing until all of it is in the output buffer
    size_t written = 0;
    while (written < plaintext_len) {
        int wrc = e->engine->write(e->engine, (char*)plaintext + written, plaintext_len - written);
        if (wrc == TLS_ERR) {
            ee_log(ERROR, "encrypt failed");
            return -1;
        }

        if (wrc == TLS_AGAIN) {
            ee_log(ERROR, "output buffer overflow");
            return -1;
        }

        if (wrc <= 0) {
            ee_log(ERROR, "partial write: %zd of %zd bytes", written, plaintext_len);
            return -1;
        }
        written += (size_t)wrc;
    }

    size_t out_len = e->out_p - e->out_buffer;
    // the caller sizes `ciphertext` with e2ee_ciphertext_len. an engine that frames records
    // smaller than that assumes could still exceed it, so fail rather than overflow.
    // the records stay buffered -- the caller treats this as fatal.
    if (out_len > ciphertext_len) {
        ee_log(ERROR, "ciphertext buffer too small: need %zd, have %zd", out_len, ciphertext_len);
        return -1;
    }
    memcpy(ciphertext, e->out_buffer, out_len);
    e->out_p = e->out_buffer;

    ee_log(TRACE, "encrypted %zd bytes", out_len);
    return (ssize_t)out_len;
}

static ssize_t e2ee_tls_decrypt(e2ee_t *e2ee, const uint8_t * ciphertext, size_t ciphertext_len, uint8_t * plaintext, size_t plaintext_len) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(TRACE, "decrypt %zd bytes", ciphertext_len);
    if (e->failed) {
        return -1;
    }
    if (buffer_input(e, ciphertext, ciphertext_len) != 0) {
        return -1;
    }

    tls_handshake_state st = e->engine->handshake_state(e->engine);
    if (st == TLS_HS_CONTINUE) {
        st = e->engine->handshake(e->engine);
    }
    // a failed handshake includes a rejected peer certificate. an engine may still decrypt
    // records that came with the peer's flight, and none of them may reach the caller
    if (st == TLS_HS_ERROR) {
        ee_log(ERROR, "handshake failed");
        return -1;
    }

    size_t plen = 0;
    int rrc = e->engine->read(e->engine, (char*)plaintext, &plen, plaintext_len);
    if (rrc == TLS_AGAIN) {
        return 0;
    }
    if (rrc == 0) {
        ee_log(TRACE, "decrypted %zd bytes", plen);
        return (ssize_t)plen;
    }
    return -1;
}

// a TLS 1.3 client completes on sending its Finished, a TLS 1.2 client only after the server's,
// and a server only after the client's
static bool e2ee_tls_ready(e2ee_t *e2ee) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    return !e->failed && e->engine->handshake_state(e->engine) == TLS_HS_COMPLETE;
}

static e2ee_t e2ee_tls_impl = {
    .method = ziti_crypto_tls,
    .clone = NULL,
    .pub = e2ee_tls_pub,
    .init = e2ee_tls_init,
    .get_header = e2ee_tls_get_header,
    .encrypt = e2ee_tls_encrypt,
    .decrypt = e2ee_tls_decrypt,
    .ready = e2ee_tls_ready,
    .handshake_output = e2ee_tls_get_header,
    .free = e2ee_tls_free,
};

static ssize_t engine_out(void *ctx, const char* data, size_t len) {
    struct e2ee_tls *e = (struct e2ee_tls*)ctx;
    ee_log(TRACE, "output %zd bytes", len);
    // a dropped tail would corrupt the record stream, so fail the engine instead
    if (!ensure_capacity(&e->out_buffer, &e->out_p, &e->out_buffer_len, len)) {
        ee_log(ERROR, "failed to buffer %zd bytes of output: out of memory", len);
        e->failed = true;
        return TLS_ERR;
    }
    memcpy(e->out_p, data, len);
    e->out_p += len;
    return (long)len;
}

static ssize_t engine_in(void *ctx, char *buf, size_t buf_len) {
    struct e2ee_tls *e = (struct e2ee_tls*)ctx;
    ee_log(TRACE, "reading %zd bytes", buf_len);
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

    ee_log(TRACE, "read %zd bytes", len);
    return (long)len;
}

e2ee_t *new_tls_e2ee(bool server, tls_context *tls) {
    // the context is borrowed from the ziti context, which drops it when disabled
    if (tls == NULL) {
        ZITI_LOG(ERROR, "no TLS context to create e2ee engine from");
        return NULL;
    }

    struct e2ee_tls *e2ee = calloc(1, sizeof(*e2ee));
    if (e2ee == NULL) {
        ZITI_LOG(ERROR, "failed to allocate e2ee engine: out of memory");
        return NULL;
    }
    e2ee->in_buffer = malloc(BUF_INIT_CAP);
    e2ee->out_buffer = malloc(BUF_INIT_CAP);
    // the server engine needs the identity cert, which set_own_cert may have failed to set
    tlsuv_engine_t engine = e2ee->in_buffer == NULL || e2ee->out_buffer == NULL ? NULL :
                            !server ? tls->new_engine(tls, NULL) :
                            tls->new_server_engine ? tls->new_server_engine(tls) : NULL;
    if (engine == NULL) {
        ZITI_LOG(ERROR, "failed to create %s TLS engine for e2ee", server ? "server" : "client");
        free(e2ee->in_buffer);
        free(e2ee->out_buffer);
        free(e2ee);
        return NULL;
    }

    e2ee->api = e2ee_tls_impl;
    e2ee->in_buffer_len = BUF_INIT_CAP;
    e2ee->in_p = e2ee->in_buffer;
    e2ee->out_buffer_len = BUF_INIT_CAP;
    e2ee->out_p = e2ee->out_buffer;

    e2ee->server = server;
    e2ee->engine = engine;

    e2ee->engine->set_io(e2ee->engine, e2ee, engine_in, engine_out);

    return (e2ee_t*)e2ee;
}


