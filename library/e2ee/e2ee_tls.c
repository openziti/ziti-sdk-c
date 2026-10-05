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
    // the TLS backend runs its FIPS module: only FIPS-approved parameters are accepted
    bool fips;
    // set once the session is refused; the engine may still report its handshake complete
    bool failed;
    // the server has seen the dialer's certificate
    bool peer_checked;

    // framing of the peer's records once the handshake is done: a partial record header,
    // and the bytes of the current record still to come
    uint8_t rec_hdr[5];
    size_t rec_hdr_len;
    size_t rec_left;

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
static uint16_t rd16(const uint8_t *p) {
    return (uint16_t) ((p[0] << 8) | p[1]);
}

#define TLS_1_2 0x0303
#define TLS_1_3 0x0304
#define GROUP_SECP256R1 0x0017
#define GROUP_SECP521R1 0x0019

#define REC_HANDSHAKE 0x16
#define HS_SERVER_HELLO 2
#define HS_SERVER_KEY_EXCHANGE 12
#define EXT_EXTENDED_MASTER_SECRET 0x0017
#define EXT_SUPPORTED_VERSIONS 0x002b
#define EXT_KEY_SHARE 0x0033
#define CURVE_TYPE_NAMED 3

struct server_flight {
    uint16_t version;
    uint16_t suite;
    uint16_t group;
    bool ems;
};

// Joins the payloads of the handshake records at the start of a flight, since a handshake message
// can span records. Stops at the first other record: TLS 1.3 encrypts everything after the ServerHello.
static uint8_t *flight_handshake_bytes(const uint8_t *b, size_t len, size_t *hs_len) {
    uint8_t *hs = malloc(len > 0 ? len : 1);
    size_t n = 0;
    size_t p = 0;
    while (hs != NULL && p + 5 <= len && b[p] == REC_HANDSHAKE) {
        size_t rec_len = rd16(b + p + 3);
        if (p + 5 + rec_len > len) {
            break;
        }
        memcpy(hs + n, b + p + 5, rec_len);
        n += rec_len;
        p += 5 + rec_len;
    }
    *hs_len = n;
    return hs;
}

static bool parse_server_hello(const uint8_t *m, size_t len, struct server_flight *f) {
    // legacy_version(2) + random(32) + session id length(1)
    if (len < 35) {
        return false;
    }
    f->version = rd16(m);
    size_t p = 2 + 32;
    p += 1 + m[p];
    // cipher suite(2) + compression(1)
    if (p + 3 > len) {
        return false;
    }
    f->suite = rd16(m + p);
    p += 3;
    if (p + 2 > len) {
        return true;
    }
    size_t ext_end = p + 2 + rd16(m + p);
    if (ext_end > len) {
        return false;
    }
    p += 2;
    while (p + 4 <= ext_end) {
        uint16_t type = rd16(m + p);
        uint16_t ext_len = rd16(m + p + 2);
        p += 4;
        if (p + ext_len > ext_end) {
            return false;
        }
        if (type == EXT_SUPPORTED_VERSIONS && ext_len == 2) f->version = rd16(m + p);
        if (type == EXT_KEY_SHARE && ext_len >= 2) f->group = rd16(m + p);
        if (type == EXT_EXTENDED_MASTER_SECRET) f->ems = true;
        p += ext_len;
    }
    return true;
}

static bool fips_tls12_suite(uint16_t suite) {
    switch (suite) {
        case 0xc02b: // ECDHE-ECDSA-AES128-GCM-SHA256
        case 0xc02c: // ECDHE-ECDSA-AES256-GCM-SHA384
        case 0xc02f: // ECDHE-RSA-AES128-GCM-SHA256
        case 0xc030: // ECDHE-RSA-AES256-GCM-SHA384
            return true;
        default:
            return false;
    }
}

// Reads the negotiated version, cipher suite and key exchange group from a server's first flight: the
// ServerHello, and for TLS 1.2 the curve in the ServerKeyExchange. The engines differ in what they report,
// so the wire is the one source both backends share. Neither backend restricts these on its own in FIPS
// mode: the OpenSSL FIPS provider serves X25519, and Schannel's group order starts with it. So with the
// backend in FIPS mode only the choices SP 800-52r2 approves pass: an AES-GCM suite, a NIST curve, and
// for TLS 1.2 ECDHE with the extended master secret.
int tls_e2ee_check_server_flight(bool fips, const uint8_t *b, size_t len) {
    size_t hs_len = 0;
    uint8_t *hs = flight_handshake_bytes(b, len, &hs_len);
    struct server_flight f = {0};
    bool hello = false;
    size_t p = 0;
    while (hs != NULL && p + 4 <= hs_len) {
        uint8_t type = hs[p];
        size_t msg_len = ((size_t)hs[p + 1] << 16) | ((size_t)hs[p + 2] << 8) | hs[p + 3];
        if (p + 4 + msg_len > hs_len) {
            break;
        }
        const uint8_t *m = hs + p + 4;
        if (p == 0) {
            hello = type == HS_SERVER_HELLO && parse_server_hello(m, msg_len, &f);
            if (!hello) {
                break;
            }
        } else if (type == HS_SERVER_KEY_EXCHANGE && msg_len >= 3 && m[0] == CURVE_TYPE_NAMED) {
            f.group = rd16(m + 1);
        }
        p += 4 + msg_len;
    }
    free(hs);

    if (!hello) {
        ZITI_LOG(fips ? ERROR : DEBUG, "tls e2ee: server flight does not start with a ServerHello");
        return fips ? -1 : 0;
    }

    ZITI_LOG(INFO, "tls e2ee negotiated version[0x%04x] suite[0x%04x] group[0x%04x]%s%s",
             f.version, f.suite, f.group, f.version == TLS_1_2 ? (f.ems ? " ems" : " no-ems") : "",
             fips ? " (FIPS mode)" : "");
    if (!fips) {
        return 0;
    }
    if (f.version == TLS_1_3) {
        if (f.suite != 0x1301 && f.suite != 0x1302) {
            ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires an AES-GCM suite, negotiated[0x%04x]", f.suite);
            return -1;
        }
    } else if (f.version == TLS_1_2) {
        if (!fips_tls12_suite(f.suite)) {
            ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires an ECDHE AES-GCM suite, negotiated[0x%04x]", f.suite);
            return -1;
        }
        if (!f.ems) {
            ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires the extended master secret with TLS 1.2");
            return -1;
        }
    } else {
        ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires TLS 1.2 or 1.3, negotiated[0x%04x]", f.version);
        return -1;
    }
    if (f.group < GROUP_SECP256R1 || f.group > GROUP_SECP521R1) {
        ZITI_LOG(ERROR, "tls e2ee: FIPS mode requires a NIST-curve group, negotiated[0x%04x]", f.group);
        return -1;
    }
    return 0;
}

// A host requires the dialer's certificate. The engine has already checked the chain of one
// that was sent; a client certificate is optional in TLS, so its absence is caught here.
static int check_peer(struct e2ee_tls *e, tls_handshake_state st) {
    if (st != TLS_HS_COMPLETE || !e->server || e->peer_checked) {
        return 0;
    }
    tlsuv_certificate_t cert = NULL;
    if (e->engine->get_peer_cert == NULL || e->engine->get_peer_cert(e->engine, &cert) != 0 || cert == NULL) {
        ee_log(ERROR, "dialer presented no certificate");
        e->failed = true;
        return -1;
    }
    cert->free(cert);
    e->peer_checked = true;
    return 0;
}

// Refuses a TLS 1.2 renegotiation from either side: after the handshake every record a peer sends
// is application data or an alert. TLS 1.3 sends its post-handshake messages (tickets, KeyUpdate)
// in application data records, so they pass. Every e2ee message carries whole records, so the
// framing starts on a record boundary.
static int check_records(struct e2ee_tls *e, const uint8_t *b, size_t len) {
    size_t p = 0;
    while (p < len) {
        if (e->rec_left > 0) {
            size_t n = MIN(e->rec_left, len - p);
            e->rec_left -= n;
            p += n;
            continue;
        }
        size_t n = MIN(sizeof(e->rec_hdr) - e->rec_hdr_len, len - p);
        memcpy(e->rec_hdr + e->rec_hdr_len, b + p, n);
        e->rec_hdr_len += n;
        p += n;
        if (e->rec_hdr_len < sizeof(e->rec_hdr)) {
            break;
        }
        e->rec_hdr_len = 0;
        if (e->rec_hdr[0] == REC_HANDSHAKE) {
            ee_log(ERROR, "peer sent a handshake record after the handshake: renegotiation is not supported");
            e->failed = true;
            return -1;
        }
        e->rec_left = rd16(e->rec_hdr + 3);
    }
    return 0;
}

static int e2ee_tls_init(e2ee_t *e2ee, const uint8_t * hello, size_t hello_len, bool server) {
    struct e2ee_tls *e = (struct e2ee_tls*)e2ee;
    ee_log(VERBOSE, "init hello[%zd]", hello_len);
    // the client is handed the host's flight, which starts with the ServerHello
    if (!e->server && tls_e2ee_check_server_flight(e->fips, hello, hello_len) != 0) {
        return -1;
    }
    if (!ensure_capacity(&e->in_buffer, &e->in_p, &e->in_buffer_len, hello_len)) {
        ee_log(ERROR, "failed to buffer hello[%zd]: out of memory", hello_len);
        return -1;
    }
    memcpy(e->in_p, hello, hello_len);
    e->in_p += hello_len;
    tls_handshake_state st = e->engine->handshake(e->engine);
    if (st == TLS_HS_ERROR) {
        ee_log(ERROR, "handshake failed");
        return -1;
    }
    // the server has just produced its flight from the client's hello
    if (e->server && tls_e2ee_check_server_flight(e->fips, (const uint8_t *) e->out_buffer, e->out_p - e->out_buffer) != 0) {
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
    if (hs == TLS_HS_ERROR || check_peer(e, hs) != 0) {
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
    // the caller sizes `ciphertext` as plaintext_len + E2EE_MAX_MSG_OVERHEAD; TLS record
    // framing (plus any pending handshake output) could still exceed it, so fail rather
    // than overflow. the records stay buffered -- the caller treats this as fatal.
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
    tls_handshake_state st = e->engine->handshake_state(e->engine);
    if (st == TLS_HS_COMPLETE && check_records(e, ciphertext, ciphertext_len) != 0) {
        return -1;
    }
    if (!ensure_capacity(&e->in_buffer, &e->in_p, &e->in_buffer_len, ciphertext_len)) {
        ee_log(ERROR, "failed to buffer %zd bytes of ciphertext: out of memory", ciphertext_len);
        return -1;
    }
    memcpy(e->in_p, ciphertext, ciphertext_len);
    e->in_p += ciphertext_len;

    size_t plen = 0;
    if (st == TLS_HS_CONTINUE) {
        st = e->engine->handshake(e->engine);
    }
    // a failed handshake includes a rejected peer certificate. an engine may still decrypt
    // records that came with the peer's flight, and none of them may reach the caller
    if (st == TLS_HS_ERROR || check_peer(e, st) != 0) {
        ee_log(ERROR, "handshake failed");
        return -1;
    }
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
    .free = e2ee_tls_free,
};

static ssize_t engine_out(void *ctx, const char* data, size_t len) {
    struct e2ee_tls *e = (struct e2ee_tls*)ctx;
    ee_log(TRACE, "output %zd bytes", len);
    if (!ensure_capacity(&e->out_buffer, &e->out_p, &e->out_buffer_len, len)) {
        ee_log(WARN, "out of memory");
    }
    len = MIN(e->out_buffer_len - (e->out_p - e->out_buffer), len);
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

    // the server engine needs the identity cert, which set_own_cert may have failed to set
    tlsuv_engine_t engine = !server ? tls->new_engine(tls, NULL) :
                            tls->new_server_engine ? tls->new_server_engine(tls) : NULL;
    if (engine == NULL) {
        ZITI_LOG(ERROR, "failed to create %s TLS engine for e2ee", server ? "server" : "client");
        return NULL;
    }

    struct e2ee_tls *e2ee = calloc(1, sizeof(*e2ee));
    e2ee->api = e2ee_tls_impl;
    e2ee->in_buffer = malloc(BUF_INIT_CAP);
    e2ee->in_buffer_len = BUF_INIT_CAP;
    e2ee->in_p = e2ee->in_buffer;

    e2ee->out_buffer = malloc(BUF_INIT_CAP);
    e2ee->out_buffer_len = BUF_INIT_CAP;
    e2ee->out_p = e2ee->out_buffer;

    e2ee->server = server;
    e2ee->engine = engine;
    // both tlsuv backends mark their version string: OpenSSL with the FIPS provider as the
    // default, win32crypto with the Windows FIPS policy on
    const char *tls_ver = tls->version ? tls->version() : NULL;
    e2ee->fips = tls_ver != NULL && strstr(tls_ver, "FIPS") != NULL;

    e2ee->engine->set_io(e2ee->engine, e2ee, engine_in, engine_out);

    return (e2ee_t*)e2ee;
}


