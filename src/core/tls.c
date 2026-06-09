#define _GNU_SOURCE
#include "ntc/tls.h"
#include "ntc/log.h"

#include "bearssl.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define NTC_TLS_MAX_CERTS 8

struct ntc_tls_conf {
    br_x509_certificate chain[NTC_TLS_MAX_CERTS]; /* data[] are malloc'd copies */
    size_t chain_len;
    br_skey_decoder_context skey; /* retains the decoded private-key bytes */
    br_rsa_private_key sk;        /* points into `skey` */
    bool have_key;
};

struct ntc_tls {
    br_ssl_server_context sc;
    bool eof;        /* transport reached EOF */
    bool close_sent; /* close_notify already requested */
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
};

/* ---- PEM -> DER ---- */

typedef struct { unsigned char *buf; size_t len, cap; bool oom; } derbuf;

static void der_append(void *ctx, const void *src, size_t len) {
    derbuf *d = ctx;
    if (d->oom) return;
    if (d->len + len > d->cap) {
        size_t nc = d->cap ? d->cap : 1024;
        while (nc < d->len + len) nc *= 2;
        unsigned char *nb = realloc(d->buf, nc);
        if (!nb) { d->oom = true; return; }
        d->buf = nb; d->cap = nc;
    }
    memcpy(d->buf + d->len, src, len);
    d->len += len;
}

/* Read a whole (small) file into a NUL-terminated, newline-terminated buffer. */
static char *read_text_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || sz > 1 << 20) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 2);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return NULL; }
    if (n == 0 || buf[n - 1] != '\n') buf[n++] = '\n'; /* PEM decoder wants EOL */
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/* Decode every PEM object in `pem`, invoking on_obj(name, der, dlen) per object.
 * Returns false on a PEM syntax error or OOM. */
static bool pem_each(const char *pem, size_t len,
                     void (*on_obj)(void *u, const char *name,
                                    const unsigned char *der, size_t dlen),
                     void *u) {
    br_pem_decoder_context pc;
    br_pem_decoder_init(&pc);
    derbuf d = { 0 };
    char name[80] = { 0 };
    bool in_obj = false, ok = true;
    size_t off = 0;
    while (off < len) {
        size_t pushed = br_pem_decoder_push(&pc, pem + off, len - off);
        off += pushed;
        int ev = br_pem_decoder_event(&pc);
        if (ev == BR_PEM_BEGIN_OBJ) {
            snprintf(name, sizeof name, "%s", br_pem_decoder_name(&pc));
            d.len = 0; d.oom = false;
            br_pem_decoder_setdest(&pc, der_append, &d);
            in_obj = true;
        } else if (ev == BR_PEM_END_OBJ) {
            if (in_obj) {
                if (d.oom) { ok = false; break; }
                on_obj(u, name, d.buf, d.len);
            }
            in_obj = false;
        } else if (ev == BR_PEM_ERROR) {
            ok = false; break;
        } else if (pushed == 0) {
            break; /* no event and no progress: malformed / done */
        }
    }
    free(d.buf);
    return ok;
}

static void collect_obj(void *u, const char *name,
                        const unsigned char *der, size_t dlen) {
    ntc_tls_conf *c = u;
    if (strstr(name, "CERTIFICATE")) {
        if (c->chain_len >= NTC_TLS_MAX_CERTS) return;
        unsigned char *copy = malloc(dlen ? dlen : 1);
        if (!copy) return;
        memcpy(copy, der, dlen);
        c->chain[c->chain_len].data = copy;
        c->chain[c->chain_len].data_len = dlen;
        c->chain_len++;
    } else if (strstr(name, "PRIVATE KEY") && !c->have_key) {
        /* br_skey_decoder accepts PKCS#1 ("RSA PRIVATE KEY") and PKCS#8
         * ("PRIVATE KEY") DER alike. */
        br_skey_decoder_push(&c->skey, der, dlen);
        c->have_key = true;
    }
}

ntc_tls_conf *ntc_tls_conf_new(const char *cert_pem_path, const char *key_pem_path) {
    if (!cert_pem_path || !key_pem_path) return NULL;
    ntc_tls_conf *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    br_skey_decoder_init(&c->skey);

    size_t clen = 0, klen = 0;
    char *cert = read_text_file(cert_pem_path, &clen);
    char *key = read_text_file(key_pem_path, &klen);
    bool ok = cert && key;
    if (ok) ok = pem_each(cert, clen, collect_obj, c);
    if (ok) ok = pem_each(key, klen, collect_obj, c);
    free(cert);
    free(key);

    if (ok && c->chain_len == 0) { NTC_ERROR("tls: no certificate in %s", cert_pem_path); ok = false; }
    if (ok && !c->have_key) { NTC_ERROR("tls: no private key in %s", key_pem_path); ok = false; }
    if (ok && br_skey_decoder_last_error(&c->skey) != 0) {
        NTC_ERROR("tls: private key decode failed (err %d)", br_skey_decoder_last_error(&c->skey));
        ok = false;
    }
    if (ok && br_skey_decoder_key_type(&c->skey) != BR_KEYTYPE_RSA) {
        NTC_ERROR("tls: private key is not RSA (EC keys not yet supported)");
        ok = false;
    }
    if (ok) {
        const br_rsa_private_key *rsa = br_skey_decoder_get_rsa(&c->skey);
        if (!rsa) { NTC_ERROR("tls: could not extract RSA private key"); ok = false; }
        else c->sk = *rsa; /* struct copy; pointers stay valid inside c->skey */
    }
    if (!ok) { ntc_tls_conf_free(c); return NULL; }
    return c;
}

void ntc_tls_conf_free(ntc_tls_conf *c) {
    if (!c) return;
    for (size_t i = 0; i < c->chain_len; i++) free(c->chain[i].data);
    free(c);
}

/* ---- per-connection engine ---- */

ntc_tls *ntc_tls_new(const ntc_tls_conf *conf) {
    if (!conf) return NULL;
    ntc_tls *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    br_ssl_server_init_full_rsa(&t->sc, conf->chain, conf->chain_len, &conf->sk);
    br_ssl_engine_set_buffer(&t->sc.eng, t->iobuf, sizeof t->iobuf, 1);

    /* Seed the engine PRNG explicitly so we never depend on BearSSL's compiled
     * system seeder being present. */
    unsigned char seed[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, seed, sizeof seed);
        if (r > 0) br_ssl_engine_inject_entropy(&t->sc.eng, seed, (size_t)r);
        close(fd);
    }
    if (br_ssl_server_reset(&t->sc) != 1) { free(t); return NULL; }
    return t;
}

void ntc_tls_free(ntc_tls *t) { free(t); }

int ntc_tls_pump_socket(ntc_tls *t, int fd) {
    br_ssl_engine_context *eng = &t->sc.eng;
    for (;;) {
        unsigned st = br_ssl_engine_current_state(eng);
        if (st & BR_SSL_CLOSED) return -1;
        bool progress = false;

        if (st & BR_SSL_SENDREC) {
            size_t len;
            unsigned char *buf = br_ssl_engine_sendrec_buf(eng, &len);
            if (buf && len) {
                ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
                if (n > 0) { br_ssl_engine_sendrec_ack(eng, (size_t)n); progress = true; }
                else if (n < 0 && errno == EINTR) continue;
                else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { /* socket full */ }
                else return -1;
            }
        }

        if (st & BR_SSL_RECVREC) {
            size_t len;
            unsigned char *buf = br_ssl_engine_recvrec_buf(eng, &len);
            if (buf && len) {
                ssize_t n = recv(fd, buf, len, 0);
                if (n > 0) { br_ssl_engine_recvrec_ack(eng, (size_t)n); progress = true; }
                else if (n == 0) { t->eof = true; }
                else if (n < 0 && errno == EINTR) continue;
                else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { /* drained */ }
                else return -1;
            }
        }

        if (!progress) break;
    }
    return 0;
}

int ntc_tls_recv(ntc_tls *t, void *buf, size_t len) {
    br_ssl_engine_context *eng = &t->sc.eng;
    if (br_ssl_engine_current_state(eng) & BR_SSL_CLOSED) return -1;
    size_t avail;
    unsigned char *src = br_ssl_engine_recvapp_buf(eng, &avail);
    if (!src || avail == 0) return 0;
    size_t n = avail < len ? avail : len;
    memcpy(buf, src, n);
    br_ssl_engine_recvapp_ack(eng, n);
    return (int)n;
}

int ntc_tls_send(ntc_tls *t, const void *buf, size_t len) {
    br_ssl_engine_context *eng = &t->sc.eng;
    size_t room;
    unsigned char *dst = br_ssl_engine_sendapp_buf(eng, &room);
    if (!dst || room == 0) return 0;
    size_t n = room < len ? room : len;
    memcpy(dst, buf, n);
    br_ssl_engine_sendapp_ack(eng, n);
    return (int)n;
}

void ntc_tls_flush(ntc_tls *t) { br_ssl_engine_flush(&t->sc.eng, 0); }

void ntc_tls_close_notify(ntc_tls *t) {
    if (!t->close_sent) { br_ssl_engine_close(&t->sc.eng); t->close_sent = true; }
}

bool ntc_tls_wants_write(const ntc_tls *t) {
    return (br_ssl_engine_current_state(&t->sc.eng) & BR_SSL_SENDREC) != 0;
}

bool ntc_tls_closed(const ntc_tls *t) {
    return t->eof || (br_ssl_engine_current_state(&t->sc.eng) & BR_SSL_CLOSED) != 0;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(tls, conf_loads_cert_and_key) {
    ntc_tls_conf *c = ntc_tls_conf_new("tests/vectors/tls.cert.pem", "tests/vectors/tls.key.pem");
    ASSERT_NOT_NULL(c);
    ntc_tls_conf_free(c);
}

TEST(tls, conf_rejects_missing_files) {
    ASSERT_TRUE(ntc_tls_conf_new("tests/vectors/nope.pem", "tests/vectors/tls.key.pem") == NULL);
    ASSERT_TRUE(ntc_tls_conf_new(NULL, NULL) == NULL);
}

TEST(tls, conf_rejects_cert_with_no_key) {
    /* the cert file has a CERTIFICATE but no PRIVATE KEY object */
    ASSERT_TRUE(ntc_tls_conf_new("tests/vectors/tls.cert.pem", "tests/vectors/tls.cert.pem") == NULL);
}

TEST(tls, engine_create_free_loop) {
    /* exercise the per-connection engine lifecycle many times. Under ASan this
     * catches use-after-free / double-free / overflow in new/free. */
    ntc_tls_conf *c = ntc_tls_conf_new("tests/vectors/tls.cert.pem", "tests/vectors/tls.key.pem");
    ASSERT_NOT_NULL(c);
    for (int i = 0; i < 200; i++) {
        ntc_tls *eng = ntc_tls_new(c);
        ASSERT_NOT_NULL(eng);
        /* fresh server engine wants to receive the ClientHello first */
        ASSERT_TRUE(ntc_tls_wants_write(eng) == false);
        ASSERT_TRUE(ntc_tls_closed(eng) == false);
        ntc_tls_free(eng);
    }
    ntc_tls_conf_free(c);
}

/* ---- in-process loopback: a full handshake + request/response between our
 * server engine and a BearSSL client over a socketpair. Unlike the integration
 * tests (which spawn the non-instrumented release binary), this runs the TLS
 * data path - pump_socket/recv/send/flush/close - INSIDE the ASan/UBSan unit
 * binary, so a buffer bug in those would be caught here. ---- */

/* accept-any X.509 wrapper (test client only) - same idea as tests/it_tls.c. */
typedef struct { const br_x509_class *vt; const br_x509_class **inner; } lb_xwc;
static void lb_sc(const br_x509_class **x, const char *s)
    { lb_xwc *w = (lb_xwc *)(void *)x; (*w->inner)->start_chain(w->inner, s); }
static void lb_scrt(const br_x509_class **x, uint32_t l)
    { lb_xwc *w = (lb_xwc *)(void *)x; (*w->inner)->start_cert(w->inner, l); }
static void lb_ap(const br_x509_class **x, const unsigned char *b, size_t l)
    { lb_xwc *w = (lb_xwc *)(void *)x; (*w->inner)->append(w->inner, b, l); }
static void lb_ec(const br_x509_class **x)
    { lb_xwc *w = (lb_xwc *)(void *)x; (*w->inner)->end_cert(w->inner); }
static unsigned lb_ech(const br_x509_class **x) {
    lb_xwc *w = (lb_xwc *)(void *)x;
    unsigned r = (*w->inner)->end_chain(w->inner);
    return r == BR_ERR_X509_NOT_TRUSTED ? 0 : r;
}
static const br_x509_pkey *lb_pk(const br_x509_class *const *x, unsigned *u)
    { const lb_xwc *w = (const lb_xwc *)(const void *)x; return (*w->inner)->get_pkey(w->inner, u); }
static const br_x509_class LB_VT = { sizeof(lb_xwc), lb_sc, lb_scrt, lb_ap, lb_ec, lb_ech, lb_pk };

/* Generic non-blocking engine<->fd pump (mirror of ntc_tls_pump_socket, for the
 * raw client engine). Returns -1 on close/error. */
static int lb_pump(br_ssl_engine_context *e, int fd) {
    for (;;) {
        unsigned st = br_ssl_engine_current_state(e);
        if (st & BR_SSL_CLOSED) return -1;
        bool prog = false;
        if (st & BR_SSL_SENDREC) {
            size_t l; unsigned char *b = br_ssl_engine_sendrec_buf(e, &l);
            ssize_t n = write(fd, b, l);
            if (n > 0) { br_ssl_engine_sendrec_ack(e, (size_t)n); prog = true; }
            else if (n < 0 && errno == EINTR) continue;
            else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { }
            else return -1;
        }
        if (st & BR_SSL_RECVREC) {
            size_t l; unsigned char *b = br_ssl_engine_recvrec_buf(e, &l);
            ssize_t n = read(fd, b, l);
            if (n > 0) { br_ssl_engine_recvrec_ack(e, (size_t)n); prog = true; }
            else if (n == 0) return -1;
            else if (n < 0 && errno == EINTR) continue;
            else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { }
            else return -1;
        }
        if (!prog) return 0;
    }
}

static bool lb_contains(const char *h, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || n < m) return false;
    for (size_t i = 0; i + m <= n; i++) if (memcmp(h + i, needle, m) == 0) return true;
    return false;
}

TEST(tls, loopback_handshake_and_io) {
    ntc_tls_conf *conf = ntc_tls_conf_new("tests/vectors/tls.cert.pem", "tests/vectors/tls.key.pem");
    ASSERT_NOT_NULL(conf);
    ntc_tls *srv = ntc_tls_new(conf);
    ASSERT_NOT_NULL(srv);

    int sp[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(sp[i], F_GETFL, 0);
        ASSERT_TRUE(fcntl(sp[i], F_SETFL, fl | O_NONBLOCK) == 0);
    }
    int sfd = sp[0], cfd = sp[1];

    br_ssl_client_context cc;
    br_x509_minimal_context xc;
    static unsigned char cbuf[BR_SSL_BUFSIZE_BIDI];
    br_ssl_client_init_full(&cc, &xc, NULL, 0);
    lb_xwc xwc = { &LB_VT, &xc.vtable };
    br_ssl_engine_set_x509(&cc.eng, &xwc.vt);
    br_ssl_engine_set_buffer(&cc.eng, cbuf, sizeof cbuf, 1);
    unsigned char seed[32];
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd >= 0) { ssize_t r = read(rfd, seed, sizeof seed);
        if (r > 0) br_ssl_engine_inject_entropy(&cc.eng, seed, (size_t)r); close(rfd); }
    ASSERT_EQ_INT(1, br_ssl_client_reset(&cc, "localhost", 0));

    const char *REQ = "GET /h HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const char *RES = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    size_t reqlen = strlen(REQ), reslen = strlen(RES);
    size_t req_sent = 0, res_sent = 0;
    char srv_got[512]; size_t srv_gotlen = 0;
    char cli_got[512]; size_t cli_gotlen = 0;
    bool res_started = false;

    for (int iter = 0; iter < 100000; iter++) {
        if (ntc_tls_pump_socket(srv, sfd) < 0 && !res_started) break;
        (void)lb_pump(&cc.eng, cfd);

        /* client pushes the request once the engine accepts app data */
        while (req_sent < reqlen) {
            size_t room; unsigned char *b = br_ssl_engine_sendapp_buf(&cc.eng, &room);
            if (!b || room == 0) break;
            size_t k = reqlen - req_sent; if (k > room) k = room;
            memcpy(b, REQ + req_sent, k); br_ssl_engine_sendapp_ack(&cc.eng, k);
            req_sent += k;
            if (req_sent == reqlen) br_ssl_engine_flush(&cc.eng, 0);
        }

        /* server drains the decrypted request */
        int r;
        while (srv_gotlen < sizeof srv_got &&
               (r = ntc_tls_recv(srv, srv_got + srv_gotlen, sizeof srv_got - srv_gotlen)) > 0)
            srv_gotlen += (size_t)r;

        /* once the server has the full request, it sends the response */
        if (!res_started && lb_contains(srv_got, srv_gotlen, "\r\n\r\n")) {
            while (res_sent < reslen) {
                int n = ntc_tls_send(srv, RES + res_sent, reslen - res_sent);
                if (n <= 0) break;
                res_sent += (size_t)n;
            }
            if (res_sent == reslen) { ntc_tls_flush(srv); ntc_tls_close_notify(srv); res_started = true; }
        } else if (res_started && res_sent < reslen) {
            while (res_sent < reslen) {
                int n = ntc_tls_send(srv, RES + res_sent, reslen - res_sent);
                if (n <= 0) break;
                res_sent += (size_t)n;
            }
            if (res_sent == reslen) ntc_tls_flush(srv);
        }

        /* client drains the decrypted response */
        for (;;) {
            size_t avail; unsigned char *b = br_ssl_engine_recvapp_buf(&cc.eng, &avail);
            if (!b || avail == 0) break;
            size_t k = avail; if (k > sizeof cli_got - cli_gotlen) k = sizeof cli_got - cli_gotlen;
            if (k == 0) break;
            memcpy(cli_got + cli_gotlen, b, k); cli_gotlen += k;
            br_ssl_engine_recvapp_ack(&cc.eng, k);
        }

        if (res_started && res_sent == reslen && cli_gotlen >= reslen) break;
        if (br_ssl_engine_current_state(&cc.eng) & BR_SSL_CLOSED) break;
    }

    /* the server received exactly the request, the client received the response */
    ASSERT_EQ_INT((int)reqlen, (int)srv_gotlen);
    ASSERT_TRUE(memcmp(srv_got, REQ, reqlen) == 0);
    ASSERT_TRUE(lb_contains(cli_got, cli_gotlen, "200 OK"));
    ASSERT_TRUE(lb_contains(cli_got, cli_gotlen, "ok"));
    ASSERT_EQ_INT(0, br_ssl_engine_last_error(&cc.eng));

    close(sfd); close(cfd);
    ntc_tls_free(srv);
    ntc_tls_conf_free(conf);
}
#endif /* UNIT_TEST */
