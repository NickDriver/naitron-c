#define _GNU_SOURCE
#include "ntc/https_client.h"
#include "ntc/log.h"

#include "bearssl.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ---- trust-anchor set (deep-copied from PEM CA certs) ---- */

struct ntc_ca {
    br_x509_trust_anchor *ta;
    size_t num;
    size_t cap;
};

typedef struct { unsigned char *buf; size_t len, cap; bool oom; } growbuf;

static void gb_append(void *ctx, const void *src, size_t len) {
    growbuf *g = ctx;
    if (g->oom) return;
    if (g->len + len > g->cap) {
        size_t nc = g->cap ? g->cap : 256;
        while (nc < g->len + len) nc *= 2;
        unsigned char *nb = realloc(g->buf, nc);
        if (!nb) { g->oom = true; return; }
        g->buf = nb; g->cap = nc;
    }
    memcpy(g->buf + g->len, src, len);
    g->len += len;
}

static char *read_text_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || sz > 4 << 20) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 2);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return NULL; }
    if (n == 0 || buf[n - 1] != '\n') buf[n++] = '\n';
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/* Decode one DER cert into a trust anchor appended to `ca` (deep-copied). */
static bool ca_add_cert(ntc_ca *ca, const unsigned char *der, size_t dlen) {
    br_x509_decoder_context dc;
    growbuf dn = { 0 };
    br_x509_decoder_init(&dc, gb_append, &dn);
    br_x509_decoder_push(&dc, der, dlen);
    const br_x509_pkey *pk = br_x509_decoder_get_pkey(&dc);
    if (!pk || br_x509_decoder_last_error(&dc) != 0 || dn.oom || dn.len == 0) {
        free(dn.buf);
        return false;
    }

    if (ca->num >= ca->cap) {
        size_t nc = ca->cap ? ca->cap * 2 : 8;
        br_x509_trust_anchor *nt = realloc(ca->ta, nc * sizeof *nt);
        if (!nt) { free(dn.buf); return false; }
        ca->ta = nt; ca->cap = nc;
    }
    br_x509_trust_anchor *ta = &ca->ta[ca->num];
    memset(ta, 0, sizeof *ta);
    ta->dn.data = dn.buf;       /* hand ownership of the DN copy to the anchor */
    ta->dn.len = dn.len;
    ta->flags = br_x509_decoder_isCA(&dc) ? BR_X509_TA_CA : 0;
    ta->pkey.key_type = pk->key_type;

    bool ok = false;
    if (pk->key_type == BR_KEYTYPE_RSA) {
        unsigned char *n = malloc(pk->key.rsa.nlen ? pk->key.rsa.nlen : 1);
        unsigned char *e = malloc(pk->key.rsa.elen ? pk->key.rsa.elen : 1);
        if (n && e) {
            memcpy(n, pk->key.rsa.n, pk->key.rsa.nlen);
            memcpy(e, pk->key.rsa.e, pk->key.rsa.elen);
            ta->pkey.key.rsa.n = n; ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
            ta->pkey.key.rsa.e = e; ta->pkey.key.rsa.elen = pk->key.rsa.elen;
            ok = true;
        } else { free(n); free(e); }
    } else if (pk->key_type == BR_KEYTYPE_EC) {
        unsigned char *q = malloc(pk->key.ec.qlen ? pk->key.ec.qlen : 1);
        if (q) {
            memcpy(q, pk->key.ec.q, pk->key.ec.qlen);
            ta->pkey.key.ec.curve = pk->key.ec.curve;
            ta->pkey.key.ec.q = q; ta->pkey.key.ec.qlen = pk->key.ec.qlen;
            ok = true;
        }
    }
    if (!ok) { free(dn.buf); return false; }
    ca->num++;
    return true;
}

/* Iterate every CERTIFICATE PEM object in `pem`, adding each as a trust anchor. */
static bool ca_load_pem_buf(ntc_ca *ca, const char *pem, size_t len) {
    br_pem_decoder_context pc;
    br_pem_decoder_init(&pc);
    growbuf der = { 0 };
    bool in_cert = false, ok = true;
    size_t off = 0;
    while (off < len) {
        size_t pushed = br_pem_decoder_push(&pc, pem + off, len - off);
        off += pushed;
        int ev = br_pem_decoder_event(&pc);
        if (ev == BR_PEM_BEGIN_OBJ) {
            const char *name = br_pem_decoder_name(&pc);
            in_cert = strstr(name, "CERTIFICATE") != NULL;
            der.len = 0; der.oom = false;
            br_pem_decoder_setdest(&pc, in_cert ? gb_append : NULL, in_cert ? &der : NULL);
        } else if (ev == BR_PEM_END_OBJ) {
            if (in_cert && !der.oom && der.len) (void)ca_add_cert(ca, der.buf, der.len);
            in_cert = false;
        } else if (ev == BR_PEM_ERROR) {
            ok = false; break;
        } else if (pushed == 0) {
            break;
        }
    }
    free(der.buf);
    return ok;
}

ntc_ca *ntc_ca_load_pem(const char *path) {
    if (!path || !path[0]) return NULL;
    size_t len = 0;
    char *pem = read_text_file(path, &len);
    if (!pem) { NTC_WARN("ca: cannot read '%s'", path); return NULL; }
    ntc_ca *ca = calloc(1, sizeof *ca);
    if (!ca) { free(pem); return NULL; }
    bool ok = ca_load_pem_buf(ca, pem, len);
    free(pem);
    if (!ok || ca->num == 0) {
        NTC_WARN("ca: no usable certificate in '%s'", path);
        ntc_ca_free(ca);
        return NULL;
    }
    return ca;
}

ntc_ca *ntc_ca_default(void) {
    const char *p = getenv("NTC_CA_BUNDLE");
    if (p && p[0]) return ntc_ca_load_pem(p);
    return ntc_ca_load_pem("third_party/ca/roots.pem");
}

void ntc_ca_free(ntc_ca *ca) {
    if (!ca) return;
    for (size_t i = 0; i < ca->num; i++) {
        free(ca->ta[i].dn.data);
        if (ca->ta[i].pkey.key_type == BR_KEYTYPE_RSA) {
            free(ca->ta[i].pkey.key.rsa.n);
            free(ca->ta[i].pkey.key.rsa.e);
        } else if (ca->ta[i].pkey.key_type == BR_KEYTYPE_EC) {
            free(ca->ta[i].pkey.key.ec.q);
        }
    }
    free(ca->ta);
    free(ca);
}

/* ---- URL parsing + bounded blocking socket ---- */

static bool parse_https_url(const char *url, char *host, size_t hcap,
                            char *port, size_t pcap, char *path, size_t pathcap) {
    if (strncmp(url, "https://", 8) != 0) return false;
    const char *h = url + 8;
    const char *slash = strchr(h, '/');
    const char *hostend = slash ? slash : h + strlen(h);
    const char *colon = memchr(h, ':', (size_t)(hostend - h));
    size_t hlen = (size_t)((colon ? colon : hostend) - h);
    if (hlen == 0 || hlen >= hcap) return false;
    memcpy(host, h, hlen); host[hlen] = '\0';
    if (colon) {
        size_t plen = (size_t)(hostend - (colon + 1));
        if (plen == 0 || plen >= pcap) return false;
        memcpy(port, colon + 1, plen); port[plen] = '\0';
    } else {
        snprintf(port, pcap, "443");
    }
    snprintf(path, pathcap, "%s", slash ? slash : "/");
    return true;
}

static int connect_timeout(const char *host, const char *port, int timeout_ms) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) { fcntl(fd, F_SETFL, fl); break; }
        if (errno == EINPROGRESS) {
            struct pollfd pfd = { fd, POLLOUT, 0 };
            int pr = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : -1);
            if (pr == 1 && (pfd.revents & POLLOUT)) {
                int err = 0; socklen_t el = sizeof err;
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
                    fcntl(fd, F_SETFL, fl); break;
                }
            }
        }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }
    return fd;
}

static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    for (;;) {
        ssize_t r = read(fd, buf, len);
        if (r > 0) return (int)r;
        if (r < 0 && errno == EINTR) continue;
        return -1; /* EOF or timeout -> stop */
    }
}
static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    for (;;) {
        ssize_t w = write(fd, buf, len);
        if (w > 0) return (int)w;
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
}

static void set_err(char *err, size_t cap, const char *msg) {
    if (err && cap) snprintf(err, cap, "%s", msg);
}

/* Copy the HTTP body out of a raw response, de-chunking if needed. Returns body
 * length or -1. Only succeeds on a 200 status line. */
static int extract_body(const char *resp, size_t rlen, char *out, size_t cap,
                        char *err, size_t errcap) {
    if (rlen < 12 || strncmp(resp, "HTTP/1.", 7) != 0) { set_err(err, errcap, "bad response"); return -1; }
    int status = atoi(resp + 9);
    const char *sep = NULL;
    for (size_t i = 0; i + 3 < rlen; i++)
        if (resp[i] == '\r' && resp[i+1] == '\n' && resp[i+2] == '\r' && resp[i+3] == '\n') { sep = resp + i + 4; break; }
    if (!sep) { set_err(err, errcap, "no header terminator"); return -1; }
    if (status != 200) {
        char m[64]; snprintf(m, sizeof m, "http status %d", status);
        set_err(err, errcap, m);
        return -1;
    }
    size_t hdr_len = (size_t)(sep - resp);
    size_t body_len = rlen - hdr_len;

    /* case-insensitive search for chunked transfer-encoding in the headers */
    bool chunked = false;
    for (size_t i = 0; i + 7 < hdr_len; i++)
        if (strncasecmp(resp + i, "chunked", 7) == 0) { chunked = true; break; }

    if (!chunked) {
        if (body_len >= cap) { set_err(err, errcap, "body too large"); return -1; }
        memcpy(out, sep, body_len);
        out[body_len] = '\0';
        return (int)body_len;
    }

    /* de-chunk: <hex-size>\r\n<data>\r\n ... 0\r\n\r\n */
    const char *p = sep, *end = resp + rlen;
    size_t w = 0;
    while (p < end) {
        char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) break;
        long sz = strtol(p, NULL, 16);
        p = eol + 1;
        if (sz <= 0) break;
        if (p + sz > end) break;
        if (w + (size_t)sz >= cap) { set_err(err, errcap, "body too large"); return -1; }
        memcpy(out + w, p, (size_t)sz);
        w += (size_t)sz;
        p += sz;
        if (p + 2 <= end && p[0] == '\r' && p[1] == '\n') p += 2; /* trailing CRLF */
    }
    out[w] = '\0';
    return (int)w;
}

static int https_do(const ntc_ca *ca, const char *method, const char *url,
                    const char *ctype, const char *body, size_t blen,
                    char *out, size_t cap, int timeout_ms, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';
    if (!ca || ca->num == 0) { set_err(err, errcap, "no trust anchors (fail closed)"); return -1; }
    if (!url || !out || cap == 0) { set_err(err, errcap, "bad args"); return -1; }
    if (timeout_ms <= 0) timeout_ms = 5000;

    char host[256], port[16], path[1024];
    if (!parse_https_url(url, host, sizeof host, port, sizeof port, path, sizeof path)) {
        set_err(err, errcap, "bad https url");
        return -1;
    }

    int fd = connect_timeout(host, port, timeout_ms);
    if (fd < 0) { set_err(err, errcap, "connect failed"); return -1; }

    /* heap-allocate the (large) TLS client state */
    struct tlsbox {
        br_ssl_client_context cc;
        br_x509_minimal_context xc;
        unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    } *b = calloc(1, sizeof *b);
    if (!b) { close(fd); set_err(err, errcap, "oom"); return -1; }

    br_ssl_client_init_full(&b->cc, &b->xc, ca->ta, ca->num); /* REAL verification */
    br_ssl_engine_set_buffer(&b->cc.eng, b->iobuf, sizeof b->iobuf, 1);

    unsigned char seed[32];
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd >= 0) {
        ssize_t rr = read(rfd, seed, sizeof seed);
        if (rr > 0) br_ssl_engine_inject_entropy(&b->cc.eng, seed, (size_t)rr);
        close(rfd);
    }
    if (br_ssl_client_reset(&b->cc, host, 0) != 1) {
        free(b); close(fd); set_err(err, errcap, "tls reset failed"); return -1;
    }

    br_sslio_context io;
    br_sslio_init(&io, &b->cc.eng, sock_read, &fd, sock_write, &fd);

    char req[1400];
    int rn = snprintf(req, sizeof req,
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: naitron-c\r\n"
        "Accept: application/json\r\nConnection: close\r\n",
        method, path, host);
    if (rn > 0 && (size_t)rn < sizeof req && body) /* append entity headers for a body */
        rn += snprintf(req + rn, sizeof req - (size_t)rn,
                       "Content-Type: %s\r\nContent-Length: %zu\r\n",
                       ctype ? ctype : "application/x-www-form-urlencoded", blen);
    if (rn > 0 && (size_t)rn < sizeof req)
        rn += snprintf(req + rn, sizeof req - (size_t)rn, "\r\n"); /* end of headers */
    int result = -1;
    if (rn > 0 && (size_t)rn < sizeof req &&
        br_sslio_write_all(&io, req, (size_t)rn) == 0 &&
        (!body || br_sslio_write_all(&io, body, blen) == 0) &&
        br_sslio_flush(&io) == 0) {
        /* read the whole response (Connection: close => server EOFs after body) */
        char *resp = malloc(256 * 1024);
        if (resp) {
            size_t total = 0;
            while (total < 256 * 1024 - 1) {
                int r = br_sslio_read(&io, resp + total, 256 * 1024 - 1 - total);
                if (r <= 0) break;
                total += (size_t)r;
            }
            int eng_err = br_ssl_engine_last_error(&b->cc.eng);
            /* A clean close_notify => 0; a truncated TCP close (no close_notify)
             * is common with "Connection: close" and is not fatal for us as long
             * as we got a complete, parseable response. A real certificate
             * failure shows up as a BR_ERR_X509_* and leaves total == 0. */
            if (total > 0)
                result = extract_body(resp, total, out, cap, err, errcap);
            else if (eng_err != 0) {
                char m[64]; snprintf(m, sizeof m, "tls error %d", eng_err);
                set_err(err, errcap, m);
            } else {
                set_err(err, errcap, "empty response");
            }
            free(resp);
        } else {
            set_err(err, errcap, "oom");
        }
    } else {
        set_err(err, errcap, "tls handshake/write failed");
    }

    free(b);
    close(fd);
    return result;
}

int ntc_https_get(const ntc_ca *ca, const char *url, char *out, size_t cap,
                  int timeout_ms, char *err, size_t errcap) {
    return https_do(ca, "GET", url, NULL, NULL, 0, out, cap, timeout_ms, err, errcap);
}

int ntc_https_post(const ntc_ca *ca, const char *url, const char *content_type,
                   const char *body, size_t blen, char *out, size_t cap,
                   int timeout_ms, char *err, size_t errcap) {
    return https_do(ca, "POST", url, content_type, body ? body : "", blen,
                    out, cap, timeout_ms, err, errcap);
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(https, url_parse) {
    char h[256], p[16], path[1024];
    ASSERT_TRUE(parse_https_url("https://example.com/.well-known/jwks.json", h, sizeof h, p, sizeof p, path, sizeof path));
    ASSERT_TRUE(strcmp(h, "example.com") == 0);
    ASSERT_TRUE(strcmp(p, "443") == 0);
    ASSERT_TRUE(strcmp(path, "/.well-known/jwks.json") == 0);

    ASSERT_TRUE(parse_https_url("https://localhost:38199/jwks.json", h, sizeof h, p, sizeof p, path, sizeof path));
    ASSERT_TRUE(strcmp(h, "localhost") == 0);
    ASSERT_TRUE(strcmp(p, "38199") == 0);

    ASSERT_TRUE(parse_https_url("https://host.tld", h, sizeof h, p, sizeof p, path, sizeof path));
    ASSERT_TRUE(strcmp(path, "/") == 0);

    ASSERT_FALSE(parse_https_url("http://insecure.com/x", h, sizeof h, p, sizeof p, path, sizeof path));
}

TEST(https, ca_load_self_signed_cert) {
    /* our test TLS cert is a self-signed CA - it must decode to one anchor */
    ntc_ca *ca = ntc_ca_load_pem("tests/vectors/tls.cert.pem");
    ASSERT_NOT_NULL(ca);
    ntc_ca_free(ca);
    /* a missing file fails cleanly */
    ASSERT_TRUE(ntc_ca_load_pem("tests/vectors/nope.pem") == NULL);
}

TEST(https, get_fails_closed_without_anchors) {
    char body[64], err[64];
    ASSERT_EQ_INT(-1, ntc_https_get(NULL, "https://localhost/x", body, sizeof body, 500, err, sizeof err));
    ASSERT_TRUE(strstr(err, "trust") != NULL);
}

TEST(https, extract_body_dechunks) {
    char out[64], err[64];
    const char *r = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    int n = extract_body(r, strlen(r), out, sizeof out, err, sizeof err);
    ASSERT_EQ_INT(9, n);
    ASSERT_TRUE(strcmp(out, "Wikipedia") == 0);

    const char *r2 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    ASSERT_EQ_INT(-1, extract_body(r2, strlen(r2), out, sizeof out, err, sizeof err));
    ASSERT_TRUE(strstr(err, "404") != NULL);
}
#endif /* UNIT_TEST */
