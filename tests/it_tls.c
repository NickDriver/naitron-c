#define _GNU_SOURCE
#include "it_tls.h"

#include "bearssl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- accept-any X.509 wrapper (brssl's -noanchor behaviour) ----
 * Wraps the standard minimal engine so the EE public key is still decoded, but
 * a missing trust anchor is not treated as fatal. Test client only. */
typedef struct {
    const br_x509_class *vtable;
    const br_x509_class **inner;
} xwc_t;

static void xwc_start_chain(const br_x509_class **ctx, const char *sn) {
    xwc_t *x = (xwc_t *)(void *)ctx; (*x->inner)->start_chain(x->inner, sn);
}
static void xwc_start_cert(const br_x509_class **ctx, uint32_t len) {
    xwc_t *x = (xwc_t *)(void *)ctx; (*x->inner)->start_cert(x->inner, len);
}
static void xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
    xwc_t *x = (xwc_t *)(void *)ctx; (*x->inner)->append(x->inner, buf, len);
}
static void xwc_end_cert(const br_x509_class **ctx) {
    xwc_t *x = (xwc_t *)(void *)ctx; (*x->inner)->end_cert(x->inner);
}
static unsigned xwc_end_chain(const br_x509_class **ctx) {
    xwc_t *x = (xwc_t *)(void *)ctx;
    unsigned r = (*x->inner)->end_chain(x->inner);
    return (r == BR_ERR_X509_NOT_TRUSTED) ? 0 : r; /* accept untrusted (self-signed) */
}
static const br_x509_pkey *xwc_get_pkey(const br_x509_class *const *ctx, unsigned *u) {
    const xwc_t *x = (const xwc_t *)(const void *)ctx;
    return (*x->inner)->get_pkey(x->inner, u);
}
static const br_x509_class XWC_VTABLE = {
    sizeof(xwc_t),
    xwc_start_chain, xwc_start_cert, xwc_append,
    xwc_end_cert, xwc_end_chain, xwc_get_pkey,
};

/* ---- blocking transport callbacks for br_sslio ---- */
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    for (;;) {
        ssize_t r = read(fd, buf, len);
        if (r > 0) return (int)r;
        if (r < 0 && errno == EINTR) continue;
        return -1;
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

int it_tls_request(int port, const char *raw, size_t rawlen, char *resp, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }

    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    br_ssl_client_init_full(&sc, &xc, NULL, 0); /* no trust anchors */
    xwc_t xwc = { &XWC_VTABLE, &xc.vtable };
    br_ssl_engine_set_x509(&sc.eng, &xwc.vtable); /* accept-any */
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

    unsigned char seed[32];
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd >= 0) {
        ssize_t r = read(rfd, seed, sizeof seed);
        if (r > 0) br_ssl_engine_inject_entropy(&sc.eng, seed, (size_t)r);
        close(rfd);
    }
    if (br_ssl_client_reset(&sc, "localhost", 0) != 1) { close(fd); return -1; }

    br_sslio_context io;
    br_sslio_init(&io, &sc.eng, sock_read, &fd, sock_write, &fd);

    int rc = -1;
    if (br_sslio_write_all(&io, raw, rawlen) == 0 && br_sslio_flush(&io) == 0) {
        size_t total = 0;
        while (total < cap - 1) {
            int r = br_sslio_read(&io, resp + total, cap - 1 - total);
            if (r <= 0) break;
            total += (size_t)r;
        }
        resp[total] = '\0';
        if (total > 0) rc = (int)total;
    }
    close(fd);
    return rc;
}

int it_tls_get(int port, const char *path, char *resp, size_t cap) {
    char req[1024];
    int n = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    if (n < 0 || (size_t)n >= sizeof req) return -1;
    return it_tls_request(port, req, (size_t)n, resp, cap);
}
