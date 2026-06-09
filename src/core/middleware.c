#define _GNU_SOURCE
#include "ntc/middleware.h"
#include "ntc/crypto.h"
#include "ntc/jwt.h"
#include "ntc/log.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NTC_RL_BUCKETS 1024

struct ntc_mw {
    ntc_mw_config cfg;
    ntc_rsa_pubkey rsa_key;             /* parsed JWKS for RS256 (if configured) */
    ntc_bucket buckets[NTC_RL_BUCKETS]; /* keyed by hash(client_ip) */
};

/* Read up to `cap`-1 bytes of a file into buf (NUL-terminated). Returns the
 * length, or -1 on error. Used for the (small) JWKS document. */
static long slurp_file(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    int err = ferror(f);
    bool more = !feof(f); /* file bigger than our buffer */
    fclose(f);
    if (err || more) return -1;
    buf[n] = '\0';
    return (long)n;
}

ntc_mw *ntc_mw_new(const ntc_mw_config *cfg) {
    ntc_mw *m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->cfg = *cfg;
    if (m->cfg.auth_jwks_file[0]) {
        char doc[16384];
        long n = slurp_file(m->cfg.auth_jwks_file, doc, sizeof doc);
        if (n > 0 && ntc_jwk_parse(doc, (size_t)n, &m->rsa_key))
            NTC_INFO("auth: loaded RS256 key from %s", m->cfg.auth_jwks_file);
        else
            NTC_WARN("auth: could not load JWKS '%s'; RS256 tokens will be rejected",
                     m->cfg.auth_jwks_file);
    }
    return m;
}
void ntc_mw_free(ntc_mw *m) { free(m); }

bool ntc_bucket_allow(ntc_bucket *b, long now_ms, double rate_per_sec, double burst) {
    if (b->last_ms == 0) { b->tokens = burst; b->last_ms = now_ms; }
    double elapsed = (double)(now_ms - b->last_ms) / 1000.0;
    if (elapsed > 0) {
        b->tokens += elapsed * rate_per_sec;
        if (b->tokens > burst) b->tokens = burst;
        b->last_ms = now_ms;
    }
    if (b->tokens >= 1.0) { b->tokens -= 1.0; return true; }
    return false;
}

static unsigned hash_str(const char *s) {
    unsigned h = 2166136261u;
    for (; s && *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    return h;
}

static void gen_request_id(char *out, size_t cap) {
    unsigned char b[8];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0 && read(fd, b, sizeof b) == (ssize_t)sizeof b) {
        for (size_t i = 0; i < sizeof b && 2 * i + 2 < cap; i++)
            snprintf(out + 2 * i, cap - 2 * i, "%02x", b[i]);
    } else {
        snprintf(out, cap, "req-0000000000000000");
    }
    if (fd >= 0) close(fd);
}

bool ntc_mw_before(ntc_mw *m, const ntc_request *req, const char *client_ip,
                   long now_ms, ntc_mw_result *r) {
    memset(r, 0, sizeof *r);
    size_t off = 0;
    char *eh = r->extra_headers;
    size_t cap = sizeof r->extra_headers;

    if (m->cfg.request_id) {
        gen_request_id(r->request_id, sizeof r->request_id);
        off += (size_t)snprintf(eh + off, cap - off, "X-Request-Id: %s\r\n", r->request_id);
    }

    if (m->cfg.cors_origin[0]) {
        off += (size_t)snprintf(eh + off, cap - off,
            "Access-Control-Allow-Origin: %s\r\n"
            "Access-Control-Allow-Methods: GET,POST,PUT,PATCH,DELETE,OPTIONS\r\n"
            "Access-Control-Allow-Headers: Authorization,Content-Type\r\n",
            m->cfg.cors_origin);
        if (ntc_slice_eq_cstr(req->method, "OPTIONS")) {
            r->short_circuit = true;
            r->status = 204;
            r->content_type = NTC_SLICE_LIT("text/plain");
            r->body = NTC_SLICE_LIT("");
            return true;
        }
    }

    if (m->cfg.auth_mode[0] && strcmp(m->cfg.auth_mode, "none") != 0) {
        bool protectd = m->cfg.auth_protect[0] == '\0' ||
                        ntc_slice_starts_with(req->path, ntc_slice_cstr(m->cfg.auth_protect));
        if (protectd) {
            ntc_slice a = ntc_http_header(req, "authorization");
            bool ok = false;
            if (a.len > 7 && memcmp(a.ptr, "Bearer ", 7) == 0) {
                ntc_slice tok = ntc_slice_new(a.ptr + 7, a.len - 7);
                if (strcmp(m->cfg.auth_mode, "apikey") == 0) {
                    size_t sl = strlen(m->cfg.auth_secret);
                    ok = tok.len == sl && ntc_ct_eq((const uint8_t *)tok.ptr,
                                                    (const uint8_t *)m->cfg.auth_secret, sl);
                } else if (strcmp(m->cfg.auth_mode, "jwt") == 0) {
                    /* dispatch on the token's own alg: HS256 -> shared secret,
                     * RS256 -> the configured JWKS public key. */
                    ntc_jwt_claims cl;
                    char alg[16];
                    if (ntc_jwt_peek_alg(tok.ptr, tok.len, alg, sizeof alg)) {
                        if (strcmp(alg, "RS256") == 0 && m->rsa_key.present)
                            ok = ntc_jwt_verify_rs256(tok.ptr, tok.len, &m->rsa_key, time(NULL), &cl);
                        else if (strcmp(alg, "HS256") == 0 && m->cfg.auth_secret[0])
                            ok = ntc_jwt_verify_hs256(tok.ptr, tok.len, m->cfg.auth_secret, time(NULL), &cl);
                    }
                    if (ok) {
                        snprintf(r->auth_sub, sizeof r->auth_sub, "%s", cl.sub);
                        snprintf(r->auth_scope, sizeof r->auth_scope, "%s", cl.scope);
                    }
                }
            }
            if (!ok) {
                r->short_circuit = true;
                r->status = 401;
                r->content_type = NTC_SLICE_LIT("application/json");
                r->body = NTC_SLICE_LIT("{\"error\":\"unauthorized\"}");
                return true;
            }
        }
    }

    if (m->cfg.rate_per_sec > 0) {
        unsigned idx = hash_str(client_ip) % NTC_RL_BUCKETS;
        double burst = m->cfg.rate_burst > 0 ? m->cfg.rate_burst : m->cfg.rate_per_sec;
        if (!ntc_bucket_allow(&m->buckets[idx], now_ms, m->cfg.rate_per_sec, burst)) {
            r->short_circuit = true;
            r->status = 429;
            r->content_type = NTC_SLICE_LIT("application/json");
            r->body = NTC_SLICE_LIT("{\"error\":\"rate limited\"}");
            return true;
        }
    }
    return false;
}

void ntc_mw_after(ntc_mw *m, const char *method, const char *path,
                  const char *request_id, int status, long duration_ms) {
    if (!m->cfg.access_log) return;
    NTC_INFO("%s %s -> %d (%ldms) rid=%s", method, path, status, duration_ms,
             request_id && request_id[0] ? request_id : "-");
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(middleware, token_bucket_limits) {
    ntc_bucket b = { 0, 0 };
    /* rate 10/s, burst 3: first 3 allowed at t=0, 4th denied */
    ASSERT_TRUE(ntc_bucket_allow(&b, 1000, 10, 3));
    ASSERT_TRUE(ntc_bucket_allow(&b, 1000, 10, 3));
    ASSERT_TRUE(ntc_bucket_allow(&b, 1000, 10, 3));
    ASSERT_FALSE(ntc_bucket_allow(&b, 1000, 10, 3));
    /* after 100ms at 10/s, 1 token refilled */
    ASSERT_TRUE(ntc_bucket_allow(&b, 1100, 10, 3));
    ASSERT_FALSE(ntc_bucket_allow(&b, 1100, 10, 3));
}

TEST(middleware, cors_preflight_short_circuits) {
    ntc_mw_config cfg = { 0 };
    cfg.cors_origin[0] = '*'; cfg.cors_origin[1] = '\0';
    ntc_mw *m = ntc_mw_new(&cfg);
    ASSERT_NOT_NULL(m);
    ntc_request req; memset(&req, 0, sizeof req);
    req.method = NTC_SLICE_LIT("OPTIONS");
    req.path = NTC_SLICE_LIT("/api/x");
    ntc_mw_result r;
    ASSERT_TRUE(ntc_mw_before(m, &req, "1.2.3.4", 1000, &r));
    ASSERT_EQ_INT(204, r.status);
    ASSERT_TRUE(strstr(r.extra_headers, "Access-Control-Allow-Origin: *") != NULL);
    ntc_mw_free(m);
}

TEST(middleware, request_id_added) {
    ntc_mw_config cfg = { 0 };
    cfg.request_id = true;
    ntc_mw *m = ntc_mw_new(&cfg);
    ntc_request req; memset(&req, 0, sizeof req);
    req.method = NTC_SLICE_LIT("GET"); req.path = NTC_SLICE_LIT("/");
    ntc_mw_result r;
    ASSERT_FALSE(ntc_mw_before(m, &req, "1.2.3.4", 1000, &r));
    ASSERT_TRUE(strlen(r.request_id) > 0);
    ASSERT_TRUE(strstr(r.extra_headers, "X-Request-Id:") != NULL);
    ntc_mw_free(m);
}

TEST(middleware, rate_limit_blocks_burst) {
    ntc_mw_config cfg = { 0 };
    cfg.rate_per_sec = 2; cfg.rate_burst = 2;
    ntc_mw *m = ntc_mw_new(&cfg);
    ntc_request req; memset(&req, 0, sizeof req);
    req.method = NTC_SLICE_LIT("GET"); req.path = NTC_SLICE_LIT("/");
    ntc_mw_result r;
    ASSERT_FALSE(ntc_mw_before(m, &req, "9.9.9.9", 1000, &r)); /* 1 */
    ASSERT_FALSE(ntc_mw_before(m, &req, "9.9.9.9", 1000, &r)); /* 2 */
    ASSERT_TRUE(ntc_mw_before(m, &req, "9.9.9.9", 1000, &r));  /* 3 -> 429 */
    ASSERT_EQ_INT(429, r.status);
    ntc_mw_free(m);
}
#endif /* UNIT_TEST */
