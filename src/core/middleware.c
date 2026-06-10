#define _GNU_SOURCE
#include "ntc/middleware.h"
#include "ntc/crypto.h"
#include "ntc/https_client.h"
#include "ntc/jwt.h"
#include "ntc/log.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NTC_RL_BUCKETS 1024
#define NTC_JWKS_MIN_REFRESH_MS 60000 /* at most one live refresh per minute */
#define NTC_JWKS_FETCH_TIMEOUT_MS 4000

struct ntc_mw {
    ntc_mw_config cfg;
    ntc_jwks jwks;                      /* parsed signing keys (RS256/ES256) */
    ntc_ca *jwks_ca;                    /* trust anchors for the JWKS URL */
    long jwks_last_fetch_ms;            /* monotonic ms of last live fetch (0=never) */
    ntc_bucket buckets[NTC_RL_BUCKETS]; /* keyed by hash(client_ip) */
};

static long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

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

/* Fetch the live JWKS over HTTPS and replace the key set on success. Bounded and
 * blocking - meant for startup and rare key-rotation refresh (see PROBLEMS.md). */
static bool mw_fetch_jwks(ntc_mw *m) {
    if (!m->cfg.auth_jwks_url[0] || !m->jwks_ca) return false;
    m->jwks_last_fetch_ms = mono_ms();
    char *doc = malloc(64 * 1024);
    if (!doc) return false;
    char err[80];
    int n = ntc_https_get(m->jwks_ca, m->cfg.auth_jwks_url, doc, 64 * 1024,
                          NTC_JWKS_FETCH_TIMEOUT_MS, err, sizeof err);
    bool ok = false;
    if (n > 0) {
        ntc_jwks fresh;
        if (ntc_jwks_parse(doc, (size_t)n, &fresh)) {
            m->jwks = fresh;
            NTC_INFO("auth: fetched %zu key(s) from %s", fresh.count, m->cfg.auth_jwks_url);
            ok = true;
        } else {
            NTC_WARN("auth: JWKS from %s did not parse", m->cfg.auth_jwks_url);
        }
    } else {
        NTC_WARN("auth: JWKS fetch from %s failed: %s", m->cfg.auth_jwks_url, err);
    }
    free(doc);
    return ok;
}

/* Refresh on an unknown-kid token, but no more than once per min-interval (so a
 * flood of forged kids cannot trigger a fetch storm on the event loop). */
static void mw_maybe_refresh(ntc_mw *m) {
    if (!m->cfg.auth_jwks_url[0] || !m->jwks_ca) return;
    long now = mono_ms();
    if (m->jwks_last_fetch_ms != 0 && now - m->jwks_last_fetch_ms < NTC_JWKS_MIN_REFRESH_MS) return;
    (void)mw_fetch_jwks(m);
}

ntc_mw *ntc_mw_new(const ntc_mw_config *cfg) {
    ntc_mw *m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->cfg = *cfg;
    if (m->cfg.auth_jwks_file[0]) {
        char doc[16384];
        long n = slurp_file(m->cfg.auth_jwks_file, doc, sizeof doc);
        if (n > 0 && ntc_jwks_parse(doc, (size_t)n, &m->jwks))
            NTC_INFO("auth: loaded %zu key(s) from %s", m->jwks.count, m->cfg.auth_jwks_file);
        else
            NTC_WARN("auth: could not load JWKS '%s'; RS256/ES256 tokens will be rejected",
                     m->cfg.auth_jwks_file);
    } else if (m->cfg.auth_jwks_url[0]) {
        m->jwks_ca = m->cfg.auth_jwks_ca[0] ? ntc_ca_load_pem(m->cfg.auth_jwks_ca)
                                            : ntc_ca_default();
        if (!m->jwks_ca)
            NTC_WARN("auth: no CA roots for JWKS URL (set auth.jwks_ca); fetch will fail closed");
        if (!mw_fetch_jwks(m)) /* prime the cache at startup, off the hot path */
            NTC_WARN("auth: initial JWKS fetch from %s failed; will retry on demand",
                     m->cfg.auth_jwks_url);
    }
    return m;
}
void ntc_mw_free(ntc_mw *m) {
    if (!m) return;
    ntc_ca_free(m->jwks_ca);
    free(m);
}

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
                     * RS256/ES256 -> the JWKS key selected by kid. */
                    ntc_jwt_claims cl;
                    char alg[16], kid[80];
                    if (ntc_jwt_peek_header(tok.ptr, tok.len, alg, sizeof alg, kid, sizeof kid)) {
                        if (strcmp(alg, "RS256") == 0 || strcmp(alg, "ES256") == 0) {
                            /* live IdPs rotate keys: if we fetch from a URL and the
                             * kid is unknown, refresh once (rate-limited) then retry. */
                            if (m->cfg.auth_jwks_url[0] && !ntc_jwks_find(&m->jwks, kid, alg))
                                mw_maybe_refresh(m);
                            if (m->jwks.count)
                                ok = ntc_jwt_verify_jwks(tok.ptr, tok.len, &m->jwks, time(NULL), &cl);
                        } else if (strcmp(alg, "HS256") == 0 && m->cfg.auth_secret[0]) {
                            ok = ntc_jwt_verify_hs256(tok.ptr, tok.len, m->cfg.auth_secret, time(NULL), &cl);
                        }
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
