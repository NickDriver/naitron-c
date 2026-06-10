#define _GNU_SOURCE
#include "ntc/session.h"
#include "ntc/crypto.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- in-memory TTL key/value store (fixed array, linear scan) ---- */

#define NTC_KV_KEYLEN 96
#define NTC_KV_VALLEN 1024

typedef struct {
    char key[NTC_KV_KEYLEN];
    char val[NTC_KV_VALLEN];
    long expiry; /* unix seconds; 0 = empty slot */
} kv_entry;

struct ntc_kvstore {
    kv_entry *e;
    size_t cap;
};

ntc_kvstore *ntc_kv_new(size_t cap) {
    if (cap == 0) cap = 1024;
    ntc_kvstore *kv = calloc(1, sizeof *kv);
    if (!kv) return NULL;
    kv->e = calloc(cap, sizeof(kv_entry));
    if (!kv->e) { free(kv); return NULL; }
    kv->cap = cap;
    return kv;
}

void ntc_kv_free(ntc_kvstore *kv) {
    if (!kv) return;
    free(kv->e);
    free(kv);
}

static kv_entry *kv_find(ntc_kvstore *kv, const char *key) {
    for (size_t i = 0; i < kv->cap; i++)
        if (kv->e[i].expiry != 0 && strcmp(kv->e[i].key, key) == 0) return &kv->e[i];
    return NULL;
}

void ntc_kv_put(ntc_kvstore *kv, const char *key, const char *val, long expiry) {
    if (!kv || !key || strlen(key) >= NTC_KV_KEYLEN || !val || strlen(val) >= NTC_KV_VALLEN) return;
    kv_entry *slot = kv_find(kv, key);
    if (!slot) {
        /* first empty slot, else the soonest-to-expire (eviction) */
        kv_entry *victim = NULL;
        for (size_t i = 0; i < kv->cap; i++) {
            if (kv->e[i].expiry == 0) { slot = &kv->e[i]; break; }
            if (!victim || kv->e[i].expiry < victim->expiry) victim = &kv->e[i];
        }
        if (!slot) slot = victim;
    }
    if (!slot) return;
    snprintf(slot->key, sizeof slot->key, "%s", key);
    snprintf(slot->val, sizeof slot->val, "%s", val);
    slot->expiry = expiry ? expiry : 1; /* never store 0 (the empty marker) */
}

bool ntc_kv_get(ntc_kvstore *kv, const char *key, long now, char *out, size_t cap) {
    if (!kv) return false;
    kv_entry *slot = kv_find(kv, key);
    if (!slot) return false;
    if (now > 0 && slot->expiry <= now) { slot->expiry = 0; return false; } /* expired -> reap */
    snprintf(out, cap, "%s", slot->val);
    return true;
}

void ntc_kv_del(ntc_kvstore *kv, const char *key) {
    if (!kv) return;
    kv_entry *slot = kv_find(kv, key);
    if (slot) { slot->expiry = 0; slot->key[0] = '\0'; slot->val[0] = '\0'; }
}

/* ---- cookies ---- */

bool ntc_cookie_get(const char *cookie_header, const char *name, char *out, size_t cap) {
    if (!cookie_header || !name) return false;
    size_t nlen = strlen(name);
    const char *p = cookie_header;
    while (*p) {
        while (*p == ' ' || *p == ';') p++;
        if (strncmp(p, name, nlen) == 0 && p[nlen] == '=') {
            const char *v = p + nlen + 1;
            const char *end = v;
            while (*end && *end != ';') end++;
            size_t vl = (size_t)(end - v);
            if (vl >= cap) vl = cap - 1;
            memcpy(out, v, vl);
            out[vl] = '\0';
            return true;
        }
        while (*p && *p != ';') p++;
    }
    return false;
}

int ntc_cookie_format(char *out, size_t cap, const char *name, const char *value,
                      bool secure, long max_age) {
    int n = snprintf(out, cap, "%s=%s; Path=/; HttpOnly; SameSite=Lax%s",
                     name, value, secure ? "; Secure" : "");
    if (n < 0 || (size_t)n >= cap) return -1;
    if (max_age >= 0)
        n += snprintf(out + n, cap - (size_t)n, "; Max-Age=%ld", max_age);
    return n;
}

/* ---- random + PKCE ---- */

static bool fill_random(unsigned char *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) { close(fd); return false; }
        got += (size_t)r;
    }
    close(fd);
    return true;
}

bool ntc_random_token(char *out, size_t cap, size_t nbytes) {
    if (nbytes > 64 || cap < nbytes * 2 + 1) return false;
    unsigned char b[64];
    if (!fill_random(b, nbytes)) return false;
    for (size_t i = 0; i < nbytes; i++) snprintf(out + 2 * i, cap - 2 * i, "%02x", b[i]);
    return true;
}

bool ntc_pkce_verifier(char *out, size_t cap) {
    unsigned char b[32];
    if (cap < 44 || !fill_random(b, sizeof b)) return false;
    int n = ntc_base64url_encode(b, sizeof b, out, cap);
    return n > 0;
}

bool ntc_pkce_challenge(const char *verifier, char *out, size_t cap) {
    if (!verifier || cap < 44) return false;
    uint8_t h[32];
    ntc_sha256((const uint8_t *)verifier, strlen(verifier), h);
    int n = ntc_base64url_encode(h, sizeof h, out, cap);
    return n > 0;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(session, kv_put_get_del_expire) {
    ntc_kvstore *kv = ntc_kv_new(8);
    ASSERT_NOT_NULL(kv);
    ntc_kv_put(kv, "sid1", "alice\tread", 2000);
    char out[64];
    ASSERT_TRUE(ntc_kv_get(kv, "sid1", 1000, out, sizeof out));
    ASSERT_TRUE(strcmp(out, "alice\tread") == 0);
    /* expired relative to now=3000 */
    ASSERT_FALSE(ntc_kv_get(kv, "sid1", 3000, out, sizeof out));
    /* overwrite + delete */
    ntc_kv_put(kv, "sid2", "bob", 5000);
    ntc_kv_put(kv, "sid2", "bob2", 5000);
    ASSERT_TRUE(ntc_kv_get(kv, "sid2", 1000, out, sizeof out));
    ASSERT_TRUE(strcmp(out, "bob2") == 0);
    ntc_kv_del(kv, "sid2");
    ASSERT_FALSE(ntc_kv_get(kv, "sid2", 1000, out, sizeof out));
    ntc_kv_free(kv);
}

TEST(session, kv_evicts_when_full) {
    ntc_kvstore *kv = ntc_kv_new(2);
    ntc_kv_put(kv, "a", "1", 1000); /* soonest expiry */
    ntc_kv_put(kv, "b", "2", 2000);
    ntc_kv_put(kv, "c", "3", 3000); /* evicts "a" */
    char out[16];
    ASSERT_FALSE(ntc_kv_get(kv, "a", 500, out, sizeof out));
    ASSERT_TRUE(ntc_kv_get(kv, "b", 500, out, sizeof out));
    ASSERT_TRUE(ntc_kv_get(kv, "c", 500, out, sizeof out));
    ntc_kv_free(kv);
}

TEST(session, cookie_parse) {
    char out[64];
    ASSERT_TRUE(ntc_cookie_get("ntc_session=abc123; other=x", "ntc_session", out, sizeof out));
    ASSERT_TRUE(strcmp(out, "abc123") == 0);
    ASSERT_TRUE(ntc_cookie_get("a=1; ntc_session=zzz", "ntc_session", out, sizeof out));
    ASSERT_TRUE(strcmp(out, "zzz") == 0);
    ASSERT_FALSE(ntc_cookie_get("a=1; b=2", "ntc_session", out, sizeof out));
    /* prefix must not false-match */
    ASSERT_FALSE(ntc_cookie_get("ntc_session_x=1", "ntc_session", out, sizeof out));
}

TEST(session, cookie_format) {
    char out[256];
    int n = ntc_cookie_format(out, sizeof out, "ntc_session", "abc", true, 3600);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(out, "ntc_session=abc") != NULL);
    ASSERT_TRUE(strstr(out, "HttpOnly") != NULL);
    ASSERT_TRUE(strstr(out, "SameSite=Lax") != NULL);
    ASSERT_TRUE(strstr(out, "Secure") != NULL);
    ASSERT_TRUE(strstr(out, "Max-Age=3600") != NULL);
    /* not secure, session cookie (no Max-Age) */
    n = ntc_cookie_format(out, sizeof out, "s", "v", false, -1);
    ASSERT_TRUE(strstr(out, "Secure") == NULL);
    ASSERT_TRUE(strstr(out, "Max-Age") == NULL);
}

TEST(session, pkce_s256_rfc_vector) {
    /* RFC 7636 Appendix B */
    const char *verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    char ch[64];
    ASSERT_TRUE(ntc_pkce_challenge(verifier, ch, sizeof ch));
    ASSERT_TRUE(strcmp(ch, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM") == 0);
}

TEST(session, pkce_verifier_and_token_random) {
    char v1[64], v2[64];
    ASSERT_TRUE(ntc_pkce_verifier(v1, sizeof v1));
    ASSERT_TRUE(ntc_pkce_verifier(v2, sizeof v2));
    ASSERT_TRUE(strcmp(v1, v2) != 0);      /* high entropy: distinct */
    ASSERT_EQ_INT(43, (int)strlen(v1));    /* 32 bytes base64url, no pad */
    char tok[40];
    ASSERT_TRUE(ntc_random_token(tok, sizeof tok, 16));
    ASSERT_EQ_INT(32, (int)strlen(tok));
}
#endif /* UNIT_TEST */
