#include "ntc/jwt.h"

#include "ntc/arena.h"
#include "ntc/crypto.h"
#include "ntc/json.h"
#include "ntc/slice.h"

#include "bearssl.h"

#include <stdio.h>
#include <string.h>

/* The three base64url segments of a compact JWS. `signed_len` spans
 * "header.payload" (the bytes the signature covers). */
typedef struct {
    const char *h;   size_t hlen;
    const char *p;   size_t plen;
    const char *sig; size_t siglen;
    size_t signed_len;
} jwt_parts;

static bool jwt_split(const char *token, size_t len, jwt_parts *out) {
    if (!token) return false;
    const char *d1 = memchr(token, '.', len);
    if (!d1) return false;
    size_t after1 = (size_t)(d1 + 1 - token);
    const char *d2 = memchr(d1 + 1, '.', len - after1);
    if (!d2) return false;
    out->h = token;            out->hlen = (size_t)(d1 - token);
    out->p = d1 + 1;           out->plen = (size_t)(d2 - (d1 + 1));
    out->sig = d2 + 1;         out->siglen = len - (size_t)(d2 + 1 - token);
    out->signed_len = (size_t)(d2 - token);
    return true;
}

/* After the signature is verified, validate the header alg and pull claims out
 * of the payload. Shared by both HS256 and RS256. */
static bool jwt_parse_claims(const jwt_parts *jp, const char *expect_alg,
                             long now_unix, ntc_jwt_claims *out) {
    ntc_arena a;
    if (ntc_arena_init(&a, 8192) != NTC_OK) return false;
    bool ok = false;

    uint8_t hbuf[1024];
    int hn = ntc_base64url_decode(jp->h, jp->hlen, hbuf, sizeof hbuf);
    if (hn > 0) {
        ntc_json *hj = ntc_json_parse(&a, (char *)hbuf, (size_t)hn);
        if (hj && ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(hj, "alg")), expect_alg)) {
            uint8_t pbuf[4096];
            int pn = ntc_base64url_decode(jp->p, jp->plen, pbuf, sizeof pbuf);
            if (pn > 0) {
                ntc_json *pj = ntc_json_parse(&a, (char *)pbuf, (size_t)pn);
                if (pj && pj->type == NTC_JSON_OBJ) {
                    long exp = (long)ntc_json_num(ntc_json_get(pj, "exp"));
                    if (!(exp && now_unix > 0 && now_unix >= exp)) { /* not expired */
                        ntc_slice sub = ntc_json_str(ntc_json_get(pj, "sub"));
                        ntc_slice scope = ntc_json_str(ntc_json_get(pj, "scope"));
                        snprintf(out->sub, sizeof out->sub, "%.*s", (int)sub.len, sub.ptr);
                        snprintf(out->scope, sizeof out->scope, "%.*s", (int)scope.len, scope.ptr);
                        out->exp = exp;
                        out->iat = (long)ntc_json_num(ntc_json_get(pj, "iat"));
                        ok = true;
                    }
                }
            }
        }
    }
    ntc_arena_destroy(&a);
    return ok;
}

bool ntc_jwt_peek_alg(const char *token, size_t len, char *out, size_t cap) {
    if (out && cap) out[0] = '\0';
    jwt_parts jp;
    if (!jwt_split(token, len, &jp)) return false;
    uint8_t hbuf[1024];
    int hn = ntc_base64url_decode(jp.h, jp.hlen, hbuf, sizeof hbuf);
    if (hn <= 0) return false;
    ntc_arena a;
    if (ntc_arena_init(&a, 4096) != NTC_OK) return false;
    bool ok = false;
    ntc_json *hj = ntc_json_parse(&a, (char *)hbuf, (size_t)hn);
    if (hj) {
        ntc_slice alg = ntc_json_str(ntc_json_get(hj, "alg"));
        if (alg.len && alg.len < cap) {
            snprintf(out, cap, "%.*s", (int)alg.len, alg.ptr);
            ok = true;
        }
    }
    ntc_arena_destroy(&a);
    return ok;
}

bool ntc_jwt_peek_header(const char *token, size_t len,
                         char *alg, size_t algcap, char *kid, size_t kidcap) {
    if (alg && algcap) alg[0] = '\0';
    if (kid && kidcap) kid[0] = '\0';
    jwt_parts jp;
    if (!jwt_split(token, len, &jp)) return false;
    uint8_t hbuf[1024];
    int hn = ntc_base64url_decode(jp.h, jp.hlen, hbuf, sizeof hbuf);
    if (hn <= 0) return false;
    ntc_arena a;
    if (ntc_arena_init(&a, 4096) != NTC_OK) return false;
    bool ok = false;
    ntc_json *hj = ntc_json_parse(&a, (char *)hbuf, (size_t)hn);
    if (hj) {
        ntc_slice av = ntc_json_str(ntc_json_get(hj, "alg"));
        if (av.len && av.len < algcap) {
            snprintf(alg, algcap, "%.*s", (int)av.len, av.ptr);
            ok = true;
            ntc_slice kv = ntc_json_str(ntc_json_get(hj, "kid"));
            if (kid && kv.len && kv.len < kidcap)
                snprintf(kid, kidcap, "%.*s", (int)kv.len, kv.ptr);
        }
    }
    ntc_arena_destroy(&a);
    return ok;
}

bool ntc_jwt_verify_hs256(const char *token, size_t len, const char *secret,
                          long now_unix, ntc_jwt_claims *out) {
    memset(out, 0, sizeof *out);
    if (!token || !secret) return false;
    jwt_parts jp;
    if (!jwt_split(token, len, &jp)) return false;

    uint8_t mac[32];
    ntc_hmac_sha256((const uint8_t *)secret, strlen(secret),
                    (const uint8_t *)token, jp.signed_len, mac);
    char macb64[64];
    int mn = ntc_base64url_encode(mac, 32, macb64, sizeof macb64);
    if (mn < 0 || (size_t)mn != jp.siglen) return false;
    if (!ntc_ct_eq((const uint8_t *)macb64, (const uint8_t *)jp.sig, jp.siglen)) return false;

    return jwt_parse_claims(&jp, "HS256", now_unix, out);
}

bool ntc_jwt_verify_rs256(const char *token, size_t len,
                          const ntc_rsa_pubkey *key, long now_unix,
                          ntc_jwt_claims *out) {
    memset(out, 0, sizeof *out);
    if (!token || !key || !key->present) return false;
    jwt_parts jp;
    if (!jwt_split(token, len, &jp)) return false;

    unsigned char sig[512];
    int sn = ntc_base64url_decode(jp.sig, jp.siglen, sig, sizeof sig);
    if (sn <= 0) return false;

    uint8_t hash[32];
    ntc_sha256((const uint8_t *)token, jp.signed_len, hash);

    br_rsa_public_key pk;
    pk.n = (unsigned char *)key->n; pk.nlen = key->nlen;
    pk.e = (unsigned char *)key->e; pk.elen = key->elen;

    /* PKCS#1 v1.5: recover the DigestInfo-embedded hash, then compare it
     * (constant-time) against the SHA-256 we computed over header.payload. */
    unsigned char hout[32];
    if (br_rsa_i31_pkcs1_vrfy(sig, (size_t)sn, BR_HASH_OID_SHA256, sizeof hout,
                              &pk, hout) != 1)
        return false;
    if (!ntc_ct_eq(hout, hash, sizeof hout)) return false;

    return jwt_parse_claims(&jp, "RS256", now_unix, out);
}

bool ntc_jwt_verify_es256(const char *token, size_t len,
                          const unsigned char *q, size_t qlen, long now_unix,
                          ntc_jwt_claims *out) {
    memset(out, 0, sizeof *out);
    if (!token || !q || qlen == 0) return false;
    jwt_parts jp;
    if (!jwt_split(token, len, &jp)) return false;

    /* A JWS ES256 signature is the raw concatenation r||s, 32 bytes each. */
    unsigned char sig[160];
    int sn = ntc_base64url_decode(jp.sig, jp.siglen, sig, sizeof sig);
    if (sn != 64) return false;

    uint8_t hash[32];
    ntc_sha256((const uint8_t *)token, jp.signed_len, hash);

    br_ec_public_key pk;
    pk.curve = BR_EC_secp256r1;
    pk.q = (unsigned char *)q;
    pk.qlen = qlen;
    const br_ec_impl *ec = br_ec_get_default();
    if (br_ecdsa_i31_vrfy_raw(ec, hash, sizeof hash, &pk, sig, (size_t)sn) != 1)
        return false;

    return jwt_parse_claims(&jp, "ES256", now_unix, out);
}

/* Decode one base64url JWK member into a fixed buffer. Returns bytes or -1.
 * Leading zero bytes are stripped (BearSSL accepts them, but keep it tidy). */
static int jwk_b64u_field(const ntc_json *obj, const char *name,
                          unsigned char *out, size_t cap) {
    ntc_slice s = ntc_json_str(ntc_json_get(obj, name));
    if (!s.len) return -1;
    int n = ntc_base64url_decode(s.ptr, s.len, out, cap);
    if (n <= 0) return -1;
    int z = 0;
    while (z < n - 1 && out[z] == 0) z++;
    if (z) { memmove(out, out + z, (size_t)(n - z)); n -= z; }
    return n;
}

static bool jwk_load_rsa(const ntc_json *jwk, ntc_rsa_pubkey *out) {
    if (!jwk || jwk->type != NTC_JSON_OBJ) return false;
    if (!ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(jwk, "kty")), "RSA")) return false;
    int nn = jwk_b64u_field(jwk, "n", out->n, sizeof out->n);
    int en = jwk_b64u_field(jwk, "e", out->e, sizeof out->e);
    if (nn <= 0 || en <= 0) return false;
    out->nlen = (size_t)nn;
    out->elen = (size_t)en;
    out->present = true;
    return true;
}

bool ntc_jwk_parse(const char *json, size_t len, ntc_rsa_pubkey *out) {
    memset(out, 0, sizeof *out);
    if (!json) return false;
    ntc_arena a;
    if (ntc_arena_init(&a, 16384) != NTC_OK) return false;
    bool ok = false;
    ntc_json *root = ntc_json_parse(&a, json, len);
    if (root) {
        const ntc_json *keys = ntc_json_get(root, "keys");
        if (keys && keys->type == NTC_JSON_ARR) {
            for (size_t i = 0; i < keys->count && !ok; i++)
                ok = jwk_load_rsa(keys->items[i], out);
        } else {
            ok = jwk_load_rsa(root, out); /* a single bare JWK */
        }
    }
    ntc_arena_destroy(&a);
    return ok;
}

/* ---- multi-key JWKS (RSA + EC), selectable by kid ---- */

/* Decode an EC coordinate (x or y) into exactly 32 left-padded bytes. JWK
 * coordinates are fixed-width, so (unlike RSA fields) we must NOT strip leading
 * zeros - we left-pad instead. Returns true on success. */
static bool jwk_ec_coord(const ntc_json *jwk, const char *name, unsigned char out[32]) {
    ntc_slice s = ntc_json_str(ntc_json_get(jwk, name));
    if (!s.len) return false;
    unsigned char tmp[48];
    int n = ntc_base64url_decode(s.ptr, s.len, tmp, sizeof tmp);
    if (n <= 0 || n > 32) return false;
    memset(out, 0, 32);
    memcpy(out + (32 - n), tmp, (size_t)n);
    return true;
}

/* Parse one JWK object into a generic key (RSA or EC P-256). Captures kid/alg. */
static bool jwk_load_one(const ntc_json *jwk, ntc_jwk_key *out) {
    if (!jwk || jwk->type != NTC_JSON_OBJ) return false;
    memset(out, 0, sizeof *out);
    ntc_slice kty = ntc_json_str(ntc_json_get(jwk, "kty"));
    ntc_slice kid = ntc_json_str(ntc_json_get(jwk, "kid"));
    ntc_slice alg = ntc_json_str(ntc_json_get(jwk, "alg"));
    if (kid.len && kid.len < sizeof out->kid) snprintf(out->kid, sizeof out->kid, "%.*s", (int)kid.len, kid.ptr);
    if (alg.len && alg.len < sizeof out->alg) snprintf(out->alg, sizeof out->alg, "%.*s", (int)alg.len, alg.ptr);

    if (ntc_slice_eq_cstr(kty, "RSA")) {
        int nn = jwk_b64u_field(jwk, "n", out->n, sizeof out->n);
        int en = jwk_b64u_field(jwk, "e", out->e, sizeof out->e);
        if (nn <= 0 || en <= 0) return false;
        out->nlen = (size_t)nn;
        out->elen = (size_t)en;
        out->kty = NTC_JWK_RSA;
        return true;
    }
    if (ntc_slice_eq_cstr(kty, "EC")) {
        /* only P-256 (ES256) is supported */
        if (!ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(jwk, "crv")), "P-256")) return false;
        out->q[0] = 0x04; /* uncompressed point */
        if (!jwk_ec_coord(jwk, "x", out->q + 1) || !jwk_ec_coord(jwk, "y", out->q + 33)) return false;
        out->qlen = 65;
        out->kty = NTC_JWK_EC;
        return true;
    }
    return false; /* unsupported kty (OKP, oct, ...) */
}

bool ntc_jwks_parse(const char *json, size_t len, ntc_jwks *out) {
    memset(out, 0, sizeof *out);
    if (!json) return false;
    ntc_arena a;
    if (ntc_arena_init(&a, 16384) != NTC_OK) return false;
    ntc_json *root = ntc_json_parse(&a, json, len);
    if (root) {
        const ntc_json *keys = ntc_json_get(root, "keys");
        if (keys && keys->type == NTC_JSON_ARR) {
            for (size_t i = 0; i < keys->count && out->count < NTC_JWKS_MAX_KEYS; i++)
                if (jwk_load_one(keys->items[i], &out->keys[out->count])) out->count++;
        } else if (jwk_load_one(root, &out->keys[0])) {
            out->count = 1; /* a single bare JWK */
        }
    }
    ntc_arena_destroy(&a);
    return out->count > 0;
}

const ntc_jwk_key *ntc_jwks_find(const ntc_jwks *set, const char *kid,
                                 const char *alg) {
    if (!set || set->count == 0) return NULL;
    int want = -1; /* required kty, or -1 = any */
    if (alg) {
        if (strcmp(alg, "RS256") == 0) want = NTC_JWK_RSA;
        else if (strcmp(alg, "ES256") == 0) want = NTC_JWK_EC;
    }
    bool havekid = kid && kid[0];
    const ntc_jwk_key *fallback = NULL;
    for (size_t i = 0; i < set->count; i++) {
        const ntc_jwk_key *k = &set->keys[i];
        if (want >= 0 && (int)k->kty != want) continue;
        if (havekid) {
            if (strcmp(k->kid, kid) == 0) return k; /* exact kid wins */
        } else if (!fallback) {
            fallback = k; /* first kty-compatible key */
        }
    }
    return havekid ? NULL : fallback;
}

bool ntc_jwt_verify_jwks(const char *token, size_t len, const ntc_jwks *set,
                         long now_unix, ntc_jwt_claims *out) {
    memset(out, 0, sizeof *out);
    if (!set) return false;
    char alg[16], kid[80];
    if (!ntc_jwt_peek_header(token, len, alg, sizeof alg, kid, sizeof kid)) return false;
    const ntc_jwk_key *k = ntc_jwks_find(set, kid, alg);
    if (!k) return false;

    if (strcmp(alg, "RS256") == 0 && k->kty == NTC_JWK_RSA) {
        ntc_rsa_pubkey rk;
        memset(&rk, 0, sizeof rk);
        memcpy(rk.n, k->n, k->nlen); rk.nlen = k->nlen;
        memcpy(rk.e, k->e, k->elen); rk.elen = k->elen;
        rk.present = true;
        return ntc_jwt_verify_rs256(token, len, &rk, now_unix, out);
    }
    if (strcmp(alg, "ES256") == 0 && k->kty == NTC_JWK_EC)
        return ntc_jwt_verify_es256(token, len, k->q, k->qlen, now_unix, out);
    return false;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(jwt, verifies_valid_hs256) {
    /* canonical jwt.io HS256 example, secret "your-256-bit-secret" */
    const char *tok =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    ntc_jwt_claims c;
    ASSERT_TRUE(ntc_jwt_verify_hs256(tok, strlen(tok), "your-256-bit-secret", 0, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.sub), "1234567890"));
}

TEST(jwt, rejects_wrong_secret) {
    const char *tok =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    ntc_jwt_claims c;
    ASSERT_FALSE(ntc_jwt_verify_hs256(tok, strlen(tok), "wrong-secret", 0, &c));
}

TEST(jwt, rejects_malformed) {
    ntc_jwt_claims c;
    ASSERT_FALSE(ntc_jwt_verify_hs256("not.a.jwt", 9, "secret", 0, &c));
    ASSERT_FALSE(ntc_jwt_verify_hs256("nodots", 6, "secret", 0, &c));
}

TEST(jwt, peek_alg) {
    const char *hs =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.x";
    char alg[16];
    ASSERT_TRUE(ntc_jwt_peek_alg(hs, strlen(hs), alg, sizeof alg));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(alg), "HS256"));
    ASSERT_FALSE(ntc_jwt_peek_alg("garbage", 7, alg, sizeof alg));
}

/* Fixed RS256 vector: RSA-2048 key (as a JWK Set), signing a token whose exp is
 * the year 2100. Generated with openssl; the matching private key is discarded.
 * See tests/vectors/rs256.* for the same material as files. */
static const char *RS256_JWKS =
    "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"test-1\",\"alg\":\"RS256\","
    "\"n\":\"kkdM1hrDB6nn77FWTltnsvWV5FgSvg_Xzd-Ymb0uaenkErqaaD1EKVT1ohGOJTqsZ_KcMOlHD_9"
    "Kq0tbO-WVpBL6rT8zG0PxNV3RDwbF4Ljhx51Sm8DtquXPQRh4uogXpKHglQr450yYBMYsvxUblMq3Is-hQH"
    "ePBtOcooOXjHK970S1L8Of-tFxwh3gkkmCtUvWIEPBsWts-JWm7t32_wohsmpSJM5GrU9XIpYK_0PEqAW3f"
    "Wyxklug-pxFKeVsH_um9GtsEVB0IFzQbfhadvNvgn2jD-h3kKuuZCbtBhUZDlFrIljANWU8oBUhwCwwaChf"
    "fwXxAC2iAhVipCSFeQ\",\"e\":\"AQAB\"}]}";
static const char *RS256_TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyczI1Ni11c2VyIiwic2NvcGUiOiJyZWFkIH"
    "dyaXRlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9.bdIpNH5kIMXWU0fo-9iLeCn2qQOh"
    "yQh-lhePWNihrNpL4fOLHsEgcXP939b0yboqm3wRWQXYtr9hFKXAEOfANO0fg4z9HDFISPXTjBaWvdSe40q"
    "LSwVkhhgdORnxK-XKglfG7IE105MzyFr1sYMB0FHYmwBaveg5UlNKT3tUL4pD6oxN-lYFI_SBI9f3lpPubQ"
    "kVa-PS59KZ26PSe6hMGcYqQerIVBhs7YZsMYpukRgFHwcF4MDg-ozNOxsR7jm5jpHH6Fkh1WSPrpko1giLN"
    "-ecC4F17IGkmZTqLlVf1RGjJxOBIHRpsgPdrAi9sjy9NzDNguhfrg_zEE6MZr4e0g";

TEST(jwt, parses_jwks) {
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(RS256_JWKS, strlen(RS256_JWKS), &k));
    ASSERT_TRUE(k.present);
    ASSERT_EQ_INT(256, (int)k.nlen); /* RSA-2048 modulus */
    ASSERT_EQ_INT(3, (int)k.elen);   /* 65537 = 0x010001 */
}

TEST(jwt, verifies_valid_rs256) {
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(RS256_JWKS, strlen(RS256_JWKS), &k));
    ntc_jwt_claims c;
    ASSERT_TRUE(ntc_jwt_verify_rs256(RS256_TOKEN, strlen(RS256_TOKEN), &k, 1700000001, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.sub), "rs256-user"));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.scope), "read write"));
}

TEST(jwt, rs256_rejects_tampered_payload) {
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(RS256_JWKS, strlen(RS256_JWKS), &k));
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", RS256_TOKEN);
    /* flip a character in the payload segment (after the first dot) */
    char *dot = strchr(buf, '.');
    dot[3] = (dot[3] == 'a') ? 'b' : 'a';
    ntc_jwt_claims c;
    ASSERT_FALSE(ntc_jwt_verify_rs256(buf, strlen(buf), &k, 1700000001, &c));
}

TEST(jwt, rs256_rejects_wrong_key) {
    /* a different RSA key (same e, modulus with one bit different) must fail */
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(RS256_JWKS, strlen(RS256_JWKS), &k));
    k.n[0] ^= 0x01;
    ntc_jwt_claims c;
    ASSERT_FALSE(ntc_jwt_verify_rs256(RS256_TOKEN, strlen(RS256_TOKEN), &k, 1700000001, &c));
}

TEST(jwt, rs256_rejects_hs256_token) {
    /* an HS256 token must not verify as RS256 (alg mismatch) */
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(RS256_JWKS, strlen(RS256_JWKS), &k));
    const char *hs =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    ntc_jwt_claims c;
    ASSERT_FALSE(ntc_jwt_verify_rs256(hs, strlen(hs), &k, 0, &c));
}

TEST(jwt, rs256_rejects_expired) {
    /* the vector's exp is 4102444800 (year 2100); a `now` past it must reject,
     * but the signature itself is valid - so this isolates the exp check. */
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(RS256_JWKS, strlen(RS256_JWKS), &k));
    ntc_jwt_claims c;
    ASSERT_TRUE(ntc_jwt_verify_rs256(RS256_TOKEN, strlen(RS256_TOKEN), &k, 4102444799, &c));
    ASSERT_FALSE(ntc_jwt_verify_rs256(RS256_TOKEN, strlen(RS256_TOKEN), &k, 4102444801, &c));
}

/* Same 2048-bit key family, a token carrying NO exp claim. */
static const char *RS256_NOEXP_JWKS =
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k2\",\"alg\":\"RS256\","
    "\"n\":\"r3ticbYx7odSGvet5WsRULP9Bxv_R_HPb0T42VyhymP2dLyhVpA5WfzrmEh_E1469enjA1RNz7qK"
    "cY7ixP4zpgrjH1-ZpyEp9sC7kAhBIFwk_r3wEn4DSXh-xbhgf4vhjV0QLX1vaS6pIw8wzyiXMuydo_P0wcT3"
    "vW_whM_3R7BjnGlwu2SJjBnMc2CGfESWJcy6EVNXMxyUGEls1ePZrotLqWsanppH2Ok2BmeXiHpl0OwqbM3g"
    "QlMTNS4ro9_3PFk688M4tfI_iFP8IHulG1tDlbjMylcI_LEYeQZKsFl90hJZWyecVVieFycIyNSn55DlXYaW"
    "c_YVcmjxshoGrw\",\"e\":\"AQAB\"}]}";
static const char *RS256_NOEXP_TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJub2V4cC11c2VyIiwic2NvcGUiOiJ4In0."
    "D_J7jzZQljdwNN7OK4VaxtwIsmpC9R1RnMBdAi_RMGZ1y2FKiH_Lx4fH53444RSjP4NU-M3-rqbGdmcnJGKd"
    "Zy7bxZeWtkHsYOv7Pa2sxVKHSK91vNkoWl80MB5pYVtK2eUBsk74ed_NufohfwBFfmkI4e2q1hnVeVZZRkHp"
    "5P-HJOlUgBxdtHX34d3b5J1HtdWree5gitZWAjEwJpdibpFKjjbOrJ4uuXUKTNXAqVY6mBIaQxlo_kr9a7Zk"
    "CXRpJo4zCm6NfdBYImydx9W0a5RlCzhE6i2yQ4fWrN_wDWDWAnTXKflEfSDzX0BGNOALQmPJDEqeIPE7hhqs"
    "MRr_4w";

TEST(jwt, rs256_accepts_missing_exp) {
    /* a token with no exp must verify regardless of `now` (no expiry to enforce) */
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(RS256_NOEXP_JWKS, strlen(RS256_NOEXP_JWKS), &k));
    ntc_jwt_claims c;
    ASSERT_TRUE(ntc_jwt_verify_rs256(RS256_NOEXP_TOKEN, strlen(RS256_NOEXP_TOKEN), &k, 4102444801, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.sub), "noexp-user"));
}

TEST(jwt, jwk_skips_non_rsa_keys) {
    /* a JWK Set whose first entry is an EC key: we must skip it and use the RSA one */
    char doc[1200];
    snprintf(doc, sizeof doc,
        "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AAAA\",\"y\":\"BBBB\"},"
        "{\"kty\":\"RSA\",\"kid\":\"k2\",\"alg\":\"RS256\",\"n\":\"%s\",\"e\":\"AQAB\"}]}",
        "r3ticbYx7odSGvet5WsRULP9Bxv_R_HPb0T42VyhymP2dLyhVpA5WfzrmEh_E1469enjA1RNz7qK"
        "cY7ixP4zpgrjH1-ZpyEp9sC7kAhBIFwk_r3wEn4DSXh-xbhgf4vhjV0QLX1vaS6pIw8wzyiXMuydo_P0wcT3"
        "vW_whM_3R7BjnGlwu2SJjBnMc2CGfESWJcy6EVNXMxyUGEls1ePZrotLqWsanppH2Ok2BmeXiHpl0OwqbM3g"
        "QlMTNS4ro9_3PFk688M4tfI_iFP8IHulG1tDlbjMylcI_LEYeQZKsFl90hJZWyecVVieFycIyNSn55DlXYaW"
        "c_YVcmjxshoGrw");
    ntc_rsa_pubkey k;
    ASSERT_TRUE(ntc_jwk_parse(doc, strlen(doc), &k));
    ASSERT_TRUE(k.present);
    ASSERT_EQ_INT(256, (int)k.nlen);
    ntc_jwt_claims c;
    ASSERT_TRUE(ntc_jwt_verify_rs256(RS256_NOEXP_TOKEN, strlen(RS256_NOEXP_TOKEN), &k, 0, &c));
}

/* ---- ES256 (EC P-256) + multi-key JWKS, generated with node (tests/vectors). ---- */
static const char *ES256_JWKS =
    "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"ec-1\",\"alg\":\"ES256\",\"use\":\"sig\","
    "\"x\":\"vBaAgxRVjeJQInuZpk7iVl3fNd9TcZ84sMVk-s03INk\","
    "\"y\":\"EkyHZFU2N52GCvWGGF4Sgjdz8Oc550GV0sVVFthvI6Y\"}]}";
static const char *ES256_TOKEN =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVjLTEifQ."
    "eyJzdWIiOiJlczI1Ni11c2VyIiwic2NvcGUiOiJyZWFkIHdyaXRlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9."
    "zAadk8eRNEbmcORrtk0Dbms2eqL3ZV0eYq2qCUkyK4f1T9yUGee5gxM6lOQLEaJbzskGsMUbofXirDxAuSp_pA";

TEST(jwt, peek_header_alg_and_kid) {
    char alg[16], kid[80];
    ASSERT_TRUE(ntc_jwt_peek_header(ES256_TOKEN, strlen(ES256_TOKEN), alg, sizeof alg, kid, sizeof kid));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(alg), "ES256"));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(kid), "ec-1"));
    /* a token with no kid leaves kid empty but still finds alg */
    const char *hs = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.x";
    ASSERT_TRUE(ntc_jwt_peek_header(hs, strlen(hs), alg, sizeof alg, kid, sizeof kid));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(alg), "HS256"));
    ASSERT_EQ_INT(0, (int)strlen(kid));
}

TEST(jwt, parses_ec_jwk) {
    ntc_jwks set;
    ASSERT_TRUE(ntc_jwks_parse(ES256_JWKS, strlen(ES256_JWKS), &set));
    ASSERT_EQ_INT(1, (int)set.count);
    ASSERT_EQ_INT(NTC_JWK_EC, (int)set.keys[0].kty);
    ASSERT_EQ_INT(65, (int)set.keys[0].qlen);
    ASSERT_EQ_INT(0x04, (int)set.keys[0].q[0]); /* uncompressed point marker */
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(set.keys[0].kid), "ec-1"));
}

TEST(jwt, verifies_valid_es256) {
    ntc_jwks set;
    ASSERT_TRUE(ntc_jwks_parse(ES256_JWKS, strlen(ES256_JWKS), &set));
    const ntc_jwk_key *k = ntc_jwks_find(&set, "ec-1", "ES256");
    ASSERT_NOT_NULL(k);
    ntc_jwt_claims c;
    ASSERT_TRUE(ntc_jwt_verify_es256(ES256_TOKEN, strlen(ES256_TOKEN), k->q, k->qlen, 1700000001, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.sub), "es256-user"));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.scope), "read write"));
}

TEST(jwt, es256_rejects_tampered_and_wrong_key) {
    ntc_jwks set;
    ASSERT_TRUE(ntc_jwks_parse(ES256_JWKS, strlen(ES256_JWKS), &set));
    const ntc_jwk_key *k = &set.keys[0];
    ntc_jwt_claims c;
    /* flip a byte in the payload segment */
    char buf[512];
    snprintf(buf, sizeof buf, "%s", ES256_TOKEN);
    char *dot = strchr(buf, '.');
    dot[3] = (dot[3] == 'a') ? 'b' : 'a';
    ASSERT_FALSE(ntc_jwt_verify_es256(buf, strlen(buf), k->q, k->qlen, 1700000001, &c));
    /* corrupt the public point: must fail */
    unsigned char q2[65];
    memcpy(q2, k->q, 65);
    q2[10] ^= 0x01;
    ASSERT_FALSE(ntc_jwt_verify_es256(ES256_TOKEN, strlen(ES256_TOKEN), q2, 65, 1700000001, &c));
}

TEST(jwt, es256_rejects_expired) {
    ntc_jwks set;
    ASSERT_TRUE(ntc_jwks_parse(ES256_JWKS, strlen(ES256_JWKS), &set));
    const ntc_jwk_key *k = &set.keys[0];
    ntc_jwt_claims c;
    ASSERT_TRUE(ntc_jwt_verify_es256(ES256_TOKEN, strlen(ES256_TOKEN), k->q, k->qlen, 4102444799, &c));
    ASSERT_FALSE(ntc_jwt_verify_es256(ES256_TOKEN, strlen(ES256_TOKEN), k->q, k->qlen, 4102444801, &c));
}

/* A JWKS holding BOTH the RS256 key (kid test-1) and the ES256 key (kid ec-1).
 * verify_jwks must route each token to the right key by alg+kid. */
static const char *MULTI_JWKS =
    "{\"keys\":["
    "{\"kty\":\"RSA\",\"kid\":\"test-1\",\"alg\":\"RS256\","
    "\"n\":\"kkdM1hrDB6nn77FWTltnsvWV5FgSvg_Xzd-Ymb0uaenkErqaaD1EKVT1ohGOJTqsZ_KcMOlHD_9"
    "Kq0tbO-WVpBL6rT8zG0PxNV3RDwbF4Ljhx51Sm8DtquXPQRh4uogXpKHglQr450yYBMYsvxUblMq3Is-hQH"
    "ePBtOcooOXjHK970S1L8Of-tFxwh3gkkmCtUvWIEPBsWts-JWm7t32_wohsmpSJM5GrU9XIpYK_0PEqAW3f"
    "Wyxklug-pxFKeVsH_um9GtsEVB0IFzQbfhadvNvgn2jD-h3kKuuZCbtBhUZDlFrIljANWU8oBUhwCwwaChf"
    "fwXxAC2iAhVipCSFeQ\",\"e\":\"AQAB\"},"
    "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"ec-1\",\"alg\":\"ES256\","
    "\"x\":\"vBaAgxRVjeJQInuZpk7iVl3fNd9TcZ84sMVk-s03INk\","
    "\"y\":\"EkyHZFU2N52GCvWGGF4Sgjdz8Oc550GV0sVVFthvI6Y\"}]}";

TEST(jwt, verify_jwks_routes_by_alg_and_kid) {
    ntc_jwks set;
    ASSERT_TRUE(ntc_jwks_parse(MULTI_JWKS, strlen(MULTI_JWKS), &set));
    ASSERT_EQ_INT(2, (int)set.count);
    ntc_jwt_claims c;
    /* RS256 token -> RSA key (kid test-1) */
    ASSERT_TRUE(ntc_jwt_verify_jwks(RS256_TOKEN, strlen(RS256_TOKEN), &set, 1700000001, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.sub), "rs256-user"));
    /* ES256 token -> EC key (kid ec-1) */
    ASSERT_TRUE(ntc_jwt_verify_jwks(ES256_TOKEN, strlen(ES256_TOKEN), &set, 1700000001, &c));
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_slice_cstr(c.sub), "es256-user"));
}

TEST(jwt, jwks_find_fails_closed_on_unknown_kid) {
    ntc_jwks set;
    ASSERT_TRUE(ntc_jwks_parse(MULTI_JWKS, strlen(MULTI_JWKS), &set));
    ASSERT_TRUE(ntc_jwks_find(&set, "no-such-kid", "RS256") == NULL);
    /* a token whose kid is unknown must not verify even though the signature
     * would match a present key - selection is by kid first. */
    ntc_jwt_claims c;
    /* rewrite the ES256 token's kid header to an unknown value -> no key found */
    /* (here we just assert find() with a wrong kid is NULL; verify_jwks uses it) */
    ASSERT_TRUE(ntc_jwks_find(&set, "ec-1", "ES256") != NULL);
    ASSERT_FALSE(ntc_jwt_verify_jwks(ES256_TOKEN, strlen(ES256_TOKEN), &set, 4102444801, &c)); /* expired */
}
#endif /* UNIT_TEST */
