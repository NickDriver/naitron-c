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
#endif /* UNIT_TEST */
