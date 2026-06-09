#include "ntc/jwt.h"

#include "ntc/arena.h"
#include "ntc/crypto.h"
#include "ntc/json.h"
#include "ntc/slice.h"

#include <stdio.h>
#include <string.h>

bool ntc_jwt_verify_hs256(const char *token, size_t len, const char *secret,
                          long now_unix, ntc_jwt_claims *out) {
    memset(out, 0, sizeof *out);
    if (!token || !secret) return false;

    const char *d1 = memchr(token, '.', len);
    if (!d1) return false;
    size_t after1 = (size_t)(d1 + 1 - token);
    const char *d2 = memchr(d1 + 1, '.', len - after1);
    if (!d2) return false;

    size_t hlen = (size_t)(d1 - token);
    size_t plen = (size_t)(d2 - (d1 + 1));
    const char *sig = d2 + 1;
    size_t siglen = len - (size_t)(sig - token);
    size_t signed_len = (size_t)(d2 - token); /* "header.payload" */

    /* signature check */
    uint8_t mac[32];
    ntc_hmac_sha256((const uint8_t *)secret, strlen(secret),
                    (const uint8_t *)token, signed_len, mac);
    char macb64[64];
    int mn = ntc_base64url_encode(mac, 32, macb64, sizeof macb64);
    if (mn < 0 || (size_t)mn != siglen) return false;
    if (!ntc_ct_eq((const uint8_t *)macb64, (const uint8_t *)sig, siglen)) return false;

    ntc_arena a;
    if (ntc_arena_init(&a, 8192) != NTC_OK) return false;
    bool ok = false;

    uint8_t hbuf[1024];
    int hn = ntc_base64url_decode(token, hlen, hbuf, sizeof hbuf);
    if (hn > 0) {
        ntc_json *hj = ntc_json_parse(&a, (char *)hbuf, (size_t)hn);
        if (hj && ntc_slice_eq_cstr(ntc_json_str(ntc_json_get(hj, "alg")), "HS256")) {
            uint8_t pbuf[4096];
            int pn = ntc_base64url_decode(d1 + 1, plen, pbuf, sizeof pbuf);
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
#endif /* UNIT_TEST */
