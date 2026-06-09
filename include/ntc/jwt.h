/* jwt.h - HS256 JSON Web Token validation (RS256/ES256 deferred to BearSSL). */
#ifndef NTC_JWT_H
#define NTC_JWT_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ntc_jwt_claims {
    char sub[128];
    char scope[256];
    long exp;
    long iat;
} ntc_jwt_claims;

/* Verify an HS256 token: signature (HMAC over header.payload with `secret`),
 * alg==HS256, and exp (if present and now_unix > 0). Fills *out on success. */
bool ntc_jwt_verify_hs256(const char *token, size_t len, const char *secret,
                          long now_unix, ntc_jwt_claims *out);

#endif /* NTC_JWT_H */
