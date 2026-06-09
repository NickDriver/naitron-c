/* jwt.h - JSON Web Token validation: HS256 (HMAC) and RS256 (RSA via BearSSL).
 *
 * HS256 uses our own HMAC-SHA256 (crypto.c). RS256 uses BearSSL's PKCS#1 v1.5
 * verifier - we never hand-roll asymmetric crypto (see docs/DECISIONS.md). */
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

/* A parsed RSA public key (modulus + exponent, unsigned big-endian). Owns its
 * bytes; sized for keys up to RSA-4096. */
typedef struct ntc_rsa_pubkey {
    unsigned char n[512];
    size_t nlen;
    unsigned char e[16];
    size_t elen;
    bool present;
} ntc_rsa_pubkey;

/* Read the "alg" header field of a token into out (e.g. "HS256" / "RS256").
 * Returns true if the header parsed and alg was found. */
bool ntc_jwt_peek_alg(const char *token, size_t len, char *out, size_t cap);

/* Verify an HS256 token: signature (HMAC over header.payload with `secret`),
 * alg==HS256, and exp (if present and now_unix > 0). Fills *out on success. */
bool ntc_jwt_verify_hs256(const char *token, size_t len, const char *secret,
                          long now_unix, ntc_jwt_claims *out);

/* Verify an RS256 token: PKCS#1 v1.5 RSA signature over SHA-256(header.payload)
 * with `key`, alg==RS256, and exp (if present and now_unix > 0). */
bool ntc_jwt_verify_rs256(const char *token, size_t len,
                          const ntc_rsa_pubkey *key, long now_unix,
                          ntc_jwt_claims *out);

/* Parse the first RSA signing key from a JWKS document - either a JWK Set
 * ({"keys":[...]}) or a single bare JWK ({"kty":"RSA",...}). Returns true on
 * success and fills *out (out->present is set). */
bool ntc_jwk_parse(const char *json, size_t len, ntc_rsa_pubkey *out);

#endif /* NTC_JWT_H */
