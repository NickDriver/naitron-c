/* jwt.h - JSON Web Token validation: HS256 (HMAC), RS256 (RSA), ES256 (EC).
 *
 * HS256 uses our own HMAC-SHA256 (crypto.c). RS256/ES256 use BearSSL's PKCS#1
 * v1.5 / ECDSA verifiers - we never hand-roll asymmetric crypto (see
 * docs/DECISIONS.md). A JWKS document may carry several keys; we select by the
 * token's `kid` (and `alg`). */
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

/* ---- multi-key JWKS (RSA + EC), selectable by kid ---- */

typedef enum { NTC_JWK_RSA, NTC_JWK_EC } ntc_jwk_kty;

/* One signing key from a JWKS. For EC P-256, `q` is the uncompressed point
 * 0x04||X||Y (65 bytes). `kid`/`alg` are "" when the JWK omits them. */
typedef struct ntc_jwk_key {
    ntc_jwk_kty kty;
    char kid[80];
    char alg[16];
    unsigned char n[512]; size_t nlen;   /* RSA modulus  */
    unsigned char e[16];  size_t elen;   /* RSA exponent */
    unsigned char q[65];  size_t qlen;   /* EC point 0x04||X||Y */
} ntc_jwk_key;

#define NTC_JWKS_MAX_KEYS 16

typedef struct ntc_jwks {
    ntc_jwk_key keys[NTC_JWKS_MAX_KEYS];
    size_t count;
} ntc_jwks;

/* Read the "alg" header field of a token into out (e.g. "HS256" / "RS256").
 * Returns true if the header parsed and alg was found. */
bool ntc_jwt_peek_alg(const char *token, size_t len, char *out, size_t cap);

/* Read both the "alg" and "kid" header fields. `kid` is set to "" when absent.
 * Returns true if the header parsed and alg was found (kid is optional). */
bool ntc_jwt_peek_header(const char *token, size_t len,
                         char *alg, size_t algcap, char *kid, size_t kidcap);

/* Verify an HS256 token: signature (HMAC over header.payload with `secret`),
 * alg==HS256, and exp (if present and now_unix > 0). Fills *out on success. */
bool ntc_jwt_verify_hs256(const char *token, size_t len, const char *secret,
                          long now_unix, ntc_jwt_claims *out);

/* Verify an RS256 token: PKCS#1 v1.5 RSA signature over SHA-256(header.payload)
 * with `key`, alg==RS256, and exp (if present and now_unix > 0). */
bool ntc_jwt_verify_rs256(const char *token, size_t len,
                          const ntc_rsa_pubkey *key, long now_unix,
                          ntc_jwt_claims *out);

/* Verify an ES256 token: ECDSA-P256 over SHA-256(header.payload) with the EC
 * public point `q` (0x04||X||Y, 65 bytes), alg==ES256, and exp. */
bool ntc_jwt_verify_es256(const char *token, size_t len,
                          const unsigned char *q, size_t qlen, long now_unix,
                          ntc_jwt_claims *out);

/* Parse the first RSA signing key from a JWKS document - either a JWK Set
 * ({"keys":[...]}) or a single bare JWK ({"kty":"RSA",...}). Returns true on
 * success and fills *out (out->present is set). */
bool ntc_jwk_parse(const char *json, size_t len, ntc_rsa_pubkey *out);

/* Parse every RSA/EC signing key from a JWKS document into *out (up to
 * NTC_JWKS_MAX_KEYS). Returns true if at least one usable key was parsed. */
bool ntc_jwks_parse(const char *json, size_t len, ntc_jwks *out);

/* Find a key by kid (exact match; pass "" to match any) and, if alg is given,
 * a compatible key type (RS256->RSA, ES256->EC). Returns NULL if none. When
 * kid is "" and exactly one key is present, that key is returned. */
const ntc_jwk_key *ntc_jwks_find(const ntc_jwks *set, const char *kid,
                                 const char *alg);

/* High-level verify against a JWKS: peek alg+kid, select the key, dispatch to
 * RS256/ES256. Returns false (fail closed) on any mismatch. */
bool ntc_jwt_verify_jwks(const char *token, size_t len, const ntc_jwks *set,
                         long now_unix, ntc_jwt_claims *out);

#endif /* NTC_JWT_H */
