/* crypto.h - SHA-256, HMAC-SHA256, base64url. Used for HS256 JWT validation.
 *
 * These are deterministic, spec-defined primitives verified against RFC test
 * vectors. Asymmetric crypto (RS256/ES256) and TLS come from BearSSL (see
 * docs/DECISIONS.md) - we do not hand-roll those. */
#ifndef NTC_CRYPTO_H
#define NTC_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void ntc_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void ntc_hmac_sha256(const uint8_t *key, size_t keylen,
                     const uint8_t *msg, size_t msglen, uint8_t out[32]);

/* url-safe base64, no padding. Encode returns chars written (excl NUL) or -1;
 * decode returns bytes written or -1. */
int ntc_base64url_encode(const uint8_t *in, size_t len, char *out, size_t cap);
int ntc_base64url_decode(const char *in, size_t len, uint8_t *out, size_t cap);

/* constant-time equality (for MAC/secret comparison) */
bool ntc_ct_eq(const uint8_t *a, const uint8_t *b, size_t n);

#endif /* NTC_CRYPTO_H */
