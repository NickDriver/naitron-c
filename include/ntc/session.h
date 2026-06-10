/* session.h - session/cookie subsystem + PKCE, for OAuth2 login.
 *
 * A small in-memory TTL key/value store backs both server-side sessions
 * (session-id -> identity) and pending logins (state -> PKCE verifier). Plus
 * cookie parse/format helpers and the PKCE code_verifier/code_challenge pair.
 * Sessions live in the gateway process (lost on restart - acceptable for now). */
#ifndef NTC_SESSION_H
#define NTC_SESSION_H

#include <stdbool.h>
#include <stddef.h>

/* ---- in-memory TTL key/value store ---- */
typedef struct ntc_kvstore ntc_kvstore;

ntc_kvstore *ntc_kv_new(size_t cap);
void ntc_kv_free(ntc_kvstore *kv);

/* Store key->val with an absolute expiry (unix seconds). Overwrites an existing
 * key; when full, evicts the soonest-to-expire entry. */
void ntc_kv_put(ntc_kvstore *kv, const char *key, const char *val, long expiry);

/* Copy the value for key into out (NUL-terminated) if present and not expired
 * (relative to `now`). Returns false on miss/expired. */
bool ntc_kv_get(ntc_kvstore *kv, const char *key, long now, char *out, size_t cap);

void ntc_kv_del(ntc_kvstore *kv, const char *key);

/* ---- cookies ---- */

/* Extract the value of cookie `name` from a "Cookie:" header value into out.
 * Returns false if not present. */
bool ntc_cookie_get(const char *cookie_header, const char *name, char *out, size_t cap);

/* Format a Set-Cookie header value (without the "Set-Cookie:" prefix):
 * "<name>=<value>; Path=/; HttpOnly; SameSite=Lax[; Secure][; Max-Age=<n>]".
 * max_age < 0 omits Max-Age (session cookie); == 0 expires it immediately. */
int ntc_cookie_format(char *out, size_t cap, const char *name, const char *value,
                      bool secure, long max_age);

/* ---- PKCE (RFC 7636, S256) ---- */

/* Generate a high-entropy code_verifier (43 base64url chars) into out. */
bool ntc_pkce_verifier(char *out, size_t cap);

/* Compute the S256 code_challenge = base64url(SHA256(verifier)) into out. */
bool ntc_pkce_challenge(const char *verifier, char *out, size_t cap);

/* Random URL-safe token (e.g. an OAuth `state` or a session id), `nbytes` of
 * entropy hex-encoded into out. */
bool ntc_random_token(char *out, size_t cap, size_t nbytes);

#endif /* NTC_SESSION_H */
