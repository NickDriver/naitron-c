/* https_client.h - minimal outbound HTTPS GET, backed by BearSSL (client side).
 *
 * Used to fetch a JWKS document from an OAuth/OIDC issuer over TLS, with REAL
 * certificate verification against a set of trust anchors (a bundled CA root
 * store, or a caller-supplied PEM via auth.jwks_ca). We never hand-roll TLS
 * (see docs/DECISIONS.md). This is a short, bounded, blocking fetch meant to run
 * off the hot path (at startup / on rare key rotation). */
#ifndef NTC_HTTPS_CLIENT_H
#define NTC_HTTPS_CLIENT_H

#include <stddef.h>

/* An immutable set of X.509 trust anchors (deep-copied; owns its bytes). */
typedef struct ntc_ca ntc_ca;

/* Load one or more CA certificates (PEM) from `path` into a trust-anchor set.
 * Returns NULL on error or if no certificate decoded. */
ntc_ca *ntc_ca_load_pem(const char *path);

/* Load the default bundled root store: $NTC_CA_BUNDLE if set, else
 * third_party/ca/roots.pem. Returns NULL if none is available. */
ntc_ca *ntc_ca_default(void);

void ntc_ca_free(ntc_ca *ca);

/* GET `url` (https://host[:port]/path) and copy the response body into `out`.
 * The peer certificate is verified against `ca`; a NULL/empty `ca` fails closed.
 * Returns the body length (>=0) on HTTP 200, or -1 on any failure (with a short
 * message in `err`, if provided). `timeout_ms` bounds connect + each I/O. */
int ntc_https_get(const ntc_ca *ca, const char *url, char *out, size_t cap,
                  int timeout_ms, char *err, size_t errcap);

#endif /* NTC_HTTPS_CLIENT_H */
