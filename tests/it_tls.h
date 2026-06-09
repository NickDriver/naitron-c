/* it_tls.h - a minimal TLS client for integration tests (BearSSL-backed).
 *
 * The plaintext it_util helpers can't speak TLS, so this gives the C harness a
 * real HTTPS client - no curl dependency. It accepts ANY server certificate
 * (like `curl -k`): INSECURE, for talking to our own self-signed test server
 * on localhost only. */
#ifndef NTC_IT_TLS_H
#define NTC_IT_TLS_H

#include <stddef.h>

/* Open a TLS connection to 127.0.0.1:port, send the raw request bytes, read the
 * full response into resp (NUL-terminated). Returns bytes read, or -1 on any
 * failure (connect/handshake/IO). */
int it_tls_request(int port, const char *raw, size_t rawlen, char *resp, size_t cap);

/* Convenience: GET `path` over TLS with a Host header + Connection: close. */
int it_tls_get(int port, const char *path, char *resp, size_t cap);

#endif /* NTC_IT_TLS_H */
