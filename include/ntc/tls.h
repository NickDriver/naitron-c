/* tls.h - TLS termination for the gateway, backed by BearSSL.
 *
 * One ntc_tls_conf is loaded at startup (cert chain + RSA private key, both
 * PEM). Each accepted HTTPS connection gets its own ntc_tls engine. The engine
 * is driven through the existing non-blocking event loop: ntc_tls_pump_socket()
 * moves encrypted bytes to/from the socket, and ntc_tls_recv/_send move
 * plaintext bytes to/from the HTTP layer. We never hand-roll TLS (DECISIONS). */
#ifndef NTC_TLS_H
#define NTC_TLS_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ntc_tls_conf ntc_tls_conf;
typedef struct ntc_tls ntc_tls;

/* Load a PEM certificate chain and a PEM RSA private key. Returns NULL (and
 * logs) on any failure (missing file, no cert, non-RSA key, etc.). */
ntc_tls_conf *ntc_tls_conf_new(const char *cert_pem_path, const char *key_pem_path);
void ntc_tls_conf_free(ntc_tls_conf *c);

/* Create a per-connection server-side TLS engine. NULL on failure. */
ntc_tls *ntc_tls_new(const ntc_tls_conf *conf);
void ntc_tls_free(ntc_tls *t);

/* Move encrypted bytes between the socket and the engine, both directions,
 * until the socket would block. Drives the handshake too. Returns 0 normally,
 * -1 if the connection has failed and should be closed. */
int ntc_tls_pump_socket(ntc_tls *t, int fd);

/* Copy up to `len` decrypted application bytes into `buf`. Returns the number
 * copied (>0), 0 if none are available right now, or -1 if the engine closed. */
int ntc_tls_recv(ntc_tls *t, void *buf, size_t len);

/* Hand up to `len` plaintext bytes to the engine to encrypt. Returns the number
 * accepted (may be 0 if the engine's output buffer is full; caller retries). */
int ntc_tls_send(ntc_tls *t, const void *buf, size_t len);

/* Force any buffered application data out into records (so a pump can send it). */
void ntc_tls_flush(ntc_tls *t);

/* Begin a clean shutdown (emit close_notify). Idempotent. */
void ntc_tls_close_notify(ntc_tls *t);

/* True if the engine has encrypted records queued to send (=> want POLL_WRITE). */
bool ntc_tls_wants_write(const ntc_tls *t);

/* True once the engine is closed/failed or the transport hit EOF. */
bool ntc_tls_closed(const ntc_tls *t);

#endif /* NTC_TLS_H */
