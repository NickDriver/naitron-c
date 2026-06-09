/* server.h - the P0 gateway: a blocking accept loop that answers 200 OK.
 * (Event loop arrives at P1, HTTP parsing at P2, routing at P3.) */
#ifndef NTC_SERVER_H
#define NTC_SERVER_H

#include <stdint.h>
#include "ntc/err.h"

/* Bind `port`, accept connections, serve until SIGINT/SIGTERM.
 * `admin_port` is the read-only dashboard (0 = disabled).
 * `tls_port` is an optional HTTPS listener (0 = disabled; needs tls.cert/key). */
NTC_NODISCARD ntc_err ntc_server_run(uint16_t port, uint16_t admin_port, uint16_t tls_port);

#endif /* NTC_SERVER_H */
