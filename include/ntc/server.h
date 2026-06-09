/* server.h - the P0 gateway: a blocking accept loop that answers 200 OK.
 * (Event loop arrives at P1, HTTP parsing at P2, routing at P3.) */
#ifndef NTC_SERVER_H
#define NTC_SERVER_H

#include <stdint.h>
#include "ntc/err.h"

/* Bind `port`, accept connections, answer a fixed JSON 200 until SIGINT/SIGTERM.
 * `admin_port` is reserved for the read-only dashboard (P8); 0 = disabled. */
NTC_NODISCARD ntc_err ntc_server_run(uint16_t port, uint16_t admin_port);

#endif /* NTC_SERVER_H */
