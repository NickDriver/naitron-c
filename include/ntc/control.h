/* control.h - the authenticated control plane.
 *
 * The core listens on a Unix-domain control socket. The CLI and (later) the
 * built-in MCP server are thin clients that send one token-prefixed command
 * line and read the response. Only the core writes the registry; clients ask
 * the core, which mutates SQLite + hot-reloads its routing table. */
#ifndef NTC_CONTROL_H
#define NTC_CONTROL_H

#include <stddef.h>
#include "ntc/err.h"

#define NTC_CONTROL_SOCK_DEFAULT  "./ntc.sock"
#define NTC_CONTROL_TOKEN_DEFAULT "./ntc.token"

/* Send "<token> <command>\n" to the control socket and read the response into
 * out (NUL-terminated). NTC_ERR_IO if the core isn't reachable. */
NTC_NODISCARD ntc_err ntc_control_call(const char *sock_path, const char *token,
                                       const char *command, char *out, size_t out_cap);

/* Resolve the control socket path ($NTC_CONTROL_SOCK or the default). */
const char *ntc_control_sock_path(void);

/* Read the token from $NTC_TOKEN or the token file ($NTC_TOKEN_FILE / default). */
NTC_NODISCARD ntc_err ntc_control_read_token(char *out, size_t cap);

#endif /* NTC_CONTROL_H */
