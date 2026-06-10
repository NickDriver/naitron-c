/* server.h - the gateway entry point.
 * (Event loop at P1, HTTP parsing P2, routing P3, IPC/controllers P4+.) */
#ifndef NTC_SERVER_H
#define NTC_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ntc/err.h"

#define NTC_DEV_MAX_WATCH 32

/* Dev-mode hot-reload options (NULL = production mode, no watching). When
 * `watch` is set, the gateway polls controller binaries' mtimes and reloads a
 * service when its binary changes; `paths` (source files/dirs) are watched too,
 * and `build_cmd` (if set) is run when any of them changes. */
typedef struct ntc_dev_opts {
    bool watch;
    const char *build_cmd;          /* run on a watched-source change (or NULL) */
    const char *const *paths;       /* source paths to watch (files or dirs)    */
    size_t npaths;
} ntc_dev_opts;

/* Bind `port`, accept connections, serve until SIGINT/SIGTERM.
 * `admin_port` is the read-only dashboard (0 = disabled).
 * `tls_port` is an optional HTTPS listener (0 = disabled; needs tls.cert/key).
 * `dev` enables watch+hot-reload (NULL = off). */
NTC_NODISCARD ntc_err ntc_server_run(uint16_t port, uint16_t admin_port,
                                     uint16_t tls_port, const ntc_dev_opts *dev);

#endif /* NTC_SERVER_H */
