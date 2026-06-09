/* controller.h - the Controller SDK.
 *
 * A controller binary implements one handler and calls ntc_controller_run().
 * The SDK owns the socket, framing, handshake, and serve loop, so a controller
 * author never touches the wire protocol - which is exactly what keeps the
 * "hardcoded protocol on both sides" from being a footgun. */
#ifndef NTC_CONTROLLER_H
#define NTC_CONTROLLER_H

#include "ntc/arena.h"
#include "ntc/http.h"
#include "ntc/slice.h"

/* Fill *res (body allocated in arena a). Return 0 on success, non-zero -> 500. */
typedef int (*ntc_controller_fn)(const ntc_request *req, ntc_response *res,
                                 ntc_arena *a, void *udata);

typedef struct ntc_controller {
    const char *name;
    ntc_controller_fn handle;
    void *udata;
} ntc_controller;

/* Run the serve loop on the inherited socket (fd in $NTC_CONTROLLER_FD).
 * Blocks until the core closes the connection; returns a process exit code. */
int ntc_controller_run(const ntc_controller *ctl);

/* Build a JSON response into `a` (printf-style). Returns 0, or -1 on OOM. */
__attribute__((format(printf, 4, 5)))
int ntc_reply_json(ntc_response *res, ntc_arena *a, int status, const char *fmt, ...);

#endif /* NTC_CONTROLLER_H */
