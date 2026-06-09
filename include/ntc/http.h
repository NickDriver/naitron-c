/* http.h - HTTP response serialization (P0 seed; parser arrives at P2). */
#ifndef NTC_HTTP_H
#define NTC_HTTP_H

#include "ntc/arena.h"
#include "ntc/err.h"
#include "ntc/slice.h"

/* Format a complete HTTP/1.1 response into `a`. The bytes are written into
 * arena memory and returned via *out (Connection: close). */
NTC_NODISCARD ntc_err ntc_http_format_response(ntc_arena *a, int status,
        const char *status_text, ntc_slice content_type, ntc_slice body,
        ntc_slice *out);

#endif /* NTC_HTTP_H */
