/* sse_controller.c - example streaming controller (Server-Sent Events).
 *
 * Demonstrates the streaming SDK: a handler drives an ntc_stream instead of
 * filling a one-shot response. Query params:
 *   ?n=<count>      number of events to emit (default 3, capped at 1000)
 *   ?delay=<ms>     sleep between events (default 0) - lets a test observe that
 *                   events arrive incrementally, not all at the end
 *   ?mode=chunked   use generic chunked framing + text/plain instead of SSE
 */
#define _GNU_SOURCE
#include "ntc/controller.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int qint(const ntc_request *req, const char *key, int dflt) {
    ntc_slice s = ntc_req_query(req, key);
    if (!s.len || s.len > 15) return dflt;
    char buf[16];
    memcpy(buf, s.ptr, s.len);
    buf[s.len] = '\0';
    return atoi(buf);
}

static int stream(const ntc_request *req, ntc_stream *st, ntc_arena *a, void *u) {
    (void)a; (void)u;
    int n = qint(req, "n", 3);
    if (n < 1) n = 1;
    if (n > 1000) n = 1000;
    int delay_ms = qint(req, "delay", 0);
    bool chunked = ntc_slice_eq_cstr(ntc_req_query(req, "mode"), "chunked");

    if (chunked) {
        if (ntc_stream_begin(st, 200, NTC_SLICE_LIT("text/plain")) != 0) return -1;
        for (int i = 0; i < n; i++) {
            char line[64];
            int ln = snprintf(line, sizeof line, "chunk %d\n", i);
            if (ln < 0 || ntc_stream_write(st, line, (size_t)ln) != 0) return 0;
            if (delay_ms > 0) usleep((useconds_t)delay_ms * 1000);
        }
    } else {
        if (ntc_sse_begin(st) != 0) return -1;
        for (int i = 0; i < n; i++) {
            char data[32];
            snprintf(data, sizeof data, "tick %d", i);
            if (ntc_sse_send(st, "message", data) != 0) return 0;
            if (delay_ms > 0) usleep((useconds_t)delay_ms * 1000);
        }
    }
    return 0; /* the SDK auto-emits RESPONSE_END */
}

int main(void) {
    ntc_controller ctl = { .name = "sse", .stream = stream, .udata = NULL };
    return ntc_controller_run(&ctl);
}
