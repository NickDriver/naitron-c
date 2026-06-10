/* ws_echo.c - example WebSocket controller.
 *
 * On open it greets the client; each message it receives it echoes back with an
 * "echo: " prefix (preserving the text/binary opcode). The gateway terminates
 * the WS protocol (handshake, masking, framing); this controller only sees
 * decoded messages via the ws_* callbacks. */
#define _GNU_SOURCE
#include "ntc/controller.h"

#include <stdio.h>
#include <string.h>

static void on_open(const ntc_request *req, ntc_ws *ws, void *u) {
    (void)req; (void)u;
    ntc_ws_send_text(ws, "welcome");
}

static void on_message(ntc_ws *ws, int opcode, const void *data, size_t len, void *u) {
    (void)u;
    char buf[1100];
    size_t m = len > 1024 ? 1024 : len;
    int n = snprintf(buf, sizeof buf, "echo: %.*s", (int)m, (const char *)data);
    if (n > 0) ntc_ws_send(ws, opcode, buf, (size_t)n);
}

static void on_close(ntc_ws *ws, void *u) { (void)ws; (void)u; }

int main(void) {
    ntc_controller ctl = {
        .name = "wsecho",
        .ws_open = on_open,
        .ws_message = on_message,
        .ws_close = on_close,
    };
    return ntc_controller_run(&ctl);
}
