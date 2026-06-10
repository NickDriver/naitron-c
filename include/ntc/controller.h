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

/* A streaming response handle (opaque). Drive it with the ntc_stream_* / ntc_sse_*
 * calls below to emit a response incrementally instead of all at once. */
typedef struct ntc_stream ntc_stream;

/* Streaming handler: drive `st` instead of filling a response. Return 0 on
 * success, non-zero -> 500 (only meaningful if the stream was never begun). */
typedef int (*ntc_stream_fn)(const ntc_request *req, ntc_stream *st,
                             ntc_arena *a, void *udata);

/* A live WebSocket connection (opaque). The gateway terminates the WS protocol;
 * the controller exchanges decoded messages via these callbacks + ntc_ws_*. */
typedef struct ntc_ws ntc_ws;
typedef void (*ntc_ws_open_fn)(const ntc_request *req, ntc_ws *ws, void *udata);
typedef void (*ntc_ws_msg_fn)(ntc_ws *ws, int opcode, const void *data,
                              size_t len, void *udata);
typedef void (*ntc_ws_close_fn)(ntc_ws *ws, void *udata);

typedef struct ntc_controller {
    const char *name;
    ntc_controller_fn handle; /* atomic handler (one-shot response)      */
    ntc_stream_fn stream;     /* streaming handler (optional; if set, takes priority) */
    ntc_ws_open_fn ws_open;       /* WebSocket opened (optional)         */
    ntc_ws_msg_fn ws_message;     /* WebSocket message received          */
    ntc_ws_close_fn ws_close;     /* WebSocket closed                    */
    void *udata;
} ntc_controller;

/* WS message opcodes for ntc_ws_send (text is UTF-8, binary is opaque). */
#define NTC_WS_OP_TEXT   1
#define NTC_WS_OP_BINARY 2

/* Run the serve loop on the inherited socket (fd in $NTC_CONTROLLER_FD).
 * Blocks until the core closes the connection; returns a process exit code. */
int ntc_controller_run(const ntc_controller *ctl);

/* Build a JSON response into `a` (printf-style). Returns 0, or -1 on OOM. */
__attribute__((format(printf, 4, 5)))
int ntc_reply_json(ntc_response *res, ntc_arena *a, int status, const char *fmt, ...);

/* ---- streaming response API (used from an ntc_stream_fn handler) ----
 * Begin once, then write/sse_send zero or more times, then end (auto-called at
 * handler return if omitted). Each returns 0 on success, -1 on a write error
 * (the controller should stop streaming). */
int ntc_stream_begin(ntc_stream *st, int status, ntc_slice content_type); /* chunked framing */
int ntc_sse_begin(ntc_stream *st);                                        /* Content-Type: text/event-stream */
int ntc_stream_write(ntc_stream *st, const void *data, size_t len);       /* one body chunk */
int ntc_sse_send(ntc_stream *st, const char *event, const char *data);    /* one SSE event (event optional) */
int ntc_stream_end(ntc_stream *st);

/* ---- WebSocket API (used from the ws_open / ws_message / ws_close callbacks) ----
 * Send a message to the peer (opcode = NTC_WS_OP_TEXT/BINARY), or close the
 * socket. Each returns 0 on success, -1 on a write error. */
int ntc_ws_send(ntc_ws *ws, int opcode, const void *data, size_t len);
int ntc_ws_send_text(ntc_ws *ws, const char *text);
int ntc_ws_close(ntc_ws *ws);

#endif /* NTC_CONTROLLER_H */
