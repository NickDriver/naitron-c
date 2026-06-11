/* wire.h - the IPC "syscall ABI" between the gateway and controller processes.
 *
 * Framing (16-byte header, big-endian): magic | version | type | reserved(2) |
 * request_id(4) | payload_len(4) | payload. Persistent Unix-domain socket per
 * controller; requests are multiplexed by request_id. The version byte lets the
 * protocol evolve; a controller SDK (controller.h) hides all of this from devs. */
#ifndef NTC_WIRE_H
#define NTC_WIRE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> /* ssize_t */

#include "ntc/http.h"
#include "ntc/slice.h"

#define NTC_WIRE_MAGIC      0x4E544331u /* "NTC1" */
/* Version byte we WRITE stays 2 so already-compiled v2 controllers keep
 * accepting gateway frames. The "v3" streaming capability is added purely via
 * new message types (RESPONSE_BEGIN/CHUNK/END), so readers accept versions
 * 2..MAX and dispatch on type - a v2 peer simply never sees the new types. */
#define NTC_WIRE_VERSION     2  /* v2: request carries path params + auth identity */
#define NTC_WIRE_VERSION_MAX 3  /* v3: streaming response frames */
#define NTC_WIRE_HEADER_LEN  16

typedef enum ntc_msg_type {
    NTC_MSG_HELLO          = 1, /* controller -> core: announce name + abi   */
    NTC_MSG_WELCOME        = 2, /* core -> controller: handshake accepted    */
    NTC_MSG_REQUEST        = 3, /* core -> controller: a routed HTTP request */
    NTC_MSG_RESPONSE       = 4, /* controller -> core: the (atomic) response */
    NTC_MSG_PING           = 5,
    NTC_MSG_PONG           = 6,
    NTC_MSG_RESPONSE_BEGIN = 7, /* controller -> core: start of a stream (status+flags+ctype) */
    NTC_MSG_RESPONSE_CHUNK = 8, /* controller -> core: a body chunk           */
    NTC_MSG_RESPONSE_END   = 9, /* controller -> core: stream complete (empty payload) */
    NTC_MSG_WS_OPEN        = 10,/* core -> controller: a WebSocket opened (REQUEST payload) */
    NTC_MSG_WS_MSG         = 11,/* both ways: one WS message (opcode + data)  */
    NTC_MSG_WS_CLOSE       = 12 /* both ways: close the WebSocket (u16 code)   */
} ntc_msg_type;

/* RESPONSE_BEGIN flags: how the gateway frames the stream to the HTTP client. */
#define NTC_STREAM_FLAG_SSE     0x01 /* text/event-stream, raw passthrough, end-on-close */
#define NTC_STREAM_FLAG_CHUNKED 0x02 /* Transfer-Encoding: chunked                       */

typedef struct ntc_wire_header {
    uint8_t version;
    uint8_t type;
    uint32_t request_id;
    uint32_t length; /* payload length */
} ntc_wire_header;

void ntc_wire_write_header(uint8_t out[NTC_WIRE_HEADER_LEN], uint8_t type,
                           uint32_t request_id, uint32_t payload_len);

/* Validate + decode just the 16-byte header (for blocking readers). */
bool ntc_wire_parse_header(const uint8_t buf[NTC_WIRE_HEADER_LEN],
                           ntc_wire_header *out);

/* 1 = a full frame is available (hdr, payload, consumed are set),
 * 0 = need more bytes, -1 = malformed (bad magic/version). */
int ntc_wire_read_frame(const uint8_t *buf, size_t len, ntc_wire_header *hdr,
                        const uint8_t **payload, size_t *consumed);

/* Encode/decode payloads. Encoders return bytes written or -1 (cap too small).
 * Decoders fill slices pointing into `buf` (so buf must outlive them). */
ssize_t ntc_wire_encode_request(const ntc_request *req, uint8_t *out, size_t cap);
ssize_t ntc_wire_encode_response(int status, ntc_slice ctype, ntc_slice body,
                                 uint8_t *out, size_t cap);
bool ntc_wire_decode_request(const uint8_t *buf, size_t len, ntc_request *req);
bool ntc_wire_decode_response(const uint8_t *buf, size_t len, int *status,
                              ntc_slice *ctype, ntc_slice *body);

/* RESPONSE with controller-set headers (a raw "Name: Value\r\n..." blob appended
 * after the body). Backward-compatible: a decoder that stops after the body
 * simply ignores the trailing blob, and decode_response_ex returns an empty
 * headers slice for a plain (no-trailer) payload. */
ssize_t ntc_wire_encode_response_ex(int status, ntc_slice ctype, ntc_slice body,
                                    ntc_slice headers, uint8_t *out, size_t cap);
bool ntc_wire_decode_response_ex(const uint8_t *buf, size_t len, int *status,
                                 ntc_slice *ctype, ntc_slice *body, ntc_slice *headers);

/* Streaming (v3). BEGIN carries status + flags + content-type; CHUNK carries an
 * opaque body slice (gateway frames it per the flags); END has an empty payload
 * (no encode/decode needed - just a header with length 0). */
ssize_t ntc_wire_encode_response_begin(int status, uint8_t flags, ntc_slice ctype,
                                       uint8_t *out, size_t cap);
bool ntc_wire_decode_response_begin(const uint8_t *buf, size_t len, int *status,
                                    uint8_t *flags, ntc_slice *ctype);
ssize_t ntc_wire_encode_chunk(ntc_slice data, uint8_t *out, size_t cap);
bool ntc_wire_decode_chunk(const uint8_t *buf, size_t len, ntc_slice *data);

/* WebSocket (v3). WS_OPEN carries a REQUEST payload (encode/decode_request).
 * WS_MSG is bidirectional: a u8 opcode (1=text, 2=binary) + a u32-prefixed data
 * slice. WS_CLOSE is bidirectional: a u16 status code (0 = none). */
ssize_t ntc_wire_encode_ws_msg(uint8_t opcode, ntc_slice data, uint8_t *out, size_t cap);
bool ntc_wire_decode_ws_msg(const uint8_t *buf, size_t len, uint8_t *opcode, ntc_slice *data);
ssize_t ntc_wire_encode_ws_close(uint16_t code, uint8_t *out, size_t cap);
bool ntc_wire_decode_ws_close(const uint8_t *buf, size_t len, uint16_t *code);

#endif /* NTC_WIRE_H */
