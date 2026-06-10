/* ws.h - WebSocket (RFC 6455) handshake + frame codec for the gateway.
 *
 * The gateway terminates WebSocket: it does the Upgrade handshake, (un)masks and
 * frames on the wire, and relays decoded messages to/from a controller as WS_MSG
 * IPC frames. Controllers never see raw WS framing. SHA-1 (for the accept key)
 * comes from BearSSL. */
#ifndef NTC_WS_H
#define NTC_WS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* RFC 6455 opcodes (low nibble of byte 0). */
typedef enum {
    NTC_WS_CONT  = 0x0,
    NTC_WS_TEXT  = 0x1,
    NTC_WS_BIN   = 0x2,
    NTC_WS_CLOSE = 0x8,
    NTC_WS_PING  = 0x9,
    NTC_WS_PONG  = 0xA,
} ntc_ws_opcode;

/* Largest single WS message we will buffer/relay (bounds memory per conn). */
#define NTC_WS_MAX_PAYLOAD (1u * 1024 * 1024)

/* Compute Sec-WebSocket-Accept from the client's Sec-WebSocket-Key. Writes a
 * NUL-terminated standard-base64 string (28 chars) into `out`. */
void ntc_ws_accept_key(const char *client_key, size_t klen, char *out, size_t cap);

/* Decode one frame from buf[0..len). On a complete frame (returns 1): sets
 * consumed (header+payload bytes), opcode, fin, and points payload+paylen at
 * the UNMASKED payload (unmasked in place inside buf). Returns 0 if more bytes
 * are needed, or -1 on a protocol error (oversized / malformed). */
int ntc_ws_decode(uint8_t *buf, size_t len, size_t *consumed,
                  ntc_ws_opcode *opcode, bool *fin,
                  uint8_t **payload, size_t *paylen);

/* Encode an unmasked server frame (FIN=1) for opcode+data into out. Returns the
 * number of bytes written, or -1 if cap is too small. */
ssize_t ntc_ws_encode(ntc_ws_opcode opcode, const uint8_t *data, size_t len,
                      uint8_t *out, size_t cap);

#endif /* NTC_WS_H */
