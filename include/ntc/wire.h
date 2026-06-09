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
#define NTC_WIRE_VERSION    2  /* v2: request carries path params + auth identity */
#define NTC_WIRE_HEADER_LEN 16

typedef enum ntc_msg_type {
    NTC_MSG_HELLO    = 1, /* controller -> core: announce name + abi   */
    NTC_MSG_WELCOME  = 2, /* core -> controller: handshake accepted    */
    NTC_MSG_REQUEST  = 3, /* core -> controller: a routed HTTP request */
    NTC_MSG_RESPONSE = 4, /* controller -> core: the response          */
    NTC_MSG_PING     = 5,
    NTC_MSG_PONG     = 6
} ntc_msg_type;

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

#endif /* NTC_WIRE_H */
