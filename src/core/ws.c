#define _GNU_SOURCE
#include "ntc/ws.h"

#include "bearssl.h"

#include <string.h>

/* ---- standard base64 (with padding); the accept key is NOT base64url ---- */
static void b64_std(const uint8_t *in, size_t n, char *out, size_t cap) {
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        char c[4] = {
            T[(v >> 18) & 0x3f], T[(v >> 12) & 0x3f],
            (i + 1 < n) ? T[(v >> 6) & 0x3f] : '=',
            (i + 2 < n) ? T[v & 0x3f] : '=',
        };
        for (int k = 0; k < 4 && o + 1 < cap; k++) out[o++] = c[k];
    }
    if (o < cap) out[o] = '\0';
}

void ntc_ws_accept_key(const char *client_key, size_t klen, char *out, size_t cap) {
    static const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    br_sha1_context c;
    br_sha1_init(&c);
    br_sha1_update(&c, client_key, klen);
    br_sha1_update(&c, GUID, sizeof GUID - 1);
    uint8_t dig[20];
    br_sha1_out(&c, dig);
    b64_std(dig, sizeof dig, out, cap);
}

int ntc_ws_decode(uint8_t *buf, size_t len, size_t *consumed,
                  ntc_ws_opcode *opcode, bool *fin,
                  uint8_t **payload, size_t *paylen) {
    if (len < 2) return 0;
    uint8_t b0 = buf[0], b1 = buf[1];
    *fin = (b0 & 0x80) != 0;
    *opcode = (ntc_ws_opcode)(b0 & 0x0f);
    bool masked = (b1 & 0x80) != 0;
    uint64_t plen = (uint64_t)(b1 & 0x7f);
    size_t off = 2;
    if (plen == 126) {
        if (len < 4) return 0;
        plen = ((uint64_t)buf[2] << 8) | buf[3];
        off = 4;
    } else if (plen == 127) {
        if (len < 10) return 0;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | buf[2 + i];
        off = 10;
    }
    if (plen > NTC_WS_MAX_PAYLOAD) return -1;
    uint8_t mask[4] = { 0 };
    if (masked) {
        if (len < off + 4) return 0;
        memcpy(mask, buf + off, 4);
        off += 4;
    }
    if (len < off + plen) return 0; /* need more bytes for the full payload */
    if (masked)
        for (uint64_t i = 0; i < plen; i++) buf[off + i] ^= mask[i & 3];
    *payload = buf + off;
    *paylen = (size_t)plen;
    *consumed = off + (size_t)plen;
    return 1;
}

ssize_t ntc_ws_encode(ntc_ws_opcode opcode, const uint8_t *data, size_t len,
                      uint8_t *out, size_t cap) {
    size_t hdr = 2;
    if (len > 0xffff) hdr = 10;
    else if (len > 125) hdr = 4;
    if (cap < hdr + len) return -1;
    out[0] = (uint8_t)(0x80 | (opcode & 0x0f)); /* FIN + opcode */
    if (hdr == 2) {
        out[1] = (uint8_t)len;
    } else if (hdr == 4) {
        out[1] = 126;
        out[2] = (uint8_t)(len >> 8);
        out[3] = (uint8_t)len;
    } else {
        out[1] = 127;
        for (int i = 0; i < 8; i++) out[2 + i] = (uint8_t)(len >> (56 - 8 * i));
    }
    if (len && data) memcpy(out + hdr, data, len);
    return (ssize_t)(hdr + len);
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(ws, accept_key_rfc_vector) {
    /* RFC 6455 section 1.3 worked example */
    char out[64];
    ntc_ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", 24, out, sizeof out);
    ASSERT_TRUE(strcmp(out, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
}

TEST(ws, encode_small_frame) {
    uint8_t out[32];
    ssize_t n = ntc_ws_encode(NTC_WS_TEXT, (const uint8_t *)"hi", 2, out, sizeof out);
    ASSERT_EQ_INT(4, (int)n);
    ASSERT_EQ_INT(0x81, out[0]);       /* FIN + text */
    ASSERT_EQ_INT(2, out[1]);          /* unmasked, len 2 */
    ASSERT_TRUE(memcmp(out + 2, "hi", 2) == 0);
}

TEST(ws, decode_masked_client_frame) {
    /* a masked client text frame "Hello" (RFC-style) */
    uint8_t frame[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d,
                        0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    size_t consumed = 0, paylen = 0;
    ntc_ws_opcode op; bool fin; uint8_t *pay;
    int r = ntc_ws_decode(frame, sizeof frame, &consumed, &op, &fin, &pay, &paylen);
    ASSERT_EQ_INT(1, r);
    ASSERT_TRUE(fin);
    ASSERT_EQ_INT(NTC_WS_TEXT, (int)op);
    ASSERT_EQ_INT(5, (int)paylen);
    ASSERT_TRUE(memcmp(pay, "Hello", 5) == 0);
    ASSERT_EQ_INT((int)sizeof frame, (int)consumed);
}

TEST(ws, decode_needs_more_bytes) {
    uint8_t frame[] = { 0x81, 0x85, 0x37, 0xfa }; /* header incomplete */
    size_t consumed = 0, paylen = 0;
    ntc_ws_opcode op; bool fin; uint8_t *pay;
    ASSERT_EQ_INT(0, ntc_ws_decode(frame, sizeof frame, &consumed, &op, &fin, &pay, &paylen));
}

TEST(ws, roundtrip_126_boundary) {
    /* a 200-byte message uses the 16-bit length form; encode then decode (we
     * mask it ourselves to mimic a client) and compare. */
    uint8_t msg[200];
    for (int i = 0; i < 200; i++) msg[i] = (uint8_t)i;
    uint8_t enc[256];
    ssize_t n = ntc_ws_encode(NTC_WS_BIN, msg, sizeof msg, enc, sizeof enc);
    ASSERT_EQ_INT(204, (int)n);        /* 4-byte header + 200 */
    ASSERT_EQ_INT(126, enc[1] & 0x7f); /* extended 16-bit length */

    /* turn the server frame into a masked client frame for the decode path */
    uint8_t cf[256];
    cf[0] = enc[0];
    cf[1] = (uint8_t)(0x80 | 126);
    cf[2] = enc[2]; cf[3] = enc[3];
    uint8_t key[4] = { 1, 2, 3, 4 };
    memcpy(cf + 4, key, 4);
    for (int i = 0; i < 200; i++) cf[8 + i] = msg[i] ^ key[i & 3];
    size_t consumed = 0, paylen = 0;
    ntc_ws_opcode op; bool fin; uint8_t *pay;
    ASSERT_EQ_INT(1, ntc_ws_decode(cf, 208, &consumed, &op, &fin, &pay, &paylen));
    ASSERT_EQ_INT(NTC_WS_BIN, (int)op);
    ASSERT_EQ_INT(200, (int)paylen);
    ASSERT_TRUE(memcmp(pay, msg, 200) == 0);
}
#endif /* UNIT_TEST */
