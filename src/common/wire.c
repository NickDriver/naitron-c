#include "ntc/wire.h"

#include <string.h>

/* ---- big-endian primitives ---- */
static void put_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ---- bounded writer ---- */
typedef struct { uint8_t *p; size_t cap, off; bool err; } wbuf;
static void w_need(wbuf *w, size_t n) { if (w->off + n > w->cap) w->err = true; }
static void w_u8(wbuf *w, uint8_t v) { w_need(w, 1); if (!w->err) { w->p[w->off] = v; w->off += 1; } }
static void w_u16(wbuf *w, uint16_t v){ w_need(w, 2); if (!w->err) { put_u16(w->p + w->off, v); w->off += 2; } }
static void w_u32(wbuf *w, uint32_t v){ w_need(w, 4); if (!w->err) { put_u32(w->p + w->off, v); w->off += 4; } }
static void w_bytes(wbuf *w, const char *s, size_t n) {
    w_need(w, n);
    if (!w->err && n) { memcpy(w->p + w->off, s, n); w->off += n; }
}
static void w_slice16(wbuf *w, ntc_slice s) {
    if (s.len > 0xFFFF) { w->err = true; return; }
    w_u16(w, (uint16_t)s.len);
    w_bytes(w, s.ptr, s.len);
}

/* ---- bounded reader ---- */
typedef struct { const uint8_t *p; size_t len, off; bool err; } rbuf;
static uint8_t r_u8(rbuf *r) { if (r->off + 1 > r->len) { r->err = true; return 0; } return r->p[r->off++]; }
static uint16_t r_u16(rbuf *r) { if (r->off + 2 > r->len) { r->err = true; return 0; } uint16_t v = get_u16(r->p + r->off); r->off += 2; return v; }
static uint32_t r_u32(rbuf *r) { if (r->off + 4 > r->len) { r->err = true; return 0; } uint32_t v = get_u32(r->p + r->off); r->off += 4; return v; }
static ntc_slice r_slice16(rbuf *r) {
    uint16_t n = r_u16(r);
    if (r->err || r->off + n > r->len) { r->err = true; return ntc_slice_new(NULL, 0); }
    ntc_slice s = ntc_slice_new((const char *)(r->p + r->off), n);
    r->off += n;
    return s;
}
static ntc_slice r_slice32(rbuf *r) {
    uint32_t n = r_u32(r);
    if (r->err || r->off + n > r->len) { r->err = true; return ntc_slice_new(NULL, 0); }
    ntc_slice s = ntc_slice_new((const char *)(r->p + r->off), n);
    r->off += n;
    return s;
}

/* ---- framing ---- */
void ntc_wire_write_header(uint8_t out[NTC_WIRE_HEADER_LEN], uint8_t type,
                           uint32_t request_id, uint32_t payload_len) {
    put_u32(out, NTC_WIRE_MAGIC);
    out[4] = NTC_WIRE_VERSION;
    out[5] = type;
    out[6] = 0;
    out[7] = 0;
    put_u32(out + 8, request_id);
    put_u32(out + 12, payload_len);
}

/* Accept any wire version in [NTC_WIRE_VERSION, NTC_WIRE_VERSION_MAX] so a v2
 * peer and a v3 (streaming) peer interoperate; capability is keyed off message
 * type, not the version byte. */
static bool version_ok(uint8_t v) {
    return v >= NTC_WIRE_VERSION && v <= NTC_WIRE_VERSION_MAX;
}

bool ntc_wire_parse_header(const uint8_t buf[NTC_WIRE_HEADER_LEN],
                           ntc_wire_header *out) {
    if (get_u32(buf) != NTC_WIRE_MAGIC) return false;
    if (!version_ok(buf[4])) return false;
    out->version = buf[4];
    out->type = buf[5];
    out->request_id = get_u32(buf + 8);
    out->length = get_u32(buf + 12);
    return true;
}

int ntc_wire_read_frame(const uint8_t *buf, size_t len, ntc_wire_header *hdr,
                        const uint8_t **payload, size_t *consumed) {
    if (len < NTC_WIRE_HEADER_LEN) return 0;
    if (get_u32(buf) != NTC_WIRE_MAGIC) return -1;
    if (!version_ok(buf[4])) return -1;
    uint32_t plen = get_u32(buf + 12);
    if (len < (size_t)NTC_WIRE_HEADER_LEN + plen) return 0;
    hdr->version = buf[4];
    hdr->type = buf[5];
    hdr->request_id = get_u32(buf + 8);
    hdr->length = plen;
    *payload = buf + NTC_WIRE_HEADER_LEN;
    *consumed = (size_t)NTC_WIRE_HEADER_LEN + plen;
    return 1;
}

/* ---- request payload ---- */
ssize_t ntc_wire_encode_request(const ntc_request *req, uint8_t *out, size_t cap) {
    wbuf w = { out, cap, 0, false };
    w_slice16(&w, req->method);
    w_slice16(&w, req->path);
    w_slice16(&w, req->query);
    size_t nh = req->nheaders > NTC_MAX_HEADERS ? NTC_MAX_HEADERS : req->nheaders;
    w_u16(&w, (uint16_t)nh);
    for (size_t i = 0; i < nh; i++) {
        w_slice16(&w, req->headers[i].name);
        w_slice16(&w, req->headers[i].value);
    }
    size_t np = req->nparams > NTC_MAX_PARAMS ? NTC_MAX_PARAMS : req->nparams;
    w_u16(&w, (uint16_t)np);
    for (size_t i = 0; i < np; i++) {
        w_slice16(&w, req->params[i].name);
        w_slice16(&w, req->params[i].value);
    }
    w_slice16(&w, req->auth_sub);
    w_slice16(&w, req->auth_scope);
    w_u32(&w, (uint32_t)req->body.len);
    w_bytes(&w, req->body.ptr, req->body.len);
    return w.err ? -1 : (ssize_t)w.off;
}

bool ntc_wire_decode_request(const uint8_t *buf, size_t len, ntc_request *req) {
    rbuf r = { buf, len, 0, false };
    memset(req, 0, sizeof *req);
    req->minor_version = 1;
    req->method = r_slice16(&r);
    req->path = r_slice16(&r);
    req->target = req->path;
    req->query = r_slice16(&r);
    uint16_t nh = r_u16(&r);
    if (nh > NTC_MAX_HEADERS) return false;
    for (uint16_t i = 0; i < nh; i++) {
        req->headers[i].name = r_slice16(&r);
        req->headers[i].value = r_slice16(&r);
    }
    req->nheaders = nh;
    uint16_t np = r_u16(&r);
    if (np > NTC_MAX_PARAMS) return false;
    for (uint16_t i = 0; i < np; i++) {
        req->params[i].name = r_slice16(&r);
        req->params[i].value = r_slice16(&r);
    }
    req->nparams = np;
    req->auth_sub = r_slice16(&r);
    req->auth_scope = r_slice16(&r);
    req->body = r_slice32(&r);
    req->content_length = req->body.len;
    req->has_content_length = req->body.len > 0;
    return !r.err;
}

/* ---- response payload ---- */
ssize_t ntc_wire_encode_response(int status, ntc_slice ctype, ntc_slice body,
                                 uint8_t *out, size_t cap) {
    wbuf w = { out, cap, 0, false };
    w_u16(&w, (uint16_t)status);
    w_slice16(&w, ctype);
    w_u32(&w, (uint32_t)body.len);
    w_bytes(&w, body.ptr, body.len);
    return w.err ? -1 : (ssize_t)w.off;
}

bool ntc_wire_decode_response(const uint8_t *buf, size_t len, int *status,
                              ntc_slice *ctype, ntc_slice *body) {
    rbuf r = { buf, len, 0, false };
    *status = (int)r_u16(&r);
    *ctype = r_slice16(&r);
    *body = r_slice32(&r);
    return !r.err;
}

ssize_t ntc_wire_encode_response_ex(int status, ntc_slice ctype, ntc_slice body,
                                    ntc_slice headers, uint8_t *out, size_t cap) {
    wbuf w = { out, cap, 0, false };
    w_u16(&w, (uint16_t)status);
    w_slice16(&w, ctype);
    w_u32(&w, (uint32_t)body.len);
    w_bytes(&w, body.ptr, body.len);
    w_slice16(&w, headers); /* trailing: u16 len + raw header bytes */
    return w.err ? -1 : (ssize_t)w.off;
}

bool ntc_wire_decode_response_ex(const uint8_t *buf, size_t len, int *status,
                                 ntc_slice *ctype, ntc_slice *body, ntc_slice *headers) {
    rbuf r = { buf, len, 0, false };
    *status = (int)r_u16(&r);
    *ctype = r_slice16(&r);
    *body = r_slice32(&r);
    if (r.off < r.len) *headers = r_slice16(&r); /* present only on an _ex payload */
    else *headers = ntc_slice_new(NULL, 0);
    return !r.err;
}

/* ---- streaming payloads (v3) ---- */
ssize_t ntc_wire_encode_response_begin(int status, uint8_t flags, ntc_slice ctype,
                                       uint8_t *out, size_t cap) {
    wbuf w = { out, cap, 0, false };
    w_u16(&w, (uint16_t)status);
    w_u8(&w, flags);
    w_slice16(&w, ctype);
    return w.err ? -1 : (ssize_t)w.off;
}

bool ntc_wire_decode_response_begin(const uint8_t *buf, size_t len, int *status,
                                    uint8_t *flags, ntc_slice *ctype) {
    rbuf r = { buf, len, 0, false };
    *status = (int)r_u16(&r);
    *flags = r_u8(&r);
    *ctype = r_slice16(&r);
    return !r.err;
}

ssize_t ntc_wire_encode_chunk(ntc_slice data, uint8_t *out, size_t cap) {
    wbuf w = { out, cap, 0, false };
    w_u32(&w, (uint32_t)data.len);
    w_bytes(&w, data.ptr, data.len);
    return w.err ? -1 : (ssize_t)w.off;
}

bool ntc_wire_decode_chunk(const uint8_t *buf, size_t len, ntc_slice *data) {
    rbuf r = { buf, len, 0, false };
    *data = r_slice32(&r);
    return !r.err;
}

ssize_t ntc_wire_encode_ws_msg(uint8_t opcode, ntc_slice data, uint8_t *out, size_t cap) {
    wbuf w = { out, cap, 0, false };
    w_u8(&w, opcode);
    w_u32(&w, (uint32_t)data.len);
    w_bytes(&w, data.ptr, data.len);
    return w.err ? -1 : (ssize_t)w.off;
}

bool ntc_wire_decode_ws_msg(const uint8_t *buf, size_t len, uint8_t *opcode, ntc_slice *data) {
    rbuf r = { buf, len, 0, false };
    *opcode = r_u8(&r);
    *data = r_slice32(&r);
    return !r.err;
}

ssize_t ntc_wire_encode_ws_close(uint16_t code, uint8_t *out, size_t cap) {
    wbuf w = { out, cap, 0, false };
    w_u16(&w, code);
    return w.err ? -1 : (ssize_t)w.off;
}

bool ntc_wire_decode_ws_close(const uint8_t *buf, size_t len, uint16_t *code) {
    rbuf r = { buf, len, 0, false };
    *code = r_u16(&r);
    return !r.err;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(wire, header_roundtrip) {
    uint8_t h[NTC_WIRE_HEADER_LEN];
    ntc_wire_write_header(h, NTC_MSG_REQUEST, 0xABCD1234u, 100);
    ntc_wire_header hdr; const uint8_t *pl; size_t consumed;
    uint8_t buf[NTC_WIRE_HEADER_LEN + 100];
    memcpy(buf, h, sizeof h);
    ASSERT_EQ_INT(1, ntc_wire_read_frame(buf, sizeof buf, &hdr, &pl, &consumed));
    ASSERT_EQ_INT(NTC_MSG_REQUEST, hdr.type);
    ASSERT_EQ_UINT(0xABCD1234u, hdr.request_id);
    ASSERT_EQ_UINT(100u, hdr.length);
    ASSERT_EQ_UINT((unsigned)(NTC_WIRE_HEADER_LEN + 100), consumed);
}

TEST(wire, read_frame_incomplete) {
    uint8_t h[NTC_WIRE_HEADER_LEN];
    ntc_wire_write_header(h, NTC_MSG_REQUEST, 1, 50);
    ntc_wire_header hdr; const uint8_t *pl; size_t consumed;
    ASSERT_EQ_INT(0, ntc_wire_read_frame(h, sizeof h, &hdr, &pl, &consumed)); /* no payload yet */
}

TEST(wire, read_frame_bad_magic) {
    uint8_t buf[NTC_WIRE_HEADER_LEN] = { 'X','X','X','X' };
    ntc_wire_header hdr; const uint8_t *pl; size_t consumed;
    ASSERT_EQ_INT(-1, ntc_wire_read_frame(buf, sizeof buf, &hdr, &pl, &consumed));
}

TEST(wire, request_roundtrip) {
    const char *raw = "POST /api/x?y=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    ntc_request in; size_t c;
    ASSERT_EQ_INT(NTC_PARSE_OK, ntc_http_parse_request(raw, strlen(raw), &in, &c));

    uint8_t enc[1024];
    ssize_t n = ntc_wire_encode_request(&in, enc, sizeof enc);
    ASSERT_TRUE(n > 0);

    ntc_request out;
    ASSERT_TRUE(ntc_wire_decode_request(enc, (size_t)n, &out));
    ASSERT_TRUE(ntc_slice_eq_cstr(out.method, "POST"));
    ASSERT_TRUE(ntc_slice_eq_cstr(out.path, "/api/x"));
    ASSERT_TRUE(ntc_slice_eq_cstr(out.query, "y=1"));
    ASSERT_EQ_UINT(2u, out.nheaders);
    ASSERT_TRUE(ntc_slice_eq_cstr(ntc_http_header(&out, "host"), "h"));
    ASSERT_TRUE(ntc_slice_eq_cstr(out.body, "abc"));
}

TEST(wire, response_roundtrip) {
    uint8_t enc[256];
    ssize_t n = ntc_wire_encode_response(201, NTC_SLICE_LIT("application/json"),
                                         NTC_SLICE_LIT("{\"id\":1}"), enc, sizeof enc);
    ASSERT_TRUE(n > 0);
    int status; ntc_slice ctype, body;
    ASSERT_TRUE(ntc_wire_decode_response(enc, (size_t)n, &status, &ctype, &body));
    ASSERT_EQ_INT(201, status);
    ASSERT_TRUE(ntc_slice_eq_cstr(ctype, "application/json"));
    ASSERT_TRUE(ntc_slice_eq_cstr(body, "{\"id\":1}"));
}

TEST(wire, response_begin_roundtrip) {
    uint8_t enc[256];
    ssize_t n = ntc_wire_encode_response_begin(200, NTC_STREAM_FLAG_SSE,
                    NTC_SLICE_LIT("text/event-stream"), enc, sizeof enc);
    ASSERT_TRUE(n > 0);
    int status; uint8_t flags; ntc_slice ctype;
    ASSERT_TRUE(ntc_wire_decode_response_begin(enc, (size_t)n, &status, &flags, &ctype));
    ASSERT_EQ_INT(200, status);
    ASSERT_EQ_INT(NTC_STREAM_FLAG_SSE, (int)flags);
    ASSERT_TRUE(ntc_slice_eq_cstr(ctype, "text/event-stream"));
}

TEST(wire, chunk_roundtrip) {
    const char raw[] = { 'a', 0, 'b', 'c', 0, 'd' }; /* embedded NULs are fine */
    uint8_t enc[64];
    ssize_t n = ntc_wire_encode_chunk(ntc_slice_new(raw, sizeof raw), enc, sizeof enc);
    ASSERT_TRUE(n > 0);
    ntc_slice data;
    ASSERT_TRUE(ntc_wire_decode_chunk(enc, (size_t)n, &data));
    ASSERT_EQ_UINT((unsigned)sizeof raw, (unsigned)data.len);
    ASSERT_TRUE(memcmp(data.ptr, raw, sizeof raw) == 0);
}

TEST(wire, response_headers_roundtrip) {
    uint8_t enc[256];
    const char *hdr = "Location: /x\r\nX-Test: 1\r\n";
    ssize_t n = ntc_wire_encode_response_ex(302, NTC_SLICE_LIT("text/html"),
                    NTC_SLICE_LIT(""), ntc_slice_cstr(hdr), enc, sizeof enc);
    ASSERT_TRUE(n > 0);
    int status; ntc_slice ct, body, headers;
    ASSERT_TRUE(ntc_wire_decode_response_ex(enc, (size_t)n, &status, &ct, &body, &headers));
    ASSERT_EQ_INT(302, status);
    ASSERT_EQ_UINT((unsigned)strlen(hdr), (unsigned)headers.len);
    ASSERT_TRUE(memcmp(headers.ptr, hdr, headers.len) == 0);

    /* a plain (no-header) RESPONSE payload decodes via _ex with empty headers */
    ssize_t pn = ntc_wire_encode_response(200, NTC_SLICE_LIT("application/json"),
                                          NTC_SLICE_LIT("{}"), enc, sizeof enc);
    ASSERT_TRUE(pn > 0);
    ASSERT_TRUE(ntc_wire_decode_response_ex(enc, (size_t)pn, &status, &ct, &body, &headers));
    ASSERT_EQ_INT(200, status);
    ASSERT_EQ_UINT(0u, (unsigned)headers.len);
    ASSERT_TRUE(ntc_slice_eq_cstr(body, "{}"));
}

TEST(wire, ws_msg_roundtrip) {
    uint8_t enc[64];
    ssize_t n = ntc_wire_encode_ws_msg(1, ntc_slice_new("ping", 4), enc, sizeof enc);
    ASSERT_TRUE(n > 0);
    uint8_t op; ntc_slice data;
    ASSERT_TRUE(ntc_wire_decode_ws_msg(enc, (size_t)n, &op, &data));
    ASSERT_EQ_INT(1, (int)op);
    ASSERT_EQ_UINT(4u, (unsigned)data.len);
    ASSERT_TRUE(memcmp(data.ptr, "ping", 4) == 0);

    uint16_t code = 0;
    n = ntc_wire_encode_ws_close(1000, enc, sizeof enc);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(ntc_wire_decode_ws_close(enc, (size_t)n, &code));
    ASSERT_EQ_INT(1000, (int)code);
}

TEST(wire, version_range_accept) {
    /* readers accept wire versions 2..3 (compat guard); 1 and 4 are rejected */
    uint8_t buf[NTC_WIRE_HEADER_LEN];
    ntc_wire_header hdr; const uint8_t *pl; size_t consumed;
    ntc_wire_write_header(buf, NTC_MSG_RESPONSE_BEGIN, 7, 0);
    ASSERT_EQ_INT(1, ntc_wire_read_frame(buf, sizeof buf, &hdr, &pl, &consumed)); /* v2 (written) */
    buf[4] = 3;
    ASSERT_EQ_INT(1, ntc_wire_read_frame(buf, sizeof buf, &hdr, &pl, &consumed)); /* v3 */
    ASSERT_TRUE(ntc_wire_parse_header(buf, &hdr));
    buf[4] = 1;
    ASSERT_EQ_INT(-1, ntc_wire_read_frame(buf, sizeof buf, &hdr, &pl, &consumed));
    ASSERT_FALSE(ntc_wire_parse_header(buf, &hdr));
    buf[4] = 4;
    ASSERT_EQ_INT(-1, ntc_wire_read_frame(buf, sizeof buf, &hdr, &pl, &consumed));
}

TEST(wire, encode_request_too_small) {
    ntc_request req;
    memset(&req, 0, sizeof req);
    req.method = NTC_SLICE_LIT("GET");
    req.path = NTC_SLICE_LIT("/x");
    req.query = NTC_SLICE_LIT("");
    req.body = NTC_SLICE_LIT("");
    uint8_t tiny[4];
    ASSERT_EQ_INT(-1, (int)ntc_wire_encode_request(&req, tiny, sizeof tiny));
}
#endif /* UNIT_TEST */
