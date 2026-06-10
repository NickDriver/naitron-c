#define _GNU_SOURCE /* POSIX read/write/getenv under -std=c23 on Linux */
#include "ntc/controller.h"
#include "ntc/wire.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int ntc_reply_json(ntc_response *res, ntc_arena *a, int status, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap2);
    va_end(ap2);
    if (n < 0) { va_end(ap); return -1; }
    char *buf = ntc_arena_alloc(a, (size_t)n + 1);
    if (!buf) { va_end(ap); return -1; }
    vsnprintf(buf, (size_t)n + 1, fmt, ap);
    va_end(ap);
    res->status = status;
    res->content_type = NTC_SLICE_LIT("application/json");
    res->body = ntc_slice_new(buf, (size_t)n);
    return 0;
}

#define NTC_CTL_MAX_PAYLOAD (256 * 1024)

static int read_full(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0) return 0; /* EOF */
        if (errno == EINTR) continue;
        return -1;
    }
    return 1;
}

static int write_full(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return 1;
}

static int send_frame(int fd, uint8_t type, uint32_t rid,
                      const uint8_t *payload, uint32_t plen) {
    uint8_t hdr[NTC_WIRE_HEADER_LEN];
    ntc_wire_write_header(hdr, type, rid, plen);
    if (write_full(fd, hdr, sizeof hdr) <= 0) return -1;
    if (plen && write_full(fd, payload, plen) <= 0) return -1;
    return 0;
}

/* ---- streaming response API ---- */
struct ntc_stream { int fd; uint32_t rid; bool begun; bool ended; };

static int stream_begin(ntc_stream *st, int status, uint8_t flags, ntc_slice ctype) {
    if (st->begun || st->ended) return -1;
    uint8_t buf[1024];
    ssize_t n = ntc_wire_encode_response_begin(status, flags, ctype, buf, sizeof buf);
    if (n < 0) return -1;
    st->begun = true;
    return send_frame(st->fd, NTC_MSG_RESPONSE_BEGIN, st->rid, buf, (uint32_t)n);
}

int ntc_stream_begin(ntc_stream *st, int status, ntc_slice content_type) {
    return stream_begin(st, status, NTC_STREAM_FLAG_CHUNKED, content_type);
}

int ntc_sse_begin(ntc_stream *st) {
    return stream_begin(st, 200, NTC_STREAM_FLAG_SSE, NTC_SLICE_LIT("text/event-stream"));
}

int ntc_stream_write(ntc_stream *st, const void *data, size_t len) {
    if (!st->begun || st->ended) return -1;
    if (len == 0) return 0;
    if (len > 0xFFFFFFFFu - 4) return -1;
    /* CHUNK payload = u32 length + bytes; send the header+length then the data
     * (so a large chunk needs no contiguous staging buffer). */
    uint8_t hdr[NTC_WIRE_HEADER_LEN + 4];
    uint32_t plen = (uint32_t)len + 4;
    ntc_wire_write_header(hdr, NTC_MSG_RESPONSE_CHUNK, st->rid, plen);
    hdr[NTC_WIRE_HEADER_LEN + 0] = (uint8_t)(len >> 24);
    hdr[NTC_WIRE_HEADER_LEN + 1] = (uint8_t)(len >> 16);
    hdr[NTC_WIRE_HEADER_LEN + 2] = (uint8_t)(len >> 8);
    hdr[NTC_WIRE_HEADER_LEN + 3] = (uint8_t)(len);
    if (write_full(st->fd, hdr, sizeof hdr) <= 0) return -1;
    if (write_full(st->fd, data, len) <= 0) return -1;
    return 0;
}

int ntc_sse_send(ntc_stream *st, const char *event, const char *data) {
    if (!st->begun || st->ended) return -1;
    size_t elen = event ? strlen(event) : 0;
    size_t dlen = data ? strlen(data) : 0;
    size_t cap = (elen ? 7 + elen + 1 : 0) + 6 + dlen + 2 + 1;
    char *buf = malloc(cap);
    if (!buf) return -1;
    size_t o = 0;
    if (elen) o += (size_t)snprintf(buf + o, cap - o, "event: %s\n", event);
    o += (size_t)snprintf(buf + o, cap - o, "data: %s\n\n", data ? data : "");
    int rc = ntc_stream_write(st, buf, o);
    free(buf);
    return rc;
}

int ntc_stream_end(ntc_stream *st) {
    if (st->ended) return 0;
    st->ended = true;
    return send_frame(st->fd, NTC_MSG_RESPONSE_END, st->rid, NULL, 0);
}

/* ---- WebSocket API ---- */
struct ntc_ws { int fd; uint32_t rid; };

int ntc_ws_send(ntc_ws *ws, int opcode, const void *data, size_t len) {
    if (len > 0xFFFFFFFFu - 16) return -1;
    size_t cap = len + 8;
    uint8_t *pl = malloc(cap);
    if (!pl) return -1;
    ssize_t pn = ntc_wire_encode_ws_msg((uint8_t)opcode, ntc_slice_new((const char *)data, len), pl, cap);
    int rc = (pn > 0) ? send_frame(ws->fd, NTC_MSG_WS_MSG, ws->rid, pl, (uint32_t)pn) : -1;
    free(pl);
    return rc;
}

int ntc_ws_send_text(ntc_ws *ws, const char *text) {
    return ntc_ws_send(ws, NTC_WS_OP_TEXT, text, text ? strlen(text) : 0);
}

int ntc_ws_close(ntc_ws *ws) {
    uint8_t cb[2];
    ssize_t pn = ntc_wire_encode_ws_close(1000, cb, sizeof cb);
    if (pn < 0) return -1;
    return send_frame(ws->fd, NTC_MSG_WS_CLOSE, ws->rid, cb, (uint32_t)pn);
}

/* ---- multipart/form-data ---- */

bool ntc_multipart_boundary(ntc_slice content_type, char *out, size_t cap) {
    const char *b = memmem(content_type.ptr, content_type.len, "boundary=", 9);
    if (!b) return false;
    b += 9;
    const char *e = content_type.ptr + content_type.len;
    if (b < e && *b == '"') { b++; const char *q = memchr(b, '"', (size_t)(e - b)); if (q) e = q; }
    else { const char *semi = memchr(b, ';', (size_t)(e - b)); if (semi) e = semi; }
    size_t n = (size_t)(e - b);
    if (n == 0 || n >= cap) return false;
    memcpy(out, b, n); out[n] = '\0';
    return true;
}

/* pull foo="bar" out of [start,end) into *slot */
static void mp_quoted(const char *start, const char *end, const char *key, ntc_slice *slot) {
    size_t kl = strlen(key);
    const char *k = memmem(start, (size_t)(end - start), key, kl);
    if (!k) return;
    k += kl;
    const char *q = memchr(k, '"', (size_t)(end - k));
    if (q) *slot = ntc_slice_new(k, (size_t)(q - k));
}

int ntc_multipart_parse(ntc_slice body, const char *boundary,
                        ntc_multipart_part *parts, int max) {
    char delim[260], sep[264];
    int dl = snprintf(delim, sizeof delim, "--%s", boundary);
    int sl = snprintf(sep, sizeof sep, "\r\n--%s", boundary);
    if (dl <= 0 || dl >= (int)sizeof delim || sl <= 0) return -1;

    const char *end = body.ptr + body.len;
    const char *cur = memmem(body.ptr, body.len, delim, (size_t)dl);
    if (!cur) return -1;
    cur += dl;

    int count = 0;
    while (cur < end && count < max) {
        if (cur + 2 <= end && cur[0] == '-' && cur[1] == '-') break;      /* closing -- */
        if (cur + 2 <= end && cur[0] == '\r' && cur[1] == '\n') cur += 2; /* end of boundary line */
        else break;
        const char *next = memmem(cur, (size_t)(end - cur), sep, (size_t)sl);
        if (!next) break;

        ntc_multipart_part part;
        memset(&part, 0, sizeof part);
        const char *hdr_end = memmem(cur, (size_t)(next - cur), "\r\n\r\n", 4);
        const char *data_start = cur;
        if (hdr_end) {
            mp_quoted(cur, hdr_end, "name=\"", &part.name);
            mp_quoted(cur, hdr_end, "filename=\"", &part.filename);
            const char *ct = memmem(cur, (size_t)(hdr_end - cur), "Content-Type:", 13);
            if (ct) {
                ct += 13;
                while (ct < hdr_end && *ct == ' ') ct++;
                const char *eol = memmem(ct, (size_t)(hdr_end - ct), "\r\n", 2);
                part.content_type = ntc_slice_new(ct, (size_t)((eol ? eol : hdr_end) - ct));
            }
            data_start = hdr_end + 4;
        }
        part.data = ntc_slice_new(data_start, (size_t)(next - data_start));
        parts[count++] = part;
        cur = next + sl;
    }
    return count;
}

int ntc_controller_run(const ntc_controller *ctl) {
    if (!ctl || (!ctl->handle && !ctl->stream && !ctl->ws_open && !ctl->ws_message))
        return 2;

    const char *fds = getenv("NTC_CONTROLLER_FD");
    if (!fds) { fprintf(stderr, "controller: NTC_CONTROLLER_FD not set\n"); return 2; }
    int fd = atoi(fds);
    if (fd < 0) return 2;

    const char *name = ctl->name ? ctl->name : "controller";
    if (send_frame(fd, NTC_MSG_HELLO, 0, (const uint8_t *)name,
                   (uint32_t)strlen(name)) != 0)
        return 1;

    static uint8_t payload[NTC_CTL_MAX_PAYLOAD];
    for (;;) {
        uint8_t hdr[NTC_WIRE_HEADER_LEN];
        int r = read_full(fd, hdr, sizeof hdr);
        if (r <= 0) break; /* core closed the connection */

        ntc_wire_header h;
        if (!ntc_wire_parse_header(hdr, &h)) {
            fprintf(stderr, "controller: bad frame header\n");
            break;
        }
        if (h.length > sizeof payload) { fprintf(stderr, "controller: payload too big\n"); break; }
        if (h.length && read_full(fd, payload, h.length) <= 0) break;

        if (h.type == NTC_MSG_WELCOME) continue;
        if (h.type == NTC_MSG_PING) { (void)send_frame(fd, NTC_MSG_PONG, h.request_id, NULL, 0); continue; }

        if (h.type == NTC_MSG_WS_OPEN) {
            if (ctl->ws_open) {
                ntc_ws ws = { fd, h.request_id };
                ntc_request req;
                if (ntc_wire_decode_request(payload, h.length, &req))
                    ctl->ws_open(&req, &ws, ctl->udata);
            }
            continue;
        }
        if (h.type == NTC_MSG_WS_MSG) {
            if (ctl->ws_message) {
                ntc_ws ws = { fd, h.request_id };
                uint8_t opcode; ntc_slice data;
                if (ntc_wire_decode_ws_msg(payload, h.length, &opcode, &data))
                    ctl->ws_message(&ws, opcode, data.ptr, data.len, ctl->udata);
            }
            continue;
        }
        if (h.type == NTC_MSG_WS_CLOSE) {
            if (ctl->ws_close) { ntc_ws ws = { fd, h.request_id }; ctl->ws_close(&ws, ctl->udata); }
            continue;
        }

        if (h.type != NTC_MSG_REQUEST) continue;

        ntc_arena a;
        if (ntc_arena_init(&a, 16 * 1024) != NTC_OK) break;

        ntc_request req;

        if (ctl->stream) { /* streaming handler takes priority */
            ntc_stream st = { .fd = fd, .rid = h.request_id, .begun = false, .ended = false };
            bool ok = ntc_wire_decode_request(payload, h.length, &req);
            int hrc = ok ? ctl->stream(&req, &st, &a, ctl->udata) : 0;
            if (st.begun) {
                if (!st.ended) (void)ntc_stream_end(&st);
            } else {
                /* handler never began a stream: emit a one-shot response instead */
                ntc_response res = { .status = ok ? (hrc ? 500 : 204) : 400,
                                     .content_type = NTC_SLICE_LIT("text/plain"),
                                     .body = ok ? (hrc ? NTC_SLICE_LIT("stream error") : NTC_SLICE_LIT(""))
                                                : NTC_SLICE_LIT("bad request") };
                size_t cap = res.body.len + res.content_type.len + 64;
                uint8_t *out = ntc_arena_alloc(&a, cap);
                if (out) {
                    ssize_t pl = ntc_wire_encode_response(res.status, res.content_type, res.body, out, cap);
                    if (pl > 0) (void)send_frame(fd, NTC_MSG_RESPONSE, h.request_id, out, (uint32_t)pl);
                }
            }
            ntc_arena_destroy(&a);
            continue;
        }

        ntc_response res = { .status = 200,
                             .content_type = NTC_SLICE_LIT("application/json"),
                             .body = NTC_SLICE_LIT("") };
        if (!ntc_wire_decode_request(payload, h.length, &req)) {
            res.status = 400;
            res.content_type = NTC_SLICE_LIT("text/plain");
            res.body = NTC_SLICE_LIT("bad request");
        } else if (ctl->handle(&req, &res, &a, ctl->udata) != 0) {
            res.status = 500;
            res.content_type = NTC_SLICE_LIT("application/json");
            res.body = NTC_SLICE_LIT("{\"error\":\"controller error\"}");
        }

        size_t cap = res.body.len + res.content_type.len + 64;
        uint8_t *out = ntc_arena_alloc(&a, cap);
        if (out) {
            ssize_t pl = ntc_wire_encode_response(res.status, res.content_type,
                                                  res.body, out, cap);
            if (pl > 0)
                (void)send_frame(fd, NTC_MSG_RESPONSE, h.request_id, out, (uint32_t)pl);
        }
        ntc_arena_destroy(&a);
    }
    return 0;
}

#ifdef UNIT_TEST
#include "ntc/test.h"

TEST(multipart, boundary_extract) {
    char b[64];
    ASSERT_TRUE(ntc_multipart_boundary(NTC_SLICE_LIT("multipart/form-data; boundary=abc123"), b, sizeof b));
    ASSERT_TRUE(strcmp(b, "abc123") == 0);
    ASSERT_TRUE(ntc_multipart_boundary(NTC_SLICE_LIT("multipart/form-data; boundary=\"q-d-q\"; x=1"), b, sizeof b));
    ASSERT_TRUE(strcmp(b, "q-d-q") == 0);
    ASSERT_FALSE(ntc_multipart_boundary(NTC_SLICE_LIT("application/json"), b, sizeof b));
}

TEST(multipart, parse_fields_and_file) {
    const char *body =
        "--X\r\n"
        "Content-Disposition: form-data; name=\"field\"\r\n\r\n"
        "hello world\r\n"
        "--X\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "FILE\r\nDATA\r\n"
        "--X--\r\n";
    ntc_multipart_part parts[8];
    int n = ntc_multipart_parse(ntc_slice_new(body, strlen(body)), "X", parts, 8);
    ASSERT_EQ_INT(2, n);
    ASSERT_TRUE(ntc_slice_eq_cstr(parts[0].name, "field"));
    ASSERT_TRUE(ntc_slice_eq_cstr(parts[0].data, "hello world"));
    ASSERT_TRUE(ntc_slice_eq_cstr(parts[1].name, "file"));
    ASSERT_TRUE(ntc_slice_eq_cstr(parts[1].filename, "a.txt"));
    ASSERT_TRUE(ntc_slice_eq_cstr(parts[1].content_type, "text/plain"));
    /* data may contain CRLF internally; only the trailing CRLF before the boundary is stripped */
    ASSERT_TRUE(ntc_slice_eq_cstr(parts[1].data, "FILE\r\nDATA"));
}
#endif /* UNIT_TEST */
