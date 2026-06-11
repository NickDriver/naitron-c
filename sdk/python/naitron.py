"""naitron-c controller SDK (Python). Implements the IPC wire protocol (v2 +
v3 streaming).

Atomic controllers define handler(req) -> (status, content_type, body) and call
naitron.run(handler, name).

Streaming controllers define handler(req, stream) -> None, drive the `stream`
(sse_begin/sse_send or begin/write, then it auto-ends), and call
naitron.run(handler, name, stream=True). See docs/WIRE_PROTOCOL.md.
"""
import os
import struct

MAGIC = 0x4E544331
VERSION = 2  # written version stays 2; v3 adds new message TYPES (7-9)
HELLO, WELCOME, REQUEST, RESPONSE, PING, PONG = 1, 2, 3, 4, 5, 6
RESPONSE_BEGIN, RESPONSE_CHUNK, RESPONSE_END = 7, 8, 9
STREAM_FLAG_SSE, STREAM_FLAG_CHUNKED = 0x01, 0x02


def _read_exact(fd, n):
    buf = b""
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _write_all(fd, data):
    while data:
        n = os.write(fd, data)
        data = data[n:]


def _send_frame(fd, typ, rid, payload=b""):
    _write_all(fd, struct.pack(">IBBHII", MAGIC, VERSION, typ, 0, rid, len(payload)))
    if payload:
        _write_all(fd, payload)


def _slice16(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack(">H", len(b)) + b


def _rd_slice16(buf, off):
    (n,) = struct.unpack_from(">H", buf, off)
    off += 2
    return buf[off:off + n], off + n


def _decode_request(p):
    off = 0
    method, off = _rd_slice16(p, off)
    path, off = _rd_slice16(p, off)
    query, off = _rd_slice16(p, off)
    (nh,) = struct.unpack_from(">H", p, off); off += 2
    headers = {}
    for _ in range(nh):
        k, off = _rd_slice16(p, off)
        v, off = _rd_slice16(p, off)
        headers[k.decode("latin1").lower()] = v.decode("latin1")
    (npar,) = struct.unpack_from(">H", p, off); off += 2
    params = {}
    for _ in range(npar):
        k, off = _rd_slice16(p, off)
        v, off = _rd_slice16(p, off)
        params[k.decode("latin1")] = v.decode("latin1")
    sub, off = _rd_slice16(p, off)
    scope, off = _rd_slice16(p, off)
    (blen,) = struct.unpack_from(">I", p, off); off += 4
    body = p[off:off + blen]
    return {
        "method": method.decode("latin1"), "path": path.decode("latin1"),
        "query": query.decode("latin1"), "headers": headers, "params": params,
        "sub": sub.decode("latin1"), "scope": scope.decode("latin1"), "body": body,
    }


def _encode_response(status, content_type, body, headers=None):
    if isinstance(body, str):
        body = body.encode()
    ct = content_type.encode()
    out = struct.pack(">HH", status, len(ct)) + ct + struct.pack(">I", len(body)) + body
    if headers:
        items = headers.items() if isinstance(headers, dict) else headers
        blob = "".join("%s: %s\r\n" % (k, v) for k, v in items).encode("latin1")
        out += struct.pack(">H", len(blob)) + blob  # trailing header block (backward-compat)
    return out


def redirect(location, status=302):
    """A handler can `return naitron.redirect("/")` to send a 302."""
    return (status, "text/html; charset=utf-8", "", {"Location": location})


class Stream:
    """A live streaming response. Use sse_begin()/sse_send() for Server-Sent
    Events, or begin()/write() for generic Transfer-Encoding: chunked. The SDK
    auto-emits RESPONSE_END once the handler returns."""

    def __init__(self, fd, rid):
        self.fd = fd
        self.rid = rid
        self.begun = False
        self.ended = False

    def sse_begin(self, status=200):
        if self.begun:
            return
        payload = struct.pack(">HB", status, STREAM_FLAG_SSE) + _slice16("text/event-stream")
        _send_frame(self.fd, RESPONSE_BEGIN, self.rid, payload)
        self.begun = True

    def begin(self, status=200, content_type="application/octet-stream"):
        if self.begun:
            return
        payload = struct.pack(">HB", status, STREAM_FLAG_CHUNKED) + _slice16(content_type)
        _send_frame(self.fd, RESPONSE_BEGIN, self.rid, payload)
        self.begun = True

    def write(self, data):
        if not self.begun:
            self.begin()
        if isinstance(data, str):
            data = data.encode()
        _send_frame(self.fd, RESPONSE_CHUNK, self.rid, struct.pack(">I", len(data)) + data)

    def sse_send(self, event, data):
        if not self.begun:
            self.sse_begin()
        self.write("event: %s\ndata: %s\n\n" % (event, data))

    def end(self):
        if self.ended:
            return
        _send_frame(self.fd, RESPONSE_END, self.rid, b"")
        self.ended = True


def run(handler, name="controller", stream=False):
    fd = int(os.environ["NTC_CONTROLLER_FD"])
    _send_frame(fd, HELLO, 0, name.encode())
    while True:
        hdr = _read_exact(fd, 16)
        if not hdr:
            break
        magic, ver, typ, _r, rid, plen = struct.unpack(">IBBHII", hdr)
        if magic != MAGIC or ver != VERSION:
            break
        payload = _read_exact(fd, plen) if plen else b""
        if payload is None:
            break
        if typ == PING:
            _send_frame(fd, PONG, rid)
            continue
        if typ != REQUEST:
            continue
        req = _decode_request(payload)
        if stream:
            st = Stream(fd, rid)
            try:
                handler(req, st)
            except Exception:
                if not st.begun:
                    _send_frame(fd, RESPONSE, rid,
                                _encode_response(500, "application/json",
                                                 '{"error":"controller error"}'))
                    continue
            finally:
                if st.begun and not st.ended:
                    st.end()
        else:
            headers = None
            try:
                res = handler(req)
                if len(res) == 4:
                    status, ctype, body, headers = res   # (status, ctype, body, headers)
                else:
                    status, ctype, body = res
            except Exception:
                status, ctype, body = 500, "application/json", '{"error":"controller error"}'
            _send_frame(fd, RESPONSE, rid, _encode_response(status, ctype, body, headers))
