"""naitron-c controller SDK (Python). Implements the v2 IPC wire protocol.

A controller defines a handler(req) -> (status, content_type, body) and calls
naitron.run(handler, name). See docs/WIRE_PROTOCOL.md.
"""
import os
import struct

MAGIC = 0x4E544331
VERSION = 2
HELLO, WELCOME, REQUEST, RESPONSE, PING, PONG = 1, 2, 3, 4, 5, 6


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


def _encode_response(status, content_type, body):
    if isinstance(body, str):
        body = body.encode()
    ct = content_type.encode()
    return struct.pack(">HH", status, len(ct)) + ct + struct.pack(">I", len(body)) + body


def run(handler, name="controller"):
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
        try:
            status, ctype, body = handler(req)
        except Exception:
            status, ctype, body = 500, "application/json", '{"error":"controller error"}'
        _send_frame(fd, RESPONSE, rid, _encode_response(status, ctype, body))
