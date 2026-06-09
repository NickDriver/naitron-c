// naitron-c controller SDK (TypeScript/Node). Implements the v2 IPC wire protocol.
import * as fs from "node:fs";

const MAGIC = 0x4e544331, VERSION = 2;
const HELLO = 1, REQUEST = 3, RESPONSE = 4, PING = 5, PONG = 6;

export interface NtcRequest {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  params: Record<string, string>;
  sub: string;
  scope: string;
  body: Buffer;
}

export type Handler = (req: NtcRequest) => [number, string, string | Buffer];

function readExact(fd: number, n: number): Buffer | null {
  const buf = Buffer.alloc(n);
  let got = 0;
  while (got < n) {
    let r: number;
    try { r = fs.readSync(fd, buf, got, n - got, null); }
    catch (e: any) { if (e.code === "EAGAIN" || e.code === "EINTR") continue; throw e; }
    if (r === 0) return null;
    got += r;
  }
  return buf;
}

function writeAll(fd: number, data: Buffer): void {
  let off = 0;
  while (off < data.length) {
    try { off += fs.writeSync(fd, data, off, data.length - off, null); }
    catch (e: any) { if (e.code === "EAGAIN" || e.code === "EINTR") continue; throw e; }
  }
}

function sendFrame(fd: number, typ: number, rid: number, payload: Buffer = Buffer.alloc(0)): void {
  const h = Buffer.alloc(16);
  h.writeUInt32BE(MAGIC, 0); h.writeUInt8(VERSION, 4); h.writeUInt8(typ, 5);
  h.writeUInt16BE(0, 6); h.writeUInt32BE(rid, 8); h.writeUInt32BE(payload.length, 12);
  writeAll(fd, h);
  if (payload.length) writeAll(fd, payload);
}

function rdSlice16(buf: Buffer, off: number): [Buffer, number] {
  const n = buf.readUInt16BE(off);
  return [buf.subarray(off + 2, off + 2 + n), off + 2 + n];
}

function decodeRequest(p: Buffer): NtcRequest {
  let off = 0, s: Buffer;
  [s, off] = rdSlice16(p, off); const method = s.toString("latin1");
  [s, off] = rdSlice16(p, off); const path = s.toString("latin1");
  [s, off] = rdSlice16(p, off); const query = s.toString("latin1");
  const nh = p.readUInt16BE(off); off += 2;
  const headers: Record<string, string> = {};
  for (let i = 0; i < nh; i++) {
    let k: Buffer, v: Buffer;
    [k, off] = rdSlice16(p, off); [v, off] = rdSlice16(p, off);
    headers[k.toString("latin1").toLowerCase()] = v.toString("latin1");
  }
  const np = p.readUInt16BE(off); off += 2;
  const params: Record<string, string> = {};
  for (let i = 0; i < np; i++) {
    let k: Buffer, v: Buffer;
    [k, off] = rdSlice16(p, off); [v, off] = rdSlice16(p, off);
    params[k.toString("latin1")] = v.toString("latin1");
  }
  let sub: Buffer, scope: Buffer;
  [sub, off] = rdSlice16(p, off); [scope, off] = rdSlice16(p, off);
  const blen = p.readUInt32BE(off); off += 4;
  return {
    method, path, query, headers, params,
    sub: sub.toString("latin1"), scope: scope.toString("latin1"),
    body: p.subarray(off, off + blen),
  };
}

function encodeResponse(status: number, ctype: string, body: string | Buffer): Buffer {
  const b = typeof body === "string" ? Buffer.from(body) : body;
  const ct = Buffer.from(ctype);
  const out = Buffer.alloc(2 + 2 + ct.length + 4 + b.length);
  let o = 0;
  out.writeUInt16BE(status, o); o += 2;
  out.writeUInt16BE(ct.length, o); o += 2; ct.copy(out, o); o += ct.length;
  out.writeUInt32BE(b.length, o); o += 4; b.copy(out, o);
  return out;
}

export function run(handler: Handler, name = "controller"): void {
  const fd = parseInt(process.env.NTC_CONTROLLER_FD!, 10);
  sendFrame(fd, HELLO, 0, Buffer.from(name));
  for (;;) {
    const hdr = readExact(fd, 16);
    if (!hdr) break;
    const magic = hdr.readUInt32BE(0), ver = hdr.readUInt8(4), typ = hdr.readUInt8(5);
    const rid = hdr.readUInt32BE(8), plen = hdr.readUInt32BE(12);
    if (magic !== MAGIC || ver !== VERSION) break;
    const payload = plen ? readExact(fd, plen) : Buffer.alloc(0);
    if (payload === null) break;
    if (typ === PING) { sendFrame(fd, PONG, rid); continue; }
    if (typ !== REQUEST) continue;
    let status: number, ctype: string, body: string | Buffer;
    try { [status, ctype, body] = handler(decodeRequest(payload)); }
    catch { status = 500; ctype = "application/json"; body = '{"error":"controller error"}'; }
    sendFrame(fd, RESPONSE, rid, encodeResponse(status, ctype, body));
  }
}
