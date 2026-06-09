//! naitron-c controller SDK (Rust). Implements the v2 IPC wire protocol.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

const MAGIC: u32 = 0x4E54_4331;
const VERSION: u8 = 2;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub params: HashMap<String, String>,
    pub sub: String,
    pub scope: String,
    pub body: Vec<u8>,
}

fn read_exact(f: &mut std::fs::File, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn rd_slice16(p: &[u8], off: &mut usize) -> Vec<u8> {
    let n = u16::from_be_bytes([p[*off], p[*off + 1]]) as usize;
    *off += 2;
    let s = p[*off..*off + n].to_vec();
    *off += n;
    s
}

fn decode_request(p: &[u8]) -> Request {
    let mut off = 0usize;
    let method = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
    let path = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
    let query = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
    let nh = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
    off += 2;
    let mut headers = HashMap::new();
    for _ in 0..nh {
        let k = String::from_utf8_lossy(&rd_slice16(p, &mut off)).to_lowercase();
        let v = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
        headers.insert(k, v);
    }
    let np = u16::from_be_bytes([p[off], p[off + 1]]) as usize;
    off += 2;
    let mut params = HashMap::new();
    for _ in 0..np {
        let k = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
        let v = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
        params.insert(k, v);
    }
    let sub = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
    let scope = String::from_utf8_lossy(&rd_slice16(p, &mut off)).into_owned();
    let blen = u32::from_be_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]]) as usize;
    off += 4;
    let body = p[off..off + blen].to_vec();
    Request { method, path, query, headers, params, sub, scope, body }
}

fn encode_response(status: u16, ctype: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ctype.len() + body.len());
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(&(ctype.len() as u16).to_be_bytes());
    out.extend_from_slice(ctype.as_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn send_frame(f: &mut std::fs::File, typ: u8, rid: u32, payload: &[u8]) {
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    h[4] = VERSION;
    h[5] = typ;
    h[8..12].copy_from_slice(&rid.to_be_bytes());
    h[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    let _ = f.write_all(&h);
    if !payload.is_empty() {
        let _ = f.write_all(payload);
    }
}

pub fn run<F: Fn(Request) -> (u16, String, Vec<u8>)>(handler: F, name: &str) {
    let fd: i32 = std::env::var("NTC_CONTROLLER_FD").unwrap().parse().unwrap();
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    send_frame(&mut f, 1, 0, name.as_bytes());
    loop {
        let hdr = match read_exact(&mut f, 16) {
            Some(h) => h,
            None => break,
        };
        let magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let ver = hdr[4];
        let typ = hdr[5];
        let rid = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let plen = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;
        if magic != MAGIC || ver != VERSION {
            break;
        }
        let payload = if plen > 0 {
            match read_exact(&mut f, plen) {
                Some(p) => p,
                None => break,
            }
        } else {
            Vec::new()
        };
        if typ == 5 {
            send_frame(&mut f, 6, rid, &[]);
            continue;
        }
        if typ != 3 {
            continue;
        }
        let (status, ctype, body) = handler(decode_request(&payload));
        send_frame(&mut f, 4, rid, &encode_response(status, &ctype, &body));
    }
}
