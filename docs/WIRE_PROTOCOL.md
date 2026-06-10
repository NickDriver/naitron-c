# naitron-c IPC wire protocol (v2 + v3 streaming)

The contract between the core (gateway) and controller processes. A controller
SDK in any language implements this. The C SDK (`src/common/controller_sdk.c`)
is the reference. All integers are **big-endian**; strings are length-prefixed
(not NUL-terminated).

**v3 adds streaming responses** (`RESPONSE_BEGIN/CHUNK/END`) as new message
types. The shared 16-byte header's `version` byte stays **2** (so an unmodified
v2 controller keeps accepting gateway frames); readers accept versions **2–3**
and dispatch on the message *type*. A v2 peer simply never emits or sees the new
types. Caveat: do not route a streaming (v3) controller through a pre-M8 core —
it would ignore the streaming frames and the client would hang.

## Transport

A controller is spawned by the core with a connected `AF_UNIX`/`SOCK_STREAM`
socket; the fd number is passed in the env var **`NTC_CONTROLLER_FD`**. The
controller reads requests and writes responses on that fd. One persistent
connection per controller; requests are multiplexed by `request_id`.

## Frame (16-byte header + payload)

```
offset size field
0      4    magic        = 0x4E544331 ("NTC1")
4      1    version      = 2
5      1    type         (see below)
6      2    reserved     = 0
8      4    request_id
12     4    payload_len
16     N    payload
```

Message types: `1 HELLO`, `2 WELCOME`, `3 REQUEST`, `4 RESPONSE`, `5 PING`,
`6 PONG`, `7 RESPONSE_BEGIN`, `8 RESPONSE_CHUNK`, `9 RESPONSE_END` (7–9 = v3 streaming).

## Handshake

1. Controller → core: `HELLO`, payload = controller name (UTF-8).
2. Core → controller: `WELCOME`, empty payload.

A mismatched `magic`/`version` is a fatal protocol error.

## REQUEST payload (v2)

```
u16 len + bytes   method        ("GET")
u16 len + bytes   path          ("/api/users/42")
u16 len + bytes   query         ("a=1&b=2", no '?')
u16 nheaders
  repeated:  u16 len+bytes name,  u16 len+bytes value
u16 nparams                     (captured path params, e.g. :id)
  repeated:  u16 len+bytes name,  u16 len+bytes value
u16 len + bytes   auth_sub      (authenticated subject, "" if none)
u16 len + bytes   auth_scope
u32 len + bytes   body
```

## RESPONSE payload (atomic, one-shot)

```
u16               status
u16 len + bytes   content_type
u32 len + bytes   body
```

## Streaming responses (v3)

A controller may answer with a stream instead of a single RESPONSE. All frames
carry the same `request_id` as the REQUEST. The gateway relays chunks to the
HTTP client as they arrive; the inflight request stays live from BEGIN to END.

**RESPONSE_BEGIN** payload:
```
u16               status
u8                flags        (bit0 = SSE, bit1 = chunked)
u16 len + bytes   content_type
```
- `flags` bit0 (`SSE`) → the gateway sends `Content-Type: text/event-stream`,
  no `Content-Length`, and passes chunk bytes through verbatim (the controller
  formats the `event:`/`data:` lines). Ended by connection close.
- `flags` bit1 (`chunked`) → the gateway sends `Transfer-Encoding: chunked` with
  the given `content_type` and frames each chunk; END emits the `0\r\n\r\n`
  terminator.

**RESPONSE_CHUNK** payload: `u32 len + bytes` — one piece of the body.

**RESPONSE_END** payload: empty.

Backpressure: the gateway never throttles the (shared, multiplexed) controller
socket for one slow client; if a client's unsent buffer exceeds the cap it is
disconnected and its remaining chunks are dropped.

## PING / PONG

`PING` (core → controller) with empty payload; controller replies `PONG` with
the same `request_id`. (Liveness; optional.)

## Limits

- Header block: ≤ 64 headers; payload framing caps at the negotiated buffer
  (256 KiB in the reference SDK).
- Path params: ≤ 8.

## Versioning

The `version` byte gates compatibility, but readers accept a **range** rather
than an exact match. v1 had no params/identity in REQUEST; v2 adds
`nparams`/params and `auth_sub`/`auth_scope`. v3 adds the streaming message
types (7–9) without changing any existing layout, so the written version byte
stays 2 and readers accept 2–3 (capability is keyed off message type). Bump the
written version + the accepted range only on a layout change to existing frames.
