# naitron-c IPC wire protocol (v2) — FROZEN

The contract between the core (gateway) and controller processes. A controller
SDK in any language implements this. The C SDK (`src/common/controller_sdk.c`)
is the reference. All integers are **big-endian**; strings are length-prefixed
(not NUL-terminated).

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

Message types: `1 HELLO`, `2 WELCOME`, `3 REQUEST`, `4 RESPONSE`, `5 PING`, `6 PONG`.

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

## RESPONSE payload

```
u16               status
u16 len + bytes   content_type
u32 len + bytes   body
```

## PING / PONG

`PING` (core → controller) with empty payload; controller replies `PONG` with
the same `request_id`. (Liveness; optional.)

## Limits

- Header block: ≤ 64 headers; payload framing caps at the negotiated buffer
  (256 KiB in the reference SDK).
- Path params: ≤ 8.

## Versioning

The `version` byte gates compatibility. v1 had no params/identity in REQUEST;
v2 adds `nparams`/params and `auth_sub`/`auth_scope`. Bump on any layout change.
