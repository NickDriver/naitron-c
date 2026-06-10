# naitron-c — v3 Spec (post-M7 roadmap: M8–M14)

Status: **agreed 2026-06-09**. **All feature phases shipped: Wave 1 (M8–M10 +
dogfood) + Wave 2 (M11–M14).** Remaining: Wave 3 deep live test, which the team
runs as a separate dogfood project (a real app built ON the framework). Working
spec for the
phases after M1–M7 (which shipped: gateway, process-per-service IPC wire v2,
middleware, auth API-key/HS256/**RS256+TLS** via BearSSL, multi-language SDKs,
static files, auto-OpenAPI). See `docs/SPEC.md` for the v2 spec, `docs/DECISIONS.md`
for locked calls, `docs/WIRE_PROTOCOL.md` for the IPC contract.

## Locked decisions (this round)
- **Streaming model:** wire **v3** — out-of-process controllers stream (not in-core-proxy-only).
- **JWKS outbound TLS trust:** **bundle a CA root set** (BearSSL trust anchors).
- **gzip dependency:** **vendor miniz** (single-file, public-domain), matching the BearSSL pattern.
- **Adopted additions:** WebSockets, OAuth2 login (code+PKCE), schema validation + typed OpenAPI.

## Out of scope (deferred / not planned)
HTTP/2 & HTTP/3, gRPC, GraphQL, our own **authorization server** (token *issuance*),
streaming/chunked *request* bodies beyond the bounded-upload bump in M14.

---

## Sequencing

**Wave 1 — Core capability + DX**
- **M8** SSE / streaming responses (wire v3) + SDKs
- **M9** Finish auth: live JWKS-over-HTTPS + ES256 (BearSSL TLS *client* + bundled CA roots)
- **M10** `ntc dev` (watch + hot-reload)
- **★ Dogfood checkpoint (DX POV)** — build a real streaming AI app; capture friction; fix quick wins

**Wave 2 — Realtime + identity + contracts + production**
- **M11** WebSockets (on the M8 streaming infra)
- **M12** OAuth2 login (auth-code + PKCE) + session/cookie subsystem (on the M9 TLS client)
- **M13** Schema validation + typed OpenAPI
- **M14** Production grab-bag: gzip (miniz) + worker pools + multipart (+ configurable max body)

**Wave 3 — Validation**
- **★ Deep live test** — fuller reference app exercising everything; perf/robustness/security shakeout

Rationale: M8→M9→M10 deliver the three things that define the developer experience for an
AI app (stream tokens, protect with a real IdP, iterate with hot-reload), so the dogfood
checkpoint evaluates a fully-formed DX. WebSockets depends on M8's long-lived-conn infra;
OAuth login depends on M9's TLS client; schema/grab-bag are independent polish.

---

## M8 — SSE / streaming responses (wire v3)

Highest product value (LLM token streaming) and architecturally foundational — converts the
one-shot request/response model into a streaming-capable one that WebSockets (M11) reuse.

- **Wire v3 = superset, range-accepted gate (NOT a hard bump).** Add message types
  `RESPONSE_BEGIN(7)` / `RESPONSE_CHUNK(8)` / `RESPONSE_END(9)`; keep atomic `RESPONSE(4)`.
  Relax the version check in `ntc_wire_parse_header`/`ntc_wire_read_frame` to accept `[2,3]`
  (`NTC_WIRE_VERSION_MIN=2`, `=3`) so unmodified v2 controllers keep working and a v3
  controller's new frame types are ignored by an old core. No HELLO/WELCOME renegotiation.
- **HTTP framing via a flags byte in BEGIN:** SSE → `Content-Type: text/event-stream`, no
  `Content-Length`, raw passthrough, end-on-close; generic → `Transfer-Encoding: chunked`.
  New `ntc_http_format_stream_head()` (no Content-Length).
- **Growable per-conn drain buffer:** add heap `swbuf/swlen/swsent/swcap` (reuse `buf_reserve`)
  + a `CS_STREAM` state; chunks append as they arrive and free as they drain. Atomic path untouched.
- **Inflight-slot lifetime:** keep the slot BEGIN→END; free at END; client disconnect mid-stream
  → `conn_close` frees the slot, later frames dropped by the gen check. `controller_died`
  truncates a mid-stream conn (close) rather than inject a 502 into an open body.
- **TLS:** generalize `tls_drive_write` to push `swbuf` and only `close_notify`+close at END;
  `ntc_tls_flush` after each chunk so events leave the engine promptly.
- **Backpressure (no head-of-line block):** one controller multiplexes many clients over one IPC
  socket → never throttle that socket for a slow client. Bound `swbuf` (~4 MB) and disconnect
  the slow client, dropping its chunks; other clients unaffected.
- **C SDK streaming API (reference):** opt-in `ntc_stream_fn` + `ntc_stream` handle:
  `ntc_stream_begin`/`ntc_sse_begin`, `ntc_stream_write`, `ntc_sse_send(event,data)`,
  `ntc_stream_end`. Atomic handlers unchanged. Then port to TS/Py/Go/Rust.

Tests: wire v3 roundtrips + version-range-accept; `m8_integration.c` — SSE over plaintext AND
TLS, chunked mode, incremental arrival, slow-client backpressure with a concurrent fast client,
client-disconnect mid-stream (no slot leak), and v2 hello_controller still 200s.

---

## M9 — Finish auth: live JWKS-over-HTTPS + ES256

- **BearSSL TLS client** (mirrors the M7 server): outbound HTTPS GET of an issuer's JWKS endpoint,
  with **real cert verification** against bundled trust anchors. Reuse `br_ssl_client` + `br_sslio`.
- **Bundle a CA root set** as a generated C array (via BearSSL `brssl ta`); config override
  `auth.jwks_ca` for private IdPs.
- **JWKS cache** by `kid` (TTL + refresh-on-unknown-kid); config `auth.jwks_url`. Reuse `ntc_jwk_parse`.
- **ES256:** EC P-256 verify via BearSSL `br_ecdsa_*`; extend alg dispatch + JWK `kty:EC` parsing.

Fail closed (→401), never hang the event loop. Tests use a hermetic local mock JWKS server.

---

## M10 — `ntc dev` (watch + hot-reload)

- **mtime polling** (not native fs-events): `stat()` watched controller binaries + config in the
  supervise tick; on change, mark the service for restart → existing `supervise()` respawns; routes
  stay live-wired.
- Optional `ntc dev --build '<cmd>'` build hook; combined colorized log streaming.

---

## ★ Dogfood checkpoint (DX POV)

Build a streaming **AI-chat reference app** as a real developer would: a controller (non-C SDK)
streaming tokens via SSE, protected by RS256/JWKS, over TLS, with a static frontend, developed
under `ntc dev`. Capture a DX punch-list; fix quick wins; keep the app in `examples/` + a
"build your first streaming app" guide.

---

## M11 — WebSockets

HTTP `Upgrade` handshake (`Sec-WebSocket-Accept` via SHA-1 in BearSSL); WS frame codec (opcodes,
client→server unmasking, fragmentation, ping/pong, close); **bidirectional wire frames** —
gateway forwards inbound WS messages to the controller mid-connection and relays outbound,
correlated by the inflight slot. New `src/common/ws.c`; SDK `ntc_ws_*`; `controllers/ws_echo.c`.

---

## M12 — OAuth2 login (auth-code + PKCE) + session/cookie subsystem

New session/cookie subsystem (signed cookies via existing HMAC-SHA256, a session store). Flow:
`/auth/login`→IdP redirect with PKCE; `/auth/callback`→code exchange (M9 TLS client) + ID-token
validation (M9 JWKS/ES256) → session. `auth` middleware accepts a session cookie or a bearer token.
New `src/core/session.c`; registry sessions table + OAuth client config.

---

## M13 — Schema validation + typed OpenAPI

JSON-Schema (pragmatic subset) validator on the existing `ntc_json` parser; per-route schemas in
the registry; a `validation` middleware (400 on invalid bodies); enrich `/_ntc/openapi.json` with
the schemas. New `src/common/schema.c`. Document the supported subset.

---

## M14 — Production grab-bag

- **gzip:** vendor **miniz** under `third_party/`; hook in `conn_respond` (stash `Accept-Encoding`
  on the conn during parse); compress compressible bodies over a threshold; set `Content-Encoding`.
  Atomic responses only in v1.
- **Worker pools:** `service.replicas`; `ctrl *conn` → pool; `gw_forward` round-robins; per-replica
  supervise; registry `replicas` column + `service scale` command.
- **Multipart:** parser in the SDK (body crosses the wire as one blob) — C reference + one other
  SDK. Add a configurable max request body (default ~1 MB) to make uploads useful; large/streaming
  uploads are future work.

---

## ★ Deep live test (Wave 3)

Fuller reference app using everything (WebSockets + OAuth login + schema-validated endpoints +
multipart + gzip + worker pools, over TLS, behind a real IdP). Robustness/perf/security shakeout
(concurrent load, `leaks`, fuzz the WS/multipart/schema parsers). Final punch-list + a production
deployment guide (systemd/Docker, CA bundle, IdP config, scaling).

---

## Conventions (all phases)
- ASan+UBSan via `make test`; in-file `TEST()` units + `tests/mN_integration.c` using
  `it_util` (plaintext) / `it_tls` (TLS). Commit + push per phase.
- Vendor third-party libs under `third_party/<lib>`, built once, linked into core/test/cov only.
- Zero-warning `-Werror -std=c23`; never DIY crypto (BearSSL); fail auth closed.
- Update `docs/WIRE_PROTOCOL.md`, `docs/DECISIONS.md`, `README.md`, and memory per phase.
