# Open problems / deferred items (come back to these)

Running log of issues found mid-development that are non-blocking. Per the
working agreement: write them down, keep building, revisit later (e.g. at the
Wave-3 deep live test).

## M9 — live JWKS-over-HTTPS + ES256

- **JWKS refresh blocks the event loop.** The unknown-`kid` refresh does a
  bounded blocking HTTPS fetch (short timeout) directly in `ntc_mw_before`,
  which runs on the gateway event loop. A min-refresh interval guard bounds it
  to at most one fetch per interval (so a flood of forged kids can't trigger a
  fetch storm), but a single refresh still briefly stalls the loop. Proper fix:
  move the fetch onto the non-blocking poller (async resolver/fetch state
  machine) or a worker thread. Acceptable for now because the startup fetch
  covers the steady state and rotation is rare.
- **CA bundle is mechanism-first.** `ntc_ca_load_pem()` + the `auth.jwks_ca`
  override are the real, tested path. The default bundled root store
  (`third_party/ca/roots.pem`) is whatever is vendored there; refreshing it from
  the upstream Mozilla/curl bundle is an ops task, and install-path resolution
  (vs. cwd-relative) is future work.

## M10 — `ntc dev` (watch + hot-reload)

- **The `--build` command runs synchronously on the event loop** (via
  `system()`), so the gateway briefly stops serving while a rebuild compiles.
  Acceptable for a local dev tool, but a production-grade version would run the
  build off the loop (worker thread / child + non-blocking wait). mtime polling
  (400ms) is also a deliberate simplification vs. native fs-events
  (kqueue EVFILT_VNODE / inotify).

## M11 — WebSockets

- **wss (WebSocket over TLS) is not wired yet.** The plaintext path is complete
  (handshake, masking, framing, bidirectional relay). A WS upgrade arriving on a
  TLS connection is rejected with 400. The frame codec is transport-agnostic, so
  wss only needs the inbound TLS read path (`on_tls_event`) to feed decrypted
  bytes into `on_ws_readable` and the outbound to keep using the existing
  `tls_drive_write` drain. Deferred to a TLS-WS follow-up.
- **No fragmentation reassembly.** Each WS data frame is relayed as its own
  message (CONT frames are forwarded but not coalesced). Fine for typical
  clients that send unfragmented messages; revisit if a client fragments.

## M12 — OAuth2 login + sessions

- **Sessions are in-memory** (a per-process TTL map), so they are lost on
  restart and not shared across replicas. A SQLite-backed store would survive
  restarts + scale across worker pools (M14). Eviction is soonest-expiry when
  full.
- **id_token validation is HS256-via-client-secret only** in this pass (valid
  per OIDC, and what the test mock uses). RS256/ES256 id_tokens should reuse the
  existing `auth.jwks_url` JWKS machinery (`ntc_jwt_verify_jwks`) - wire
  `oauth.jwks_url` to validate IdPs that sign id_tokens with RS256 (the common
  case for Google/Auth0). The token exchange + PKCE + session plumbing is
  IdP-agnostic; only the id_token signature check needs the JWKS branch.
- The OAuth flow is **plaintext-cookie + same-origin** assumptions: the demo
  redirect_uri is http for localhost. In production set `Secure` cookies (the
  gateway already sets Secure when the request arrived over TLS) and an https
  redirect_uri.

## M13 — schema validation + typed OpenAPI

- **Validator is a documented JSON-Schema subset** (type/required/properties/
  additionalProperties/items/enum/min-max/min-maxLength/min-maxItems), not the
  full spec: no `$ref`, `allOf`/`anyOf`/`oneOf`, `pattern`, `format`, or
  dependent schemas. Add as needed.
- **Request bodies only.** Query/path-param and response-body validation are not
  wired (the OpenAPI emits request schemas only). The schema doc is also bounded
  by the JSON parser's `NTC_JSON_MAX_MEMBERS` (64) per object and the 64 KiB
  OpenAPI buffer.
- Schemas load from a single `schema.file` at startup (no live reload); editing
  it needs a restart (or `ntc dev`).

## M14 — gzip + worker pools + multipart + max body

- **gzip is atomic-only.** Streamed (SSE/chunked) and WebSocket payloads are not
  compressed. Threshold is 256 B, text-ish content types only.
- **max_body is bounded by the per-conn read buffer (`NTC_CONN_RBUF`, 64 KiB).**
  `max_body` can only *lower* the limit; raising it past the buffer needs a
  growable per-conn buffer (and streaming/chunked *request* bodies remain future
  work). Multipart uploads therefore cap at ~64 KiB for now.
- **Replicas are processes, capped at `NTC_MAX_REPLICAS` (8) per service**, with
  in-memory round-robin (no sticky sessions, no health-weighting). Scaling state
  persists in the registry config (`replicas:<name>`); the `service scale` change
  is live. Sessions (M12) are per-process, so OAuth login + replicas don't share
  session state yet (would need the shared/SQLite session store).
