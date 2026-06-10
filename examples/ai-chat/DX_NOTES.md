# Dogfood checkpoint — DX punch-list

Built the streaming AI-chat app in this folder as a developer would (Python SDK
controller, SSE token streaming, JWT-protected, served + hot-reloaded under
`ntc dev`). This is the Wave-1 dev-experience review. Findings, in priority
order, with what was fixed now vs. deferred.

## Fixed during the checkpoint (quick wins)

1. **`NTC_CONTROLLER_BIN` hardcoded the route to `GET /api/hello`.** A real app
   serves its own path (`/api/chat`), so the quickstart controller was 404. Added
   **`NTC_CONTROLLER_ROUTE`** (a `;`-separated list of `"METHOD /path"`) to
   customize the seeded route(s). The example sets `GET /api/chat`.
2. **Streaming wasn't available in the Python SDK** (M8 shipped streaming only in
   the C SDK). Ported it: `sdk/python/naitron.py` now has `Stream`
   (`sse_begin`/`sse_send`, `begin`/`write`, auto-`end`) and `run(..., stream=True)`.
   This app is the proof it works end to end.

## Confirmed good (keep)

- **Auth identity passthrough just works:** the JWT `sub` arrives at the
  controller as `req["sub"]` with no extra wiring (wire v2 carries it).
- **Interpreted controllers hot-reload for free:** under `ntc dev`, editing
  `chat_controller.py` reloads it with no `--build` (the script *is* the binary).
  C controllers need `--build "make ..."`.
- **Incremental SSE is real:** tokens leave the gateway as they're produced
  (verified: ~40 ms apart over plaintext and TLS), not buffered to the end.

## Deferred to Wave 2 (folded into the roadmap)

3. **No browser login flow.** The user must mint a token (`mint_token.py`) and
   paste it. → **M12 (OAuth2 login + sessions/cookies)** is exactly this.
4. **`EventSource` can't send an `Authorization` header**, so the frontend
   streams with `fetch()` + a `ReadableStream` reader and parses SSE frames by
   hand. Works, but it's a sharp edge. A cookie/session auth path (M12) would let
   a plain `EventSource` work; document this either way.
5. **Python SDK isn't installable.** The controller needs a `sys.path` insert to
   `import naitron`. → package the SDKs (pip/npm/crates) — Wave 2/3 polish.
6. **Streaming still missing in the TS / Go / Rust SDKs.** Only C and (now)
   Python stream. → port during M11/M14 SDK passes.

## Minor

- Query-string parsing + URL-decoding is the controller's job (no helper); the
  Python app uses `urllib.parse`. A small `req` query helper would be friendlier.
- The seeded service is always named `hello` regardless of the controller's own
  name; cosmetic (routing is what matters).
