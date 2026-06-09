# Blockers & deferred decisions (for later discussion)

Running log of things hit during M1–M6 implementation that need a human call or
are deferred. Nothing here blocks moving to the next step.

| # | Stage | Item | Status |
|---|-------|------|--------|
| 1 | M3 | **BearSSL vendoring.** RS256/ES256 JWT (needs RSA/EC verify + JWKS over HTTPS) and OAuth2 login flows (need TLS) require a vetted crypto/TLS lib. Vendoring BearSSL (~150 files) isn't doable from this session. **Implemented without it:** API-key auth + **HS256** JWT validation (SHA-256 + HMAC + base64url written from scratch and verified against RFC test vectors — deterministic hashes, not key-material crypto). **Deferred until BearSSL is vendored:** RS256/ES256 + JWKS, OAuth2 authorization-code login. Decision needed: how to vendor BearSSL (git submodule / vendor script / amalgamation). | OPEN |
| 2 | M3 | Identity (JWT `sub`/scope) is currently only used to gate + log at the gateway. Passing it through to controllers needs the wire-protocol extension in **M4**. | done in M4 |
| 3 | M6 | **Deferred M6 items.** Implemented: static file serving + auto-OpenAPI (`/_ntc/openapi.json`). Deferred (each is a real feature, not a quick add): **SSE streaming** (needs a streaming connection state machine in the event loop + a streaming controller contract), **TLS** (needs BearSSL, see #1), **gzip/brotli** (needs a deflate impl or vendored zlib), **`ntc dev`** watch+reload (file-watch + rebuild orchestration), **worker pools** (N processes per service — orchestrator extension), **multipart/file-upload** parsing. | OPEN |
