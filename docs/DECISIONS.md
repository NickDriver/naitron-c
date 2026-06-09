# Blockers & deferred decisions (for later discussion)

Running log of things hit during M1–M6 implementation that need a human call or
are deferred. Nothing here blocks moving to the next step.

| # | Stage | Item | Status |
|---|-------|------|--------|
| 1 | M3 | **BearSSL vendoring.** RS256/ES256 JWT (needs RSA/EC verify + JWKS over HTTPS) and OAuth2 login flows (need TLS) require a vetted crypto/TLS lib. **Resolved in M7:** BearSSL vendored as a git submodule at `third_party/bearssl` (built to `libbearssl.a`, linked into core/test/cov only). **RS256 JWT** verification now uses BearSSL's PKCS#1 v1.5 verifier with a static **JWKS/JWK** public key (`auth.jwks_file`); the middleware dispatches HS256 vs RS256 per-token. **TLS termination** wraps gateway connections with `br_ssl_server` driven through the non-blocking event loop (`--tls <port>` + `tls.cert`/`tls.key` PEM). **Still deferred (follow-up):** ES256, **live JWKS-over-HTTPS** fetch (needs the BearSSL TLS *client*), OAuth2 authorization-code+PKCE login. | done in M7 (ES256/JWKS-fetch/OAuth follow-up) |
| 2 | M3 | Identity (JWT `sub`/scope) is currently only used to gate + log at the gateway. Passing it through to controllers needs the wire-protocol extension in **M4**. | done in M4 |
| 3 | M6 | **Deferred M6 items.** Implemented: static file serving + auto-OpenAPI (`/_ntc/openapi.json`); **TLS** delivered in M7 (see #1). Still deferred (each is a real feature, not a quick add): **SSE streaming** (needs a streaming connection state machine in the event loop + a streaming controller contract), **gzip/brotli** (needs a deflate impl or vendored zlib), **`ntc dev`** watch+reload (file-watch + rebuild orchestration), **worker pools** (N processes per service — orchestrator extension), **multipart/file-upload** parsing. | OPEN |
