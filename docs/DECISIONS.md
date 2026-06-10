# Blockers & deferred decisions (for later discussion)

Running log of things hit during M1–M6 implementation that need a human call or
are deferred. Nothing here blocks moving to the next step.

| # | Stage | Item | Status |
|---|-------|------|--------|
| 1 | M3 | **BearSSL vendoring.** RS256/ES256 JWT (needs RSA/EC verify + JWKS over HTTPS) and OAuth2 login flows (need TLS) require a vetted crypto/TLS lib. **Resolved in M7:** BearSSL vendored as a git submodule at `third_party/bearssl` (built to `libbearssl.a`, linked into core/test/cov only). **RS256 JWT** verification now uses BearSSL's PKCS#1 v1.5 verifier with a static **JWKS/JWK** public key (`auth.jwks_file`); the middleware dispatches HS256 vs RS256 per-token. **TLS termination** wraps gateway connections with `br_ssl_server` driven through the non-blocking event loop (`--tls <port>` + `tls.cert`/`tls.key` PEM). **Done in M9:** **ES256** (EC P-256 via `br_ecdsa_i31_vrfy_raw`, JWK `kty:EC`), **live JWKS-over-HTTPS** fetch via a new BearSSL TLS *client* (`src/core/https_client.c`) with REAL cert verification against trust anchors (`auth.jwks_url` + `auth.jwks_ca`/bundled roots), multi-key JWKS selectable by `kid` with rate-limited rotation refresh. **Still deferred:** OAuth2 authorization-code+PKCE login (M12). | done in M7+M9 (OAuth login → M12) |
| 2 | M3 | Identity (JWT `sub`/scope) is currently only used to gate + log at the gateway. Passing it through to controllers needs the wire-protocol extension in **M4**. | done in M4 |
| 3 | M6 | **Deferred M6 items.** Implemented: static file serving + auto-OpenAPI (`/_ntc/openapi.json`); **TLS** delivered in M7 (see #1). Scheduled in the v3 roadmap (`docs/SPEC_v3.md`): **SSE streaming**→M8, **`ntc dev`**→M10, **gzip + worker pools + multipart**→M14. | planned (SPEC_v3) |

## v3 roadmap decisions (2026-06-09)

Agreed when planning M8–M14 (see `docs/SPEC_v3.md`). The user picked all four deferred themes
plus three additions.

| # | Decision | Choice |
|---|----------|--------|
| 4 | **Streaming model (M8).** How do out-of-process controllers stream (the wire is one-shot today)? | **Wire v3** — controllers stream via new `RESPONSE_BEGIN/CHUNK/END` frames; the gateway relays chunks. Version gate **range-accepts [2,3]** so v2 controllers keep working (NOT a hard bump). Rejected: in-core/proxy-only streaming (undercuts the microkernel value prop). |
| 5 | **JWKS outbound TLS trust (M9).** Verifying an IdP's TLS cert needs CA roots. | **Bundle a CA root set** (BearSSL trust anchors, generated C array), config override `auth.jwks_ca`. Rejected: system CA bundle (brittle across hosts), operator-PEM-only (inconvenient). |
| 6 | **gzip DEFLATE dependency (M14).** | **Done:** vendored **miniz** 3.0.2 (single-file, public-domain) at `third_party/miniz` (compiled to `build/miniz.o` with `-w`, linked into core/test/cov only); `src/core/gzip.c` wraps raw DEFLATE in a gzip header+CRC32+ISIZE. Responses are gzipped when the client sends `Accept-Encoding: gzip` and the body is text-ish + ≥256 B (atomic only). Rejected: system `-lz` (build/runtime dep). |
| 7 | **Roadmap additions.** Beyond the four deferred themes, adopt: | **WebSockets** (M11, on the M8 streaming infra), **OAuth2 login** code+PKCE + session/cookie layer (M12, on the M9 TLS client), **schema validation + typed OpenAPI** (M13). Out of scope: HTTP/2/3, gRPC, GraphQL, our own authorization server, large streaming uploads. |
