# naitron-c

A microkernel-style web backend framework written from scratch in pure C (C23).
One central **gateway** routes each `/api/*` route to an isolated **controller**
process; a small **core/orchestrator** supervises them. Control is via the `ntc`
CLI and a built-in MCP server; observability via a read-only dashboard.

> Status: **M1–M7 implemented** (on top of feature-complete P1–P8). UX/DX
> (detached daemon, formatted CLI, dashboard-by-default, `/_ntc/*`, MCP-over-HTTP);
> a **middleware** chain (request-id, access-log, CORS, rate-limit); **auth**
> (API keys + HS256 **and RS256** JWT — HS256/HMAC from scratch, RS256 + TLS via
> vendored **BearSSL**); **controller DX** (path params + query + auth identity over
> the frozen v2 wire, `ntc_reply_json`, `ntc new controller`); **SDKs in Python,
> TypeScript, Go, Rust** (`sdk/`); **static file serving** + **auto-OpenAPI**
> (`/_ntc/openapi.json`); **TLS termination** (`--tls <port>`).
> Deferred (follow-up): live JWKS-over-HTTPS, OAuth-login, ES256, SSE, gzip,
> `ntc dev`, worker pools — see `docs/DECISIONS.md`. Roadmap: `docs/SPEC.md`.

## CLI

```sh
ntc start 3000                              # run the gateway/core (the daemon)
ntc status                                  # core status
ntc service add hello ./build/hello_controller   # register + spawn (live)
ntc route add GET /api/hello hello          # route to a service (live)
ntc service list ; ntc route list
ntc service rm hello ; ntc stop ; ntc token
ntc start 3000 --admin 9000                 # + read-only dashboard on :9000
ntc start 3000 --tls 3443                    # + HTTPS on :3443 (needs tls.cert/tls.key)
ntc mcp                                      # built-in MCP server (stdio) for AI clients
```

### Auth & TLS config

```sh
# RS256 JWT: verify against a static JWKS/JWK public-key document
ntc config set auth.mode jwt
ntc config set auth.jwks_file ./jwks.json          # or NTC_AUTH_JWKS_FILE
ntc config set auth.protect /api/                  # prefix to protect ("" = all)
# (HS256 still works via auth.secret; the token's own `alg` selects the path.)

# TLS termination (PEM cert chain + RSA private key)
ntc config set tls.cert ./cert.pem                 # or NTC_TLS_CERT
ntc config set tls.key  ./key.pem                  # or NTC_TLS_KEY
ntc config set tls.port 3443                        # or --tls 3443 / NTC_TLS_PORT
# dev cert:  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -subj /CN=localhost
```

## Build & run

```sh
make            # release binary -> build/ntc
./build/ntc start 3000
curl localhost:3000/api/hello
```

```sh
make test       # all tests under AddressSanitizer + UndefinedBehaviorSanitizer
make test-unit  # unit tests only
make test-it    # integration tests only
make test-list  # list every registered test (with kind + TODO markers)
make coverage   # llvm-cov line/function coverage
make clean
```

The test runner is a small CLI (`build/ntc_test [all|unit|it|list|help]`).
Tests have a **kind** — `TEST`/`TEST_TODO` (unit, in-file) and
`ITEST`/`ITEST_TODO` (integration, in `tests/`) — and a **status**:
`PASS` · `FAIL` · `SKIP` (runtime `SKIP("reason")`) · `TODO` (planned, declared
with `*_TODO`, never executed). Only `FAIL` returns a nonzero exit.

## Layout

```
include/ntc/   public headers (err, arena, slice, http, log, signal, server, test, version)
src/common/    libcommon: arena, slice, err, log, signal, http
src/core/      main (the `ntc` CLI) + server (gateway accept loop)
src/test/      unit-test runner (provides main() for test builds)
```

## Conventions

- **C23**, compiled with clang, `-Wall -Wextra -Werror`.
- Every fallible function returns `ntc_err` and is marked `[[nodiscard]]`;
  ignoring an error is a build failure. Propagate with `TRY(...)`.
- Per-request **arena** for memory; **slices** (`ptr+len`) instead of `char*`.
- Unit tests live at the bottom of each `.c` under `#ifdef UNIT_TEST` and
  auto-register via `TEST(suite, name)` — release builds omit them entirely.

## Roadmap

P0 scaffold · P1 event loop (kqueue/epoll) · P2 HTTP parser · P3 router +
controller contract · P4 IPC + controller SDK + out-of-process controller ·
P5 orchestrator + SQLite registry · P6 control API + CLI · P7 MCP server ·
P8 metrics + dashboard.
