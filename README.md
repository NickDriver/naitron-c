# naitron-c

A microkernel-style web backend framework written from scratch in pure C (C23).
One central **gateway** routes each `/api/*` route to an isolated **controller**
process; a small **core/orchestrator** supervises them. Control is via the `ntc`
CLI and a built-in MCP server; observability via a read-only dashboard.

> Status: **P8 — feature-complete (P1–P8).** A read-only dashboard + metrics
> serve on a localhost-only admin port (`ntc start 3000 --admin 9000`, then open
> http://127.0.0.1:9000): live request/status counts, per-service up/down status
> and restarts, and routes. The full stack: event loop (P1), HTTP parser (P2),
> router (P3), IPC + Controller SDK (P4), orchestrator with supervision + SQLite
> registry (P5), authenticated control plane + CLI (P6), built-in MCP server (P7),
> dashboard (P8).

## CLI

```sh
ntc start 3000                              # run the gateway/core (the daemon)
ntc status                                  # core status
ntc service add hello ./build/hello_controller   # register + spawn (live)
ntc route add GET /api/hello hello          # route to a service (live)
ntc service list ; ntc route list
ntc service rm hello ; ntc stop ; ntc token
ntc start 3000 --admin 9000                 # + read-only dashboard on :9000
ntc mcp                                      # built-in MCP server (stdio) for AI clients
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
