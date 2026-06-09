# naitron-c

A microkernel-style web backend framework written from scratch in pure C (C23).
One central **gateway** routes each `/api/*` route to an isolated **controller**
process; a small **core/orchestrator** supervises them. Control is via the `ntc`
CLI and a built-in MCP server; observability via a read-only dashboard.

> Status: **P6** — authenticated control plane + CLI. The core listens on a
> token-authenticated Unix control socket; the `ntc` CLI registers services and
> routes **on a live server** (`ntc service add`, `ntc route add`) and the core
> hot-reloads its routing table — plug-and-play, no restart. Also `status`,
> `service/route list`, `service rm`, `stop`. Built on the orchestrator (P5),
> IPC (P4), router (P3), parser (P2), event loop (P1).

## CLI

```sh
ntc start 3000                              # run the gateway/core (the daemon)
ntc status                                  # core status
ntc service add hello ./build/hello_controller   # register + spawn (live)
ntc route add GET /api/hello hello          # route to a service (live)
ntc service list ; ntc route list
ntc service rm hello ; ntc stop ; ntc token
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
