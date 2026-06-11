# naitron-c — project status & next steps

Handoff snapshot (2026-06-10). Read this first to pick up where we left off.

## Where we are

The framework is feature-complete through the v3 roadmap (P0–P8, M1–M14) **plus**
persistent sessions and controller response headers. We then built a **real app
on it** (the task-board dogfood) to find what's missing, fixed the top finding,
and are about to start the **data plane** (the next big track).

- **170 test files / 169 tests pass, 0 failures, 0 leaks** (ASan+UBSan).
- Two repos:
  - **framework**: `~/work/c_ms_backend_framwork` (this repo).
  - **dogfood app**: `~/work/naitron-projects/todo-board` (its own git, an
    external project that consumes the framework).

## What's built & shipped

Everything from `docs/SPEC.md` (v2: P0–P8, M1–M7) and `docs/SPEC_v3.md`
(v3: M8–M14) — gateway, process-per-service IPC, middleware, JWT/JWKS/ES256 auth,
TLS, SSE streaming, `ntc dev`, WebSockets, OAuth2 login, schema validation +
typed OpenAPI, gzip, worker-pool replicas, multipart, configurable body limit.

Since then (post-M14):
- **Persistent sessions** (`src/core/session_store.c`) — OAuth sessions moved
  from in-memory to their own SQLite; survive a gateway restart. Commit
  `aa1ecf8`.
- **Controller response headers** (commit `2e76579`) — controllers can now set
  arbitrary headers / redirect / set cookies (`ntc_res_header`/`ntc_redirect` in
  C; a 4-tuple or `naitron.redirect()` in Python). Wire RESPONSE gained a
  backward-compatible trailing header blob.

## What we still need to fix (the punch-list)

From the dogfood — full detail in `~/work/naitron-projects/todo-board/FINDINGS.md`.

**P0 — blocks real apps**
1. ~~Controllers can't set response headers~~ — **DONE** (`2e76579`).
2. **SDKs aren't installable.** Python needs a `sys.path` hack; C compiles the
   framework's `.c` sources directly; no `libnaitron`, no distributable `ntc`.
   Need pip/npm/crates packages + a `libnaitron` + a release `ntc` binary.
3. **No data layer.** Each controller DIYs its own SQLite. → the data-plane
   track below.
4. **Multi-controller routing is imperative** (run.sh issues 9 `route add`
   calls). Want a declarative `naitron.toml` manifest (routes → controllers,
   replicas, schemas).

**P1 — friction**
5. A controller is all-atomic OR all-streaming (had to split CRUD and SSE).
6. **No pub/sub / change-feed** (realtime needs polling the shared DB). → the
   data-plane change-feed below.
7. Serial controller model blocks long-lived streams (SSE needs N replicas).
8. WebSockets only in the C SDK (port to Python/TS/Go/Rust).

**P2 — polish:** no stream-disconnect signal to the controller; CLI needs the
control token even over the local Unix socket; local OAuth needs a mock IdP
(`oauth_mock` only does `/token`); a friendlier "port in use" bind error.

Also see `docs/PROBLEMS.md` for the per-phase caveats (wss-over-TLS not wired,
JWKS refresh blocks the loop briefly, gzip atomic-only, id_token HS256-only, etc.).

## What we're planning to do next

### Immediate: the data plane (Topology C)

The dogfood made the case: the core should own the app data and controllers
should query it over IPC (no per-language DB driver). Plan:

- **Slice 1 — the query loop.** New *controller-initiated* wire frames
  `DB_QUERY` / `DB_RESULT`; the core owns one app SQLite (`data.db`, separate
  from the registry + sessions DBs) and runs parameterized queries; SDK gets
  `ntc_db_query(sql, params) → rows` and `ntc_db_exec(...) → {affected, last_id}`
  in **C and Python**. **Rows as JSON** for the first cut; **synchronous**
  execution on the loop (slow-query caveat noted, thread pool later). Then
  migrate the todo-board onto it as the proof.
  - **Open design fork (decide first):** JSON rows (simple, ship it) vs. a typed
    binary row encoding (faster, but hard to change once SDKs depend on it).
    Leaning JSON for slice 1.
- **Slice 2 — the change-feed.** `subscribe(table)` → the core pushes a notice on
  change. Kills the SSE polling the todo-board needed (#6) and is the seed of the
  sync engine.

### After that: traditional backends + local-first (the big arc)

These were decided in design discussion (not yet built):

- **Pluggable backends behind the data plane:** SQLite (default, embedded) →
  **Postgres** (via libpq) and **Mongo** for apps that outgrow embedded.
- **Local-first / P2P:** the same "collections + change-feed" primitive becomes
  a **CRDT** on the client, with the core as a sync relay.
  - **CRDT = Loro**, run in a **Rust sync service** (a process speaking the wire
    protocol, NOT linked into the C core). Prerequisite: **port WebSockets to the
    Rust SDK** (it's v2-atomic only today).
  - **P2P transport = iroh** for native peers + relay; browsers use WebRTC/relay.
  - True "user owns their data" (E2E encryption, dumb-relay mode) is a later layer.
- **WASM reactive frontend** (language-agnostic, TEA / model-view-update view
  protocol): **tabled**, but it's the *client half* of local-first — it comes
  back when we do local-first web.

### Locked architecture decisions (don't re-litigate)

- **Data topology = C (core-owned data plane).** The core is the data/sync hub;
  controllers query over IPC; this is what makes language-agnostic data + the
  sync engine + P2P clean.
- **Sessions → SQLite** (done). **App users + logins → Postgres** (app data
  layer; the framework does NOT own a users table — that would make it an IdP).
  **Admin/superuser → named tokens + roles** in the control-plane DB (not
  passwords; recovery via local CLI since admins own the box) — *deferred, confirm
  need against the app*. **Logs store + retention → deferred.**
- **Both traditional and local-first are one foundation** — a sync engine where
  Postgres/Mongo are just backends and iroh is just a transport.

## How to run things

```sh
# framework
cd ~/work/c_ms_backend_framwork && make && make test   # 169 pass, 0 leaks

# dogfood app (collaborative task board)
cd ~/work/naitron-projects/todo-board && ./run.sh       # http://localhost:7800/
#   (port 7000 is macOS AirPlay — we use 7800; mock IdP on 7801/7843)
```

## Git state at the break

- **framework**: 2 commits ahead of `origin/main` (`aa1ecf8` sessions,
  `2e76579` headers) — **not yet pushed**.
- **dogfood** (`naitron-projects/todo-board`): local git only, **no remote**.

## The exact next action

Build **data-plane slice 1** (core-owned `data.db` + `DB_QUERY`/`DB_RESULT` wire
frames + `ntc_db_query`/`exec` in the C and Python SDKs), once the JSON-vs-binary
row-encoding fork is decided (leaning JSON). Then migrate the todo-board onto it.
