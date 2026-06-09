# naitron-c — v2 Spec (post-P8 follow-up)

Status: **design / agreed**, not yet implemented. This is the working spec for
the next milestones after the P1–P8 build. Decisions below are locked unless
marked **OPEN**.

---

## Part 1 — UX / DX fixes

### 1.1 Process model: foreground + detached

Foreground stays the **default** (correct for systemd / Docker / k8s — they
supervise a foreground process; double-forking under a supervisor is an
anti-pattern). Add ergonomics around it:

- `ntc start <port>` — foreground, with a clear startup banner.
- `ntc start <port> -d|--detach` — fork to background, write a **PID file**
  (`./ntc.pid`, `$NTC_PID_FILE`), redirect logs to `./ntc.log` (`$NTC_LOG_FILE`),
  print `started (pid N) · logs: ./ntc.log`, return immediately.
- `ntc stop` — via the control socket; fall back to PID-file + SIGTERM.
- `ntc restart`, `ntc logs [-f]` (tail the log file).
- **Double-start guard**: refuse if the PID file points at a live process.
- Ship a **systemd unit** + **Dockerfile** as docs (the production path).

### 1.2 CLI-native output, JSON on demand

Separate the **wire format** (core control protocol stays JSON) from the
**presentation** (CLI renders human-friendly by default; `--json` for machines).
Applies to `status`, `service list`, `route list`.

```
$ ntc status
naitron-c 0.0.1   ● running   up 2h14m   backend kqueue
gateway   :3000        dashboard  127.0.0.1:9090
services  3 (2 up, 1 down)        routes  12
requests  1.2M   2xx 1.19M   4xx 8.4k   5xx 12
```

### 1.3 Dashboard on by default; the public `/`

- Rename **admin → console / dashboard** (it's a read-only overview).
- **On by default**, bound to `127.0.0.1`, default port `9090`, **advertised in
  the startup banner** (`dashboard: http://127.0.0.1:9090`). `--dashboard <port>`
  to move, `--no-dashboard` to disable. (No more `--admin` requirement.)
- The overview UI stays **localhost-only** — it exposes service names, binary
  paths and statuses, which must not be public.
- **Reserved framework namespace** on the public gateway port, never collides
  with user routes:
  - `GET /_ntc/health`, `GET /_ntc/ready` — for load balancers / k8s probes
    (non-sensitive).
  - `GET /_ntc/metrics` — Prometheus exposition (localhost-gated).
- **Public `/`** (when no user route claims it) → a minimal, non-sensitive
  landing, overridable by a user route:
  > `<App> powered by naitron-c` · core uptime
  - `<App>` is a config value (`app.name`, default `"naitron-c app"`); set via
    config file / `ntc config set app.name "..."` / `$NTC_APP_NAME`.

### 1.4 MCP: always-on, built-in; stdio adapter secondary

One MCP module (`libmcp`, separate library for organization), two transports:

1. **Built-in HTTP transport, in the core, always-on** (optional) — mounted at
   `/_ntc/mcp` on the console (localhost) port, **token-authenticated**. A
   running server is immediately AI-connectable; no separate process. Lives in
   the never-die core, so it can't independently crash → no orchestration needed.
   *This is the primary transport.*
2. **`ntc mcp` stdio adapter** for desktop MCP clients that spawn a subprocess
   (Claude Desktop style) — bridges stdio ↔ the core control socket.
   **Subcommands (no dashes):**
   - `ntc mcp` — run the stdio server (prints a stderr banner so it's not silent).
   - `ntc mcp tools` — list the available tools (human; `--json` for raw).
   - `ntc mcp help`.

Security: MCP can spawn processes (≈ RCE) → HTTP transport is **localhost-only +
token-auth**, never on the public port.

---

## Part 2 — Middleware framework (general-purpose)

The gateway is the choke point; middleware is a **chain run around dispatch**.
Designed to serve auth *and* reporting / health / any internal cross-cutting
concern an engineer wants.

**Model:**
- A middleware sees the request on the way in and the response on the way out:
  ```
  request → [request-id] → [access-log start] → [cors] → [rate-limit]
          → [auth] → [validation] → DISPATCH → [metrics] → [access-log end] → response
  ```
- Each middleware may: read/annotate the request context, **short-circuit** with
  a response (auth reject, 429, CORS preflight), and observe the final response
  (logging, metrics, reporting).
- **Built-in middleware** (in-core C modules, registered in a pipeline):
  `request_id`, `access_log`, `metrics` (feeds `/_ntc/metrics` + dashboard),
  `cors`, `rate_limit`, `body_limit`, `auth` (see Part 3), `health_gate`.
- **Scoping**: global or per route-prefix (e.g. auth on `/api/admin/*`, open on
  `/api/public/*`), stored in the registry, managed via CLI/MCP.
- **Extensibility**: built-ins are the common set; custom middleware can be added
  as in-core C modules now, and (later) as an out-of-process *middleware
  controller* the gateway calls before forwarding, for custom logic in any
  language. **OPEN**: do we ship the out-of-process middleware hook in v2 or
  defer it.
- Passing middleware-derived context (e.g. authenticated identity) **to
  controllers** requires extending the wire protocol — done in Part 4.

---

## Part 3 — Auth & OAuth

**Crypto decision (LOCKED): never roll our own crypto.** We implement the OAuth
*logic* (flows, middleware, token cache, JWKS handling) ourselves, but the
primitives (SHA-256, HMAC, RSA/EC verify, base64url, TLS for JWKS/IdP calls)
come from a vetted, self-contained library. **Pick: BearSSL** (tiny, MIT, no
deps). **OPEN**: confirm BearSSL vs OpenSSL.

Delivered in order of value:
1. **API keys** — simplest; gateway validates a key, identity → controller.
2. **OAuth2 / OIDC resource server** — validate incoming bearer tokens:
   - `HS256` (HMAC) and `RS256`/`ES256` (JWKS-fetched public keys) JWT verify.
   - Optional token introspection (RFC 7662).
   - This is the `auth` middleware → protects your API. Highest value.
3. **OAuth2 / OIDC client (login flows)** — authorization-code + PKCE, for apps
   that log users in via Google / GitHub / any OIDC IdP; sets a session.
4. **(Later) Authorization server** — issue our own tokens. Most work, least
   common; defer.

Identity (subject, scopes, claims) is attached to the request context and passed
to controllers over the extended wire protocol (Part 4).

---

## Part 4 — Controller DX + wire-protocol freeze

Prerequisite for real apps **and** for multi-language SDKs.

- **Carry over the wire**: path params (`:id`), parsed query params, and the
  request headers + auth identity (today only the raw path crosses the boundary).
- **SDK ergonomics** (reference = C SDK): `ntc_param(c, "id")`,
  `ntc_query(c, "page")`, `ntc_header(c, "...")`, `ntc_body_json(c)`,
  `ntc_reply_json(c, status, ...)`, `ntc_reply_status(...)`, identity accessors.
- **`ntc new controller <name>`** — scaffold a controller against the SDK.
- **Freeze + version the wire protocol** and publish it as
  `docs/WIRE_PROTOCOL.md` — the contract every language SDK implements against.

---

## Part 5 — Multi-language controller SDKs

The wire protocol (P4, frozen in Part 4) is language-agnostic — this is the
framework's differentiator: write isolated, gateway-fronted services in any
language while the core stays C. Each SDK implements: read `$NTC_CONTROLLER_FD`,
HELLO/WELCOME handshake, REQUEST decode → user handler → RESPONSE encode, plus
idiomatic request/response/params/query/body/identity helpers.

Targets (idiomatic, each in `sdk/<lang>/`), suggested order by web-dev reach:
1. **TypeScript / Node**
2. **Python**
3. **Go**
4. **Rust**

C SDK is the reference implementation.

---

## Part 6 — Milestone sequencing

Order respects the agreed priority (middleware → OAuth → languages) and real
dependencies (wire freeze must precede the SDKs).

- **M1 — UX/DX pass:** Part 1 (process model, CLI formatting, dashboard-default
  + `/_ntc/*` + public landing, MCP reshape). Fast, makes it pleasant.
- **M2 — Middleware framework:** Part 2 (chain + built-ins: request-id,
  access-log, metrics, cors, rate-limit, body-limit, health). The foundation
  auth plugs into.
- **M3 — Auth & OAuth:** Part 3 (vendor BearSSL; API keys → resource-server JWT
  → login flows).
- **M4 — Controller DX + wire freeze:** Part 4 (params/query/headers/identity
  over the wire, SDK ergonomics, `ntc new controller`, `docs/WIRE_PROTOCOL.md`).
- **M5 — Multi-language SDKs:** Part 5 (TS → Python → Go → Rust).
- **M6 — Full-stack & modern:** static file serving, SSE streaming (AI tokens),
  auto-OpenAPI from the registry, `ntc dev` (watch+reload), worker pools (N
  procs/service), TLS termination, gzip, multipart/uploads.

---

## Open decisions — RESOLVED (2026-06-09)

1. **Crypto library:** **BearSSL.**
2. **Out-of-process middleware hook:** **deferred** (post-M6).
3. **SDK home:** **monorepo** `sdk/<lang>/`.
4. **Defaults:** dashboard port **9090**, app.name default **"naitron-c app"** — confirmed.

See `docs/DECISIONS.md` for blockers found during implementation.
