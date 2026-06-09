# naitron-c controller SDKs

Write isolated, gateway-fronted controllers in any language — the core stays C,
you get C-gateway performance + process isolation. Each SDK implements the v2
IPC wire protocol (`docs/WIRE_PROTOCOL.md`); the C SDK is the reference.

A controller is a process the core spawns; it reads requests and writes
responses on the inherited socket (`$NTC_CONTROLLER_FD`).

| Lang | SDK | Example | Run as |
|------|-----|---------|--------|
| C | `src/common/controller_sdk.c` | `controllers/hello_controller.c` | compiled binary |
| Python | `sdk/python/naitron.py` | `sdk/python/example.py` | `#!/usr/bin/env python3` script |
| TypeScript | `sdk/typescript/naitron.ts` | `sdk/typescript/example.ts` | `node` (strips types) |
| Go | `sdk/go/naitron.go` | `sdk/go/example/main.go` | `go build` binary |
| Rust | `sdk/rust/src/lib.rs` | `sdk/rust/examples/hello.rs` | `cargo build` binary |

Build the Go + Rust examples: `make sdk-examples`.

## Register a controller (on a running core)

```sh
ntc service add hello ./sdk/python/example.py
ntc route add GET /api/hello/:name hello
curl localhost:3000/api/hello/world
```

Each example handler receives method, path, query, headers, captured path
params (`:name`), and the authenticated subject; returns `(status, content_type,
body)`.
