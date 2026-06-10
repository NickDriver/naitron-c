# Open problems / deferred items (come back to these)

Running log of issues found mid-development that are non-blocking. Per the
working agreement: write them down, keep building, revisit later (e.g. at the
Wave-3 deep live test).

## M9 — live JWKS-over-HTTPS + ES256

- **JWKS refresh blocks the event loop.** The unknown-`kid` refresh does a
  bounded blocking HTTPS fetch (short timeout) directly in `ntc_mw_before`,
  which runs on the gateway event loop. A min-refresh interval guard bounds it
  to at most one fetch per interval (so a flood of forged kids can't trigger a
  fetch storm), but a single refresh still briefly stalls the loop. Proper fix:
  move the fetch onto the non-blocking poller (async resolver/fetch state
  machine) or a worker thread. Acceptable for now because the startup fetch
  covers the steady state and rotation is rare.
- **CA bundle is mechanism-first.** `ntc_ca_load_pem()` + the `auth.jwks_ca`
  override are the real, tested path. The default bundled root store
  (`third_party/ca/roots.pem`) is whatever is vendored there; refreshing it from
  the upstream Mozilla/curl bundle is an ops task, and install-path resolution
  (vs. cwd-relative) is future work.
