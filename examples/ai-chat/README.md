# Streaming AI-chat — your first naitron-c app

A complete, self-contained example: a **Python controller** streams a chat
"completion" **token-by-token over SSE**, the endpoint is **JWT-protected**, a
static frontend renders the stream live, and the whole thing runs under
**`ntc dev`** so editing the controller hot-reloads it.

It exercises the v3 stack end to end: streaming (M8), auth (M3/M9), static files
(M6), and the dev loop (M10).

```
examples/ai-chat/
  chat_controller.py   streaming controller (Python SDK, run(..., stream=True))
  web/index.html       chat UI (fetch + ReadableStream parses the SSE frames)
  mint_token.py        prints a dev HS256 JWT to paste into the UI
  run.sh               configures env + launches `ntc dev`
```

## Run it

```sh
make                       # build build/ntc
examples/ai-chat/run.sh    # serves http://127.0.0.1:3000
```

Open <http://127.0.0.1:3000/>, then in another shell mint a token and paste it
into the token box:

```sh
python3 examples/ai-chat/mint_token.py
```

Type a message — the reply streams in word by word.

## How it works

- **Mounting:** `run.sh` points `NTC_CONTROLLER_BIN` at `chat_controller.py` and
  sets `NTC_CONTROLLER_ROUTE="GET /api/chat"` so the gateway routes `/api/chat`
  to it (the default would be `/api/hello`).
- **Streaming:** the controller calls `st.sse_begin()` then `st.sse_send(event,
  data)` per token; the gateway relays each chunk to the browser immediately as
  `text/event-stream`. The SDK auto-sends the terminating frame when the handler
  returns.
- **Auth:** `NTC_AUTH_MODE=jwt` + `NTC_AUTH_PROTECT=/api` makes the gateway
  verify the `Authorization: Bearer <jwt>` before the request reaches the
  controller; the validated `sub` arrives as `req["sub"]`. This demo uses an
  HS256 shared secret (`mint_token.py`); in production set `auth.jwks_url` to
  your IdP's JWKS endpoint instead (RS256/ES256, verified over TLS).
- **Hot reload:** `run.sh` uses `ntc dev`; edit `chat_controller.py` and the
  gateway respawns it on the next request — no restart.

> Why `fetch()` and not `EventSource`? `EventSource` can't send an
> `Authorization` header, so the page streams with `fetch()` + a `ReadableStream`
> reader and splits the SSE frames itself. See `DX_NOTES.md`.
