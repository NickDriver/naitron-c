#!/usr/bin/env python3
"""Streaming AI-chat controller (naitron-c Python SDK, v3 streaming).

Streams a "completion" token-by-token over SSE. In a real app the token loop
would pull from an LLM client; here it's a deterministic canned reply so the
example is self-contained. The endpoint is JWT-protected by the gateway, so
`req["sub"]` is the authenticated user.
"""
import json
import os
import sys
import time
from urllib.parse import parse_qs, unquote_plus

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))
import naitron  # noqa: E402


def fake_llm_tokens(prompt):
    reply = ("You said: \"%s\". " % prompt) + (
        "This reply is streamed from a naitron-c controller one token at a "
        "time over Server-Sent Events, so the browser renders it as it arrives."
    )
    return reply.split(" ")


def handle(req, st):
    # message comes from ?q=... or a JSON body {"message": "..."}
    msg = ""
    if req["query"]:
        q = parse_qs(req["query"])
        if "q" in q:
            msg = unquote_plus(q["q"][0])
    if not msg and req["body"]:
        try:
            msg = json.loads(req["body"]).get("message", "")
        except Exception:
            pass
    msg = msg.strip() or "(empty message)"
    user = req["sub"] or "anonymous"

    st.sse_begin()
    st.sse_send("meta", json.dumps({"user": user}))
    for tok in fake_llm_tokens(msg):
        st.sse_send("token", tok + " ")
        time.sleep(0.04)
    st.sse_send("done", "[DONE]")


if __name__ == "__main__":
    naitron.run(handle, name="chat", stream=True)
