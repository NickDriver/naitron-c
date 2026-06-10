#!/usr/bin/env python3
"""Mint a dev HS256 JWT for the AI-chat example.

  python3 mint_token.py [secret] [sub]

Prints a compact JWT signed with `secret` (default "dev-secret", matching
run.sh). Paste it into the chat UI's token box. In production you would not mint
tokens here - the gateway validates RS256/ES256 from your IdP's JWKS instead
(see `auth.jwks_url`).
"""
import base64
import hashlib
import hmac
import json
import sys
import time


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def main():
    secret = sys.argv[1] if len(sys.argv) > 1 else "dev-secret"
    sub = sys.argv[2] if len(sys.argv) > 2 else "demo-user"
    now = int(time.time())
    sep = (",", ":")  # compact JSON (no spaces), matching typical JWT encoders
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=sep).encode())
    payload = b64(json.dumps({"sub": sub, "scope": "chat", "iat": now, "exp": now + 3600}, separators=sep).encode())
    sig = b64(hmac.new(secret.encode(), (header + "." + payload).encode(), hashlib.sha256).digest())
    print(header + "." + payload + "." + sig)


if __name__ == "__main__":
    main()
