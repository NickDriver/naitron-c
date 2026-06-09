#!/usr/bin/env python3
"""Example naitron-c controller in Python."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import naitron  # noqa: E402


def handle(req):
    body = json.dumps({
        "controller": "py-hello",
        "lang": "python",
        "pid": os.getpid(),
        "method": req["method"],
        "path": req["path"],
        "name": req["params"].get("name", ""),
        "sub": req["sub"],
    }, separators=(",", ":"))
    return 200, "application/json", body


naitron.run(handle, "py-hello")
