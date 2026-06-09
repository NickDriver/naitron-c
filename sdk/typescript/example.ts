#!/usr/bin/env node
// Example naitron-c controller in TypeScript (Node strips types at runtime).
import { run, type NtcRequest } from "./naitron.ts";

run((req: NtcRequest): [number, string, string] => {
  const body = JSON.stringify({
    controller: "ts-hello",
    lang: "typescript",
    pid: process.pid,
    method: req.method,
    path: req.path,
    name: req.params.name ?? "",
    sub: req.sub,
  });
  return [200, "application/json", body];
}, "ts-hello");
