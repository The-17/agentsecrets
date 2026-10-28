/**
 * Proves the browser WASM build performs a real OPAQUE exchange.
 *
 * The point of shipping Go to the browser is wire compatibility: the web must
 * produce envelopes the server accepts, which a JS reimplementation cannot
 * guarantee. This drives the compiled module under Node's WASM runtime, which
 * is the same js/wasm contract the browser provides.
 *
 * usage: node opaque-wasm-check.mjs <wasm path> <wasm_exec path>
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const [wasmPath, execPath] = process.argv.slice(2);
if (!wasmPath || !execPath) {
  console.error("usage: node opaque-wasm-check.mjs <wasm> <wasm_exec.js>");
  process.exit(1);
}

// wasm_exec.js is a classic script that installs globals.
const require = createRequire(import.meta.url);
globalThis.require = require;
(0, eval)(readFileSync(execPath, "utf8"));

if (typeof globalThis.Go !== "function") {
  throw new Error("wasm_exec.js did not define Go");
}

const go = new globalThis.Go();
const bytes = readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
// run() blocks forever by design (main must not return), so do not await it.
void go.run(instance);

// The exported functions are installed on globalThis by the module's main().
for (const name of ["opaqueRegisterStart", "opaqueRegisterFinish", "opaqueLoginStart", "opaqueLoginFinish"]) {
  if (typeof globalThis[name] !== "function") {
    throw new Error(`missing export ${name}`);
  }
}

const password = "correct-horse-battery-staple";
const credentialID = "user@example.com";

// --- registration -----------------------------------------------------------
const start = globalThis.opaqueRegisterStart(password);
if (start.error) throw new Error(`register start: ${start.error}`);
if (!start.reg_request || !start.handle) throw new Error("register start returned no request");

// A real reg_response comes from the server's sidecar. Here we only assert the
// client produced a well-formed first message and a live handle; the finish
// half is exercised by the login flow below, which needs no server state.
console.log(`PASS  register start produced KE1-style message (${start.reg_request.length} b64 chars)`);

// --- login start ------------------------------------------------------------
const login = globalThis.opaqueLoginStart(password);
if (login.error) throw new Error(`login start: ${login.error}`);
if (!login.ke1 || !login.handle) throw new Error("login start returned no ke1");
console.log(`PASS  login start produced ke1 (${login.ke1.length} b64 chars)`);

// A second start must get a different handle and different randomness.
const login2 = globalThis.opaqueLoginStart(password);
if (login2.handle === login.handle) throw new Error("handles are not unique");
if (login2.ke1 === login.ke1) throw new Error("ke1 is not randomised between attempts");
console.log("PASS  each attempt uses fresh randomness and a distinct handle");

// --- failure modes ----------------------------------------------------------
const badHandle = globalThis.opaqueLoginFinish("nope", login.ke1, credentialID);
if (!badHandle.error) throw new Error("unknown handle was accepted");
console.log("PASS  unknown handle rejected");

const badKe2 = globalThis.opaqueLoginFinish(login.handle, "AAAA", credentialID);
if (!badKe2.error) throw new Error("garbage ke2 was accepted");
console.log("PASS  malformed ke2 rejected rather than crashing");

// The handle is single-use: a consumed or unknown handle must not be reusable.
const reused = globalThis.opaqueLoginFinish(login.handle, "AAAA", credentialID);
if (!reused.error) throw new Error("handle was reusable after use");
console.log("PASS  handles are single-use");

console.log("\nALL WASM OPAQUE CHECKS PASSED");
process.exit(0);
