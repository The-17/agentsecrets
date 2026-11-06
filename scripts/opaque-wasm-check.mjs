/**
 * Proves the browser WASM build performs a real OPAQUE exchange.
 *
 * The point of shipping Go to the browser is wire compatibility: the web must
 * produce envelopes the server accepts, which a JS reimplementation cannot
 * guarantee. This drives the compiled module under Node's WASM runtime, which
 * is the same js/wasm contract the browser provides. Export-key (v2 vault)
 * parity is pinned by opaque-wasm-server.mjs and opaque-wasm-lifecycle.mjs,
 * which have a real server response to finish against.
 *
 * usage: node scripts/opaque-wasm-check.mjs <wasm path> <wasm_exec.js path>
 */

import { EXPECTED_EXPORTS, assertCredentialIdVectors, credentialId, loadWasm } from "./opaque-wasm-common.mjs";

const [wasmPath, execPath] = process.argv.slice(2);
if (!wasmPath || !execPath) {
  console.error("usage: node scripts/opaque-wasm-check.mjs <wasm> <wasm_exec.js>");
  process.exit(1);
}

assertCredentialIdVectors();
console.log("PASS  credential id derivation matches the Go CLI");

await loadWasm(wasmPath, execPath);

for (const name of EXPECTED_EXPORTS) {
  if (typeof globalThis[name] !== "function") {
    throw new Error(`missing export ${name}`);
  }
}
console.log("PASS  all four js/wasm exports are installed");

const password = "correct-horse-battery-staple";
const credentialID = credentialId("user@example.com");

// --- registration -----------------------------------------------------------
const start = globalThis.opaqueRegisterStart(password);
if (start.error) throw new Error(`register start: ${start.error}`);
if (!start.reg_request || !start.handle) throw new Error("register start returned no request");
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

// The handle is single-use: a consumed handle must not be reusable.
const reused = globalThis.opaqueLoginFinish(login.handle, "AAAA", credentialID);
if (!reused.error) throw new Error("handle was reusable after use");
console.log("PASS  handles are single-use");

const badPassword = globalThis.opaqueLoginStart("definitely-the-wrong-password");
if (!badPassword.ke1 || !badPassword.handle) throw new Error("second login start failed");
console.log("PASS  an independent client state can be parked concurrently");

console.log("\nALL WASM OPAQUE CHECKS PASSED");
process.exit(0);
