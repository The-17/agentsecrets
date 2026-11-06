/**
 * Does the server accept OPAQUE messages built by the browser WASM module?
 *
 * This is the claim that matters for shipping Go to the browser. The WASM
 * self-check proves the module produces well-formed messages; this proves the
 * server's sidecar accepts them, and that the v2 export key survives the
 * exchange. The export key wraps the second vault share, so a WASM build that
 * dropped it would strand v2 accounts even though registration succeeded.
 *
 * Runs against a live server with a sidecar. Without OPAQUE configured the
 * endpoint answers 503 and this exits non-zero, rather than pretending to pass.
 *
 * usage: node scripts/opaque-wasm-server.mjs <wasm> <wasm_exec> <baseUrl>
 */

import { assertCredentialIdVectors, credentialId, loadWasm } from "./opaque-wasm-common.mjs";

const [wasmPath, execPath, base] = process.argv.slice(2);
if (!wasmPath || !execPath || !base) {
  console.error("usage: node scripts/opaque-wasm-server.mjs <wasm> <wasm_exec> <baseUrl>");
  process.exit(1);
}

assertCredentialIdVectors();
await loadWasm(wasmPath, execPath);

const password = "correct-horse-battery-staple";
const email = "wasm-probe@example.com";
const credentialID = credentialId(email);

let failures = 0;
const check = (name, ok, detail = "") => {
  if (ok) {
    console.log(`PASS  ${name}`);
    return;
  }
  failures += 1;
  console.log(`FAIL  ${name}  (${detail})`);
};

const start = globalThis.opaqueRegisterStart(password);
check("wasm produced reg_request", Boolean(start.reg_request), start.error);

const res = await fetch(`${base}/api/auth/opaque/register/start/`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ reg_request: start.reg_request, credential_id: credentialID }),
});
const body = await res.json().catch(() => ({}));

check(
  "server accepted the WASM registration request",
  res.ok,
  `status ${res.status}: ${JSON.stringify(body).slice(0, 160)}`,
);

if (res.ok) {
  const regResponse = body?.data?.reg_response;
  check("server returned a reg_response", Boolean(regResponse));
  if (regResponse) {
    const finished = globalThis.opaqueRegisterFinish(start.handle, regResponse, credentialID);
    check("wasm completed registration from the server's response", Boolean(finished.reg_record), finished.error);
    check("wasm produced the v2 vault export key", Boolean(finished.export_key), finished.error);
  }
}

console.log(failures === 0 ? "\nWASM <-> SERVER OPAQUE COMPATIBLE" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
