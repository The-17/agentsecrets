/**
 * Full OPAQUE lifecycle through the browser WASM module, against a real server.
 *
 * Proves the whole chain the web console will run:
 *   1. password login works before enrollment
 *   2. WASM registers the account (server stores the record)
 *   3. password login is then REFUSED (password_login_disabled)
 *   4. WASM logs in with OPAQUE and receives a full session
 *   5. the session carries the vault, so the console can unlock it
 *
 * usage: node opaque-wasm-lifecycle.mjs <wasm> <wasm_exec> <baseUrl>
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const [wasmPath, execPath, base] = process.argv.slice(2);
if (!wasmPath || !execPath || !base) {
  console.error("usage: node opaque-wasm-lifecycle.mjs <wasm> <wasm_exec> <baseUrl>");
  process.exit(1);
}

const require = createRequire(import.meta.url);
globalThis.require = require;
(0, eval)(readFileSync(execPath, "utf8"));
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), go.importObject);
void go.run(instance);

let failures = 0;
const check = (name, ok, detail = "") => {
  if (ok) console.log(`PASS  ${name}`);
  else {
    failures += 1;
    console.log(`FAIL  ${name}  (${detail})`);
  }
};

const email = `wasm-life+${Date.now()}@example.com`;
const password = "correct-horse-battery-staple";
const credentialID = email.toLowerCase();

const post = async (path, body, token) => {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${base}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
};

// 1. register + password login
const reg = await post("/api/auth/register/", {
  email,
  password,
  first_name: "Wasm",
  last_name: "Life",
  key_salt: "AAAA",
  terms_agreement: true,
});
check("register", reg.status === 201, `status ${reg.status}`);

const pwLogin = await post("/api/auth/login/", { email, password });
check("password login before enrollment", pwLogin.status === 200, `status ${pwLogin.status}`);
const access = pwLogin.body?.data?.access;

// 2. enroll through WASM
const start = globalThis.opaqueRegisterStart(password);
check("wasm registration start", Boolean(start.reg_request), start.error);

const started = await post("/api/auth/opaque/register/start/", {
  reg_request: start.reg_request,
  credential_id: credentialID,
});
check("server registration start", started.status === 200, `status ${started.status}`);

const regResponse = started.body?.data?.reg_response;
const finished = globalThis.opaqueRegisterFinish(start.handle, regResponse, credentialID);
check("wasm registration finish", Boolean(finished.reg_record), finished.error);

const stored = await post(
  "/api/auth/opaque/register/finish/",
  { reg_record: finished.reg_record, credential_id: credentialID },
  access
);
check("server stored the record", stored.status === 200, `status ${stored.status}: ${JSON.stringify(stored.body).slice(0, 120)}`);

// 3. password must now be refused
const pwAfter = await post("/api/auth/login/", { email, password });
check("password login refused after enrollment", pwAfter.status === 401, `status ${pwAfter.status}`);
check(
  "refusal carries password_login_disabled",
  pwAfter.body?.code === "password_login_disabled" || pwAfter.body?.data?.code === "password_login_disabled",
  JSON.stringify(pwAfter.body).slice(0, 120)
);

// 4. OPAQUE login through WASM
const loginStart = globalThis.opaqueLoginStart(password);
check("wasm login start", Boolean(loginStart.ke1), loginStart.error);

const ls = await post("/api/auth/opaque/login/start/", {
  email,
  ke1: loginStart.ke1,
  credential_id: credentialID,
});
check("server login start", ls.status === 200, `status ${ls.status}: ${JSON.stringify(ls.body).slice(0, 120)}`);

const ke2 = ls.body?.data?.ke2;
const serverState = ls.body?.data?.server_state;
const loginFinish = globalThis.opaqueLoginFinish(loginStart.handle, ke2, credentialID);
check("wasm login finish", Boolean(loginFinish.ke3), loginFinish.error);

const lf = await post("/api/auth/opaque/login/finish/", {
  email,
  ke3: loginFinish.ke3,
  server_state: serverState,
  credential_id: credentialID,
});
check("OPAQUE login returns a session", lf.status === 200 && Boolean(lf.body?.data?.access), `status ${lf.status}`);
check("session carries the vault field", lf.body?.data?.vault !== undefined);
check("session carries user.id", Boolean(lf.body?.data?.user?.id));

// 5. wrong password must fail at the exchange, not authenticate
const bad = globalThis.opaqueLoginStart("definitely-the-wrong-password");
const badStart = await post("/api/auth/opaque/login/start/", {
  email,
  ke1: bad.ke1,
  credential_id: credentialID,
});
let badRejected = false;
if (badStart.status === 200) {
  const badFinish = globalThis.opaqueLoginFinish(badStart.body?.data?.ke2 ? bad.handle : bad.handle, badStart.body?.data?.ke2, credentialID);
  badRejected = Boolean(badFinish.error);
} else {
  badRejected = true;
}
check("wrong password fails the exchange", badRejected);

console.log(failures === 0 ? "\nOPAQUE WEB LIFECYCLE PASSED" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
