/**
 * Shared helpers for the js/wasm OPAQUE harnesses.
 *
 * The credential id is authenticated inside the OPAQUE record, so a harness
 * that derives it differently from the CLI would be testing a different
 * contract and could pass while the web console is broken. One helper here,
 * pinned against Go's independent vectors, keeps all three harnesses honest.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

// Must match opaqueCredentialNamespace in pkg/auth/opaque_login.go.
const NAMESPACE = Buffer.from("6f9619ff8b86d011b42d00c04fc964ff", "hex");

/** UUIDv5(namespace, lowercase(trim(email))), byte for byte like the CLI. */
export function credentialId(email) {
  const name = email.trim().toLowerCase();
  const hash = createHash("sha1").update(NAMESPACE).update(name, "utf8").digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Vectors computed independently in pkg/auth/opaque_credential_id_test.go. */
export function assertCredentialIdVectors() {
  const cases = [
    ["test@example.com", "3df16d73-1694-500b-8507-78ec2acda1f7"],
    ["opaque-test@example.com", "0e6acf9f-4723-5965-8654-0ca3946867ef"],
    ["  TEST@Example.COM ", "3df16d73-1694-500b-8507-78ec2acda1f7"],
  ];
  for (const [email, want] of cases) {
    const got = credentialId(email);
    if (got !== want) {
      throw new Error(`credentialId(${JSON.stringify(email)}) = ${got}, want ${want}`);
    }
  }
}

/**
 * Load a Go js/wasm module under Node. wasm_exec.js is a classic GOROOT script
 * that installs the Go global; it is a build artifact we generated ourselves,
 * not input from a remote peer. run() never resolves by design (a wasm main
 * must not return), so it is deliberately not awaited.
 */
export async function loadWasm(wasmPath, execPath) {
  const require = createRequire(import.meta.url);
  globalThis.require = require;
  (0, eval)(readFileSync(execPath, "utf8"));
  if (typeof globalThis.Go !== "function") {
    throw new Error("wasm_exec.js did not define Go");
  }
  const go = new globalThis.Go();
  const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), go.importObject);
  void go.run(instance);
}

export const EXPECTED_EXPORTS = [
  "opaqueRegisterStart",
  "opaqueRegisterFinish",
  "opaqueLoginStart",
  "opaqueLoginFinish",
];
