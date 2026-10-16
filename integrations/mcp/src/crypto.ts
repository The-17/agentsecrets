/**
 * Client-side cryptography — CLOUD MODE ONLY (headless operation).
 * Byte-compatible with pkg/crypto in the Go CLI, used solely so the bridge
 * can encrypt for POST secrets.create and decrypt pull results without the
 * binary. In LOCAL mode the helper performs all crypto inside the CLI
 * (keychain-held keys); this module is never consulted there.
 *
 * - EncryptSecret / DecryptSecret: AES-256-GCM, 12-byte random nonce
 *   prepended to the ciphertext, whole thing base64-std-encoded. Implemented
 *   with node:crypto (no third-party primitives — never roll your own).
 * - sealForUser: NaCl crypto_box_seal (anonymous sealed box, libsodium
 *   construction) for encrypting a fresh workspace key to a user's X25519
 *   public key on workspace_create. Uses tweetnacl's audited primitives;
 *   only the standard sealed-box *construction* is assembled here
 *   (ephemeral keypair + box + prepend ephemeral pubkey), exactly as
 *   crypto_box_seal does.
 */

import * as crypto from 'node:crypto';
import nacl from 'tweetnacl';

const NONCE_BYTES = 12;
const KEY_BYTES = 32;

export function generateWorkspaceKey(): Buffer {
  return crypto.randomBytes(KEY_BYTES);
}

/** Mirrors Go EncryptSecret: base64(nonce || AES-256-GCM(nonce, plaintext)). */
export function encryptSecret(plaintext: string, workspaceKey: Buffer): string {
  if (workspaceKey.length !== KEY_BYTES) {
    throw new Error(`invalid workspace key length ${workspaceKey.length}; want ${KEY_BYTES} bytes`);
  }
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', workspaceKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]).toString('base64');
}

/** Mirrors Go DecryptSecret. Throws on tamper / wrong key. */
export function decryptSecret(encryptedB64: string, workspaceKey: Buffer): string {
  if (workspaceKey.length !== KEY_BYTES) {
    throw new Error(`invalid workspace key length ${workspaceKey.length}; want ${KEY_BYTES} bytes`);
  }
  const raw = Buffer.from(encryptedB64, 'base64');
  if (raw.length < NONCE_BYTES + 16) throw new Error('ciphertext too short');
  const nonce = raw.subarray(0, NONCE_BYTES);
  const ct = raw.subarray(NONCE_BYTES, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', workspaceKey, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/**
 * Anonymous sealed box to a recipient X25519 public key (both 32 bytes).
 * Mirrors Go EncryptForUser (box.SealAnonymous). Returns raw bytes; callers
 * base64-encode for transport.
 */
export function sealForUser(recipientPublicKey: Buffer, data: Buffer): Buffer {
  if (recipientPublicKey.length !== KEY_BYTES) {
    throw new Error(`invalid public key size: got ${recipientPublicKey.length}, want ${KEY_BYTES}`);
  }
  const ephemeral = nacl.box.keyPair();
  // libsodium crypto_box_seal nonce derivation:
  // nonce = Blake2b(ephemeral_pk || recipient_pk) first 24 bytes.
  const derived = sealNonce(Buffer.from(ephemeral.publicKey), recipientPublicKey);
  const boxed = nacl.box(
    new Uint8Array(data),
    derived,
    new Uint8Array(recipientPublicKey),
    ephemeral.secretKey
  );
  if (!boxed) throw new Error('sealed-box encryption failed');
  return Buffer.concat([Buffer.from(ephemeral.publicKey), Buffer.from(boxed)]);
}

function sealNonce(ephemeralPk: Buffer, recipientPk: Buffer): Uint8Array {
  // crypto_generichash(BLAKE2b-512) of epk||rpk, first crypto_box_NONCEBYTES.
  const h = crypto.createHash('blake2b512');
  h.update(ephemeralPk);
  h.update(recipientPk);
  return new Uint8Array(h.digest().subarray(0, 24));
}
