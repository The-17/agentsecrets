import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import nacl from 'tweetnacl';
import { encryptSecret, decryptSecret, generateWorkspaceKey, sealForUser } from '../src/crypto.js';

describe('AES-256-GCM secret envelope (byte-compatible with Go EncryptSecret)', () => {
  it('round-trips', () => {
    const key = generateWorkspaceKey();
    assert.equal(key.length, 32);
    const ct = encryptSecret('sk_live_123', key);
    assert.equal(decryptSecret(ct, key), 'sk_live_123');
  });
  it('uses a random 12-byte nonce prefix (Go format: base64(nonce||ct||tag))', () => {
    const key = generateWorkspaceKey();
    const a = Buffer.from(encryptSecret('same', key), 'base64');
    const b = Buffer.from(encryptSecret('same', key), 'base64');
    assert.notDeepEqual(a.subarray(0, 12), b.subarray(0, 12));
    assert.ok(a.length > 12 + 16 && b.length > 12 + 16);
  });
  it('rejects wrong key / tampered ciphertext', () => {
    const ct = encryptSecret('v', generateWorkspaceKey());
    assert.throws(() => decryptSecret(ct, generateWorkspaceKey()));
    const raw = Buffer.from(ct, 'base64');
    const last = raw[raw.length - 1];
    assert.ok(last !== undefined);
    raw[raw.length - 1] = last ^ 1;
    assert.throws(() => decryptSecret(raw.toString('base64'), generateWorkspaceKey()));
  });
  it('rejects bad key lengths', () => {
    assert.throws(() => encryptSecret('v', Buffer.alloc(16)), /32 bytes/);
    assert.throws(() => decryptSecret('eA==', Buffer.alloc(16)), /32 bytes/);
  });
  it('decrypts a structurally valid external envelope', () => {
    // Build the envelope by hand (independent construction, same spec).
    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const body = Buffer.concat([c.update('hello', 'utf8'), c.final(), c.getAuthTag()]);
    const env = Buffer.concat([nonce, body]).toString('base64');
    assert.equal(decryptSecret(env, key), 'hello');
  });
});

describe('sealed box to user public key (libsodium crypto_box_seal construction)', () => {
  it('opens with the recipient secret key', () => {
    const recipient = nacl.box.keyPair();
    const sealed = sealForUser(Buffer.from(recipient.publicKey), Buffer.from('workspace-key-32-bytes-0123456789ab'.slice(0, 32)));
    // Sealed box = 32B ephemeral pk + 16B overhead + message.
    assert.equal(sealed.length, 32 + 16 + 32);
    const epk = sealed.subarray(0, 32);
    const boxed = sealed.subarray(32);
    const h = crypto.createHash('blake2b512');
    h.update(epk);
    h.update(Buffer.from(recipient.publicKey));
    const nonce = new Uint8Array(h.digest().subarray(0, 24));
    const opened = nacl.box.open(new Uint8Array(boxed), nonce, new Uint8Array(epk), recipient.secretKey);
    assert.ok(opened);
    assert.equal(Buffer.from(opened).toString('utf8'), 'workspace-key-32-bytes-0123456789ab'.slice(0, 32));
  });
  it('uses a fresh ephemeral key per call', () => {
    const recipient = nacl.box.keyPair();
    const a = sealForUser(Buffer.from(recipient.publicKey), Buffer.from('x'.repeat(32)));
    const b = sealForUser(Buffer.from(recipient.publicKey), Buffer.from('x'.repeat(32)));
    assert.notDeepEqual(a.subarray(0, 32), b.subarray(0, 32));
  });
  it('rejects bad public key size', () => {
    assert.throws(() => sealForUser(Buffer.alloc(16), Buffer.alloc(32)), /public key size/);
  });
});
