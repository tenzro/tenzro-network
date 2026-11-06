'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { createHash, createPublicKey, verify } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { platformBackend, DeviceKey } = require('..');

const BIN = join(__dirname, '..', 'bin', 'tenzro-device-key.js');
const run = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', input: 'n\n' });
// The tests below that reach real hardware create keys in it, so they run only
// when asked: TENZRO_DEVICE_KEY_HARDWARE_TEST=1.
const hardware = platformBackend() !== null && process.env.TENZRO_DEVICE_KEY_HARDWARE_TEST === '1';

test('reports the platform backend', () => {
  assert.ok([null, 'tpm', 'secure-enclave'].includes(platformBackend()));
});

test('exposes no key export or import surface', () => {
  const names = Object.getOwnPropertyNames(DeviceKey.prototype).concat(Object.keys(DeviceKey));
  for (const n of names) assert.doesNotMatch(n, /export|import|private|secret|seed/i);
});

test('refuses to open a key without hardware', { skip: platformBackend() !== null }, () => {
  assert.throws(() => DeviceKey.open('tenzro-binding-test'), /no TPM 2.0 or Secure Enclave .* no software fallback/);
});

test('signs a digest the public key verifies', { skip: !hardware }, async () => {
  const key = DeviceKey.open('tenzro-binding-test');
  const pub = key.publicKey();
  assert.strictEqual(pub.length, 65);
  const digest = createHash('sha256').update('tenzro').digest();
  const sig = await key.signDigest(digest);
  assert.strictEqual(sig.length, 64);
  const jwk = { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') };
  assert.ok(verify('sha256', Buffer.from('tenzro'), { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, sig));
  await assert.rejects(key.signDigest(Buffer.alloc(31)), /32-byte digest/);
});

test('exposes provisionTpm', () => {
  assert.strictEqual(typeof require('..').provisionTpm, 'function');
});

test('provisioning without hardware throws and changes nothing', { skip: platformBackend() !== null }, () => {
  assert.throws(() => require('..').provisionTpm(), /no TPM 2.0 or Secure Enclave .* no software fallback/);
});

test('the provision command explains its usage', () => {
  const none = run();
  assert.strictEqual(none.status, 2);
  assert.match(none.stderr, /usage: tenzro-device-key provision/);
  const help = run('--help');
  assert.strictEqual(help.status, 0);
  assert.match(help.stdout, /storage root, attestation key and identity key/);
  assert.strictEqual(run('provision', '--bogus').status, 2);
});

test('the provision command refuses on a machine without hardware', { skip: platformBackend() !== null }, () => {
  const r = run('provision', '--yes');
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /No TPM 2.0 or Secure Enclave/);
});
