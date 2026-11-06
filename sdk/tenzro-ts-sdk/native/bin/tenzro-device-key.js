#!/usr/bin/env node
'use strict';
// tenzro-device-key provision [--yes]
//
// Provisions this machine's TPM once, so device keys can be made in it. The
// same provisioning `tenzro-node tpm provision` performs; running both is safe.

const USAGE = `usage: tenzro-device-key provision [--yes]

Provisions this machine's TPM 2.0 for @tenzro/device-key: creates the persistent
storage root, attestation key and identity key, or reports that they exist.
Run it once per machine as a user that can open the TPM (on Linux,
/dev/tpmrm0, usually the tss group). It does not touch a Secure Enclave, which
needs no provisioning. Without --yes it asks before it changes the TPM.`;

function fail(message, code = 1) {
  process.stderr.write(message + '\n');
  process.exit(code);
}

const [command, ...flags] = process.argv.slice(2);
if (command === '-h' || command === '--help') {
  process.stdout.write(USAGE + '\n');
  process.exit(0);
}
if (command !== 'provision' || flags.some((f) => f !== '--yes')) fail(USAGE, 2);

let deviceKey;
try {
  deviceKey = require('..');
} catch (e) {
  fail(e.message);
}

const backend = deviceKey.platformBackend();
if (backend === null) {
  fail('No TPM 2.0 or Secure Enclave is available on this machine; device keys live only in hardware and there is no software fallback.');
}
if (backend !== 'tpm') {
  process.stdout.write('This machine uses the Secure Enclave, which needs no provisioning.\n');
  process.exit(0);
}

function run() {
  let lines;
  try {
    lines = deviceKey.provisionTpm();
  } catch (e) {
    fail(e.message);
  }
  process.stdout.write(lines.join('\n') + '\nThis machine\'s TPM is provisioned.\n');
}

if (flags.includes('--yes')) {
  run();
} else {
  process.stdout.write('This creates persistent keys in this machine\'s TPM (or confirms they exist). Continue? [y/N] ');
  process.stdin.setEncoding('utf8');
  process.stdin.once('data', (answer) => {
    if (answer.trim().toLowerCase() !== 'y') fail('Not provisioned.');
    run();
  });
}
