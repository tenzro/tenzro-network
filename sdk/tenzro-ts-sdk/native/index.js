'use strict';
// Loads the prebuilt binary for this platform. A local build
// (`npm run build`) wins over the published per-platform package.
const { existsSync } = require('node:fs');
const { join } = require('node:path');

const PLATFORMS = {
  'linux-x64': 'linux-x64-gnu',
  'linux-arm64': 'linux-arm64-gnu',
  'darwin-arm64': 'darwin-arm64',
  'darwin-x64': 'darwin-x64',
  'win32-x64': 'win32-x64-msvc',
};

function load() {
  const suffix = PLATFORMS[`${process.platform}-${process.arch}`];
  if (!suffix) {
    throw new Error(
      `@tenzro/device-key has no build for ${process.platform}-${process.arch}; ` +
        'device keys need a TPM 2.0 or Secure Enclave platform',
    );
  }
  const local = join(__dirname, `device-key.${suffix}.node`);
  if (existsSync(local)) return require(local);
  return require(`@tenzro/device-key-${suffix}`);
}

module.exports = load();
