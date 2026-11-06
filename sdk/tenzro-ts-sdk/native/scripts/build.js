'use strict';
// Builds the binding for the host and places it where index.js looks first.
const { execFileSync } = require('node:child_process');
const { copyFileSync } = require('node:fs');
const { join } = require('node:path');

const SUFFIX = {
  'linux-x64': 'linux-x64-gnu',
  'linux-arm64': 'linux-arm64-gnu',
  'darwin-arm64': 'darwin-arm64',
  'darwin-x64': 'darwin-x64',
  'win32-x64': 'win32-x64-msvc',
}[`${process.platform}-${process.arch}`];
if (!SUFFIX) throw new Error(`unsupported platform ${process.platform}-${process.arch}`);

execFileSync('cargo', ['build', '--release', '-p', 'tenzro-device-key-node', '--features', 'node'], {
  stdio: 'inherit',
  cwd: __dirname,
});
const target = process.env.CARGO_TARGET_DIR || join(__dirname, '..', '..', '..', '..', 'target');
const lib = {
  linux: 'libtenzro_device_key_node.so',
  darwin: 'libtenzro_device_key_node.dylib',
  win32: 'tenzro_device_key_node.dll',
}[process.platform];
copyFileSync(join(target, 'release', lib), join(__dirname, '..', `device-key.${SUFFIX}.node`));
