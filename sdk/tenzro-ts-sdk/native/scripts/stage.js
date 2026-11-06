'use strict';
// Copies the per-platform binaries into their npm packages before a publish.
//
//   node scripts/stage.js <dir>
//
// <dir> holds device-key.<suffix>.node for every platform, built on that
// platform with `npm run build` (each build leaves its binary next to
// index.js). Refuses when any platform is missing, so a release never
// publishes a platform package without its binary.
const { copyFileSync, existsSync } = require('node:fs');
const { join } = require('node:path');

const SUFFIXES = [
  'linux-x64-gnu',
  'linux-arm64-gnu',
  'darwin-arm64',
  'darwin-x64',
  'win32-x64-msvc',
];

const dir = process.argv[2];
if (!dir) throw new Error('usage: node scripts/stage.js <dir-with-binaries>');
const missing = SUFFIXES.filter((s) => !existsSync(join(dir, `device-key.${s}.node`)));
if (missing.length) {
  throw new Error(`no binary for: ${missing.join(', ')}`);
}
for (const s of SUFFIXES) {
  const file = `device-key.${s}.node`;
  copyFileSync(join(dir, file), join(__dirname, '..', 'npm', s, file));
  console.log(`staged npm/${s}/${file}`);
}
