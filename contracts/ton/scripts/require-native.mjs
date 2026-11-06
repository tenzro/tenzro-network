// `npm run test:native` runs every test on the native TVM: it needs
// TON_EMULATOR, the path of a native libemulator from a TON release.
import fs from 'node:fs';

const lib = process.env.TON_EMULATOR;
if (!lib || !fs.existsSync(lib)) {
  console.error('set TON_EMULATOR to a native libemulator (libemulator-linux-x86_64.so from a TON release)');
  process.exit(1);
}
