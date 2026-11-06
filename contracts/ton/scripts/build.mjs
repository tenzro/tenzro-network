// Compile the bridge (the jetton master), the TEP-74 jetton wallet and the
// finality client with the FunC compiler and write their code cells.
import fs from 'node:fs';
import path from 'node:path';
import { compileFunc } from '@ton-community/func-js';

const dir = path.dirname(new URL(import.meta.url).pathname);
const read = (f) => fs.readFileSync(path.join(dir, '../contracts', f), 'utf8');
const jetton = ['prelude.fc', 'jetton/params.fc', 'jetton/op-codes.fc', 'jetton/jetton-utils.fc'];
const contracts = {
  bridge: [...jetton, 'bridge.fc'],
  'jetton-wallet': [...jetton, 'jetton/jetton-wallet.fc'],
  finality: ['prelude.fc', 'finality.fc'],
  'agent-account': ['prelude.fc', 'state-proof.fc', 'agent-account-config.fc', 'agent-account.fc'],
  'settlement-lock': ['prelude.fc', 'state-proof.fc', 'settlement-lock.fc'],
};

fs.mkdirSync(path.join(dir, '../build'), { recursive: true });
for (const [name, targets] of Object.entries(contracts)) {
  const sources = Object.fromEntries(targets.map((f) => [f, read(f)]));
  const result = await compileFunc({ targets, sources });
  if (result.status === 'error') {
    console.error(result.message);
    process.exit(1);
  }
  fs.writeFileSync(path.join(dir, `../build/${name}.code.boc.b64`), result.codeBoc);
  console.log(`compiled ${name}`);
}
