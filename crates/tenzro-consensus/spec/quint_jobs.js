// Quint simulations from one compilation of each specification.
//
//   node quint_jobs.js work <quint> <jobs-file> <out-dir> <worker>
//   node quint_jobs.js cpus
//
// `quint run` parses and typechecks the whole specification file on every call: about a minute for
// commit_rule.qnt, longer than most of the runs it then makes. A worker does that once per specification and
// runs its jobs through Quint's own simulator (`runSimulator`, the function `quint run` calls, Rust backend), so
// an execution written here is the one `quint run` writes for the same arguments.
//
// The jobs file has one simulation per line, in the order they start:
//   gen <spec> <dir> <main> <name> <seed> <samples>
//       <samples> executions, written to <out>/<dir>
//   wit <spec> <dir> <main> <name> <seed> <samples> <invariant> <step> <key> <target>
//       up to <samples> executions of <step> until one violates <invariant>, which reaches the witness; that
//       execution is written to <out>/<dir>. Skipped once <target> jobs of <key> have reached it.
//   chk <spec> <check> <main> <name> <seed> <samples> <invariant>
//       <samples> executions, every state checked against <invariant>; a violation is written to <out>/logs.
//
// Workers share the file: a job is taken by creating <out>/claims/<line> exclusively. Worker k takes a job only
// while k is below the processors the host has free (`cpus`), so a host loaded by others runs fewer; the first
// MIN_JOBS workers (default 2) always run, at the low priority the caller gives them. No job starts at or after
// DEADLINE (Unix seconds); at HARD_DEADLINE a running simulation is stopped and its job reported CUT. A worker
// prints one line per job:
//   GEN <name> traces=<k> duplicates=<d>               <d> dropped: another job wrote the same states
//   WITNESS <key> <name> samples=<n> duplicates=<d>    the witness is reached
//   WITNESS-MISS <key> <name> samples=<n>              not reached in this job's executions
//   WITNESS-DONE <key> <name>                          not run: <target> jobs reached the witness already
//   CHECK-OK <check> <name> samples=<n>
//   CHECK-VIOLATED <check> <name> trace=<file>
//   FAILED <kind> <name>: <reason>
//   CUT <kind> <name>                                  stopped at HARD_DEADLINE, nothing kept
//   NOT-STARTED <kind> <name> [<key>]                  DEADLINE came first
//
// `cpus` prints the processors free for this process: the cgroup's CPU quota or the host's processors,
// whichever is fewer, less the load the rest of the host puts on them (one-minute load average); at least 1.
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const crypto = require('crypto');

const nowS = () => Date.now() / 1000;

function quotaCpus() {
  // cgroup v2: the smallest cpu.max quota on the way from this process's cgroup to the root.
  let best = Infinity;
  let rel;
  try {
    const line = fs.readFileSync('/proc/self/cgroup', 'utf8').split('\n').find(l => l.startsWith('0::'));
    if (!line) return best;
    rel = line.slice(3).trim() || '/';
  } catch (_) {
    return best;
  }
  for (;;) {
    try {
      const [quota, period] = fs.readFileSync(path.join('/sys/fs/cgroup', rel, 'cpu.max'), 'utf8').trim().split(/\s+/);
      if (quota !== 'max') best = Math.min(best, Number(quota) / Number(period));
    } catch (_) {
      // no cpu controller at this level
    }
    if (rel === '/') return best;
    rel = path.dirname(rel);
  }
}

// `own`: processes of this run already counted in the load average.
function cpus(own = 0) {
  // The host's processors: the load average counts them all (availableParallelism would already apply the quota).
  const cores = os.cpus().length;
  const others = Math.max(0, os.loadavg()[0] - own);
  return Math.max(1, Math.floor(Math.min(quotaCpus(), cores - others)));
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// The processes this one started (the Rust evaluator), by pid.
function children() {
  const pids = [];
  try {
    for (const t of fs.readdirSync('/proc/self/task')) {
      const c = fs.readFileSync(`/proc/self/task/${t}/children`, 'utf8').trim();
      if (c) pids.push(...c.split(/\s+/).map(Number));
    }
  } catch (_) {
    // not Linux: nothing to stop
  }
  return pids;
}

async function work(quint, jobsFile, out, k) {
  // Quint is loaded with the first job that needs it.
  let cc = null;
  const steps = Number(process.env.STEPS || 400);
  const deadline = Number(process.env.DEADLINE || Infinity);
  const hard = Number(process.env.HARD_DEADLINE || Infinity);
  const maxWorkers = Number(process.env.JOBS || 1);
  const minWorkers = Number(process.env.MIN_JOBS || 2);
  const claims = path.join(out, 'claims');
  const staging = path.join(out, 'staging', String(k));
  fs.mkdirSync(claims, { recursive: true });
  fs.rmSync(staging, { recursive: true, force: true });
  fs.mkdirSync(staging, { recursive: true });
  const lines = fs.readFileSync(jobsFile, 'utf8').split('\n').filter(l => l.trim());
  const stages = new Map();
  const say = s => fs.writeSync(1, s + '\n');
  const busy = () => fs.readdirSync(claims).filter(f => f.startsWith('busy.')).length;

  async function stageOf(spec) {
    if (!stages.has(spec)) {
      cc = cc || require(path.join(path.dirname(fs.realpathSync(quint)), 'cliCommands.js'));
      const base = {
        input: spec, init: 'init', step: 'step', invariant: 'true', invariants: [], witnesses: [], hide: [],
        verbosity: 0, backend: 'rust', mbt: false, nThreads: 1, maxSteps: steps, nTraces: 1,
      };
      let s = await cc.load(base);
      for (const next of [cc.parse, cc.typecheck]) {
        if (s.isLeft()) break;
        s = await next(s.value);
      }
      if (s.isLeft()) {
        const e = s.value;
        throw new Error(`${spec}: ${e.msg} ${JSON.stringify((e.stage && e.stage.errors) || []).slice(0, 400)}`);
      }
      stages.set(spec, s.value);
    }
    return stages.get(spec);
  }

  // Runs one simulation; its executions land in the staging folder as <name>_<k>.itf.json.
  async function simulate(spec, a) {
    const st = await stageOf(spec);
    const args = {
      ...st.args, main: a.main, seed: BigInt(a.seed), maxSamples: a.samples, nTraces: a.traces, maxSteps: steps,
      nThreads: 1, step: a.step || 'step', invariant: a.invariant || 'true', mbt: a.mbt,
      outItf: path.join(staging, `${a.name}_{seq}.itf.json`),
    };
    const r = await cc.runSimulator({ ...st, args });
    if (r.isRight()) return 'ok';
    if (r.value.msg === 'Invariant violated') return 'violation';
    const errs = (r.value.stage && r.value.stage.errors) || [];
    throw new Error(`${r.value.msg}: ${errs.map(e => e.explanation || JSON.stringify(e)).join('; ').slice(0, 400)}`);
  }

  const staged = name => fs.readdirSync(staging).filter(f => f.startsWith(name + '_') && f.endsWith('.itf.json'));
  // Gzipped into <dir> under a temporary name, then renamed: a stopped worker never leaves half a file there.
  // An execution whose states another job already wrote is dropped: identical executions are replayed once.
  // Quint writes the states last and the same way each time, so equal text after "states" is equal states.
  function keep(name, dir) {
    const kept = { n: 0, dup: 0 };
    for (const f of staged(name)) {
      const src = path.join(staging, f);
      const text = fs.readFileSync(src);
      const at = text.indexOf('"states":');
      const digest = crypto.createHash('sha256').update(at < 0 ? text : text.subarray(at)).digest('hex');
      try {
        fs.writeFileSync(path.join(claims, `states.${digest}`), f, { flag: 'wx' });
      } catch (_) {
        fs.unlinkSync(src);
        kept.dup++;
        continue;
      }
      const dst = path.join(dir, f + '.gz');
      fs.writeFileSync(dst + '.part', zlib.gzipSync(text));
      fs.renameSync(dst + '.part', dst);
      fs.unlinkSync(src);
      kept.n++;
    }
    return kept;
  }
  const drop = name => staged(name).forEach(f => fs.unlinkSync(path.join(staging, f)));

  let current = null;
  if (Number.isFinite(hard)) {
    const t = setTimeout(() => {
      for (const pid of children()) {
        try {
          process.kill(pid, 'SIGKILL');
        } catch (_) {
          // already gone
        }
      }
      if (current) say(`CUT ${current}`);
      fs.rmSync(path.join(claims, `busy.${k}`), { force: true });
      process.exit(0);
    }, Math.max(0, (hard - nowS()) * 1000));
    t.unref();
  }

  for (let i = 0; i < lines.length; i++) {
    while (k >= minWorkers && nowS() < deadline && k >= Math.min(maxWorkers, cpus(busy()))) await sleep(15000);
    try {
      fs.writeFileSync(path.join(claims, String(i)), String(k), { flag: 'wx' });
    } catch (_) {
      continue;
    }
    const f = lines[i].trim().split(/\s+/);
    const [kind, spec] = f;
    if (nowS() >= deadline) {
      say(`NOT-STARTED ${kind} ${kind === 'chk' ? `${f[2]} ${f[4]} samples=${f[6]}` : `${f[4]}${kind === 'wit' ? ` ${f[9]}` : ''}`}`);
      continue;
    }
    fs.writeFileSync(path.join(claims, `busy.${k}`), '');
    try {
      if (kind === 'gen') {
        const [, , dir, main, name, seed, samples] = f;
        current = `gen ${name}`;
        const r = await simulate(spec, { main, name, seed, samples: Number(samples), traces: Number(samples), mbt: true });
        const kept = keep(name, path.join(out, dir));
        say(r === 'ok' ? `GEN ${name} traces=${kept.n} duplicates=${kept.dup}` : `FAILED gen ${name}: ${r}`);
      } else if (kind === 'wit') {
        const [, , dir, main, name, seed, samples, invariant, step, key, target] = f;
        current = `wit ${name}`;
        const reached = fs.readdirSync(claims).filter(x => x.startsWith(`reached.${key}.`)).length;
        if (reached >= Number(target)) {
          say(`WITNESS-DONE ${key} ${name}`);
        } else {
          const r = await simulate(spec, { main, name, seed, samples: Number(samples), traces: 1, invariant, step, mbt: true });
          if (r === 'violation') {
            const kept = keep(name, path.join(out, dir));
            fs.writeFileSync(path.join(claims, `reached.${key}.${i}`), '');
            say(`WITNESS ${key} ${name} samples=${samples} duplicates=${kept.dup}`);
          } else {
            drop(name);
            say(`WITNESS-MISS ${key} ${name} samples=${samples}`);
          }
        }
      } else if (kind === 'chk') {
        const [, , check, main, name, seed, samples, ...inv] = f;
        current = `chk ${check} ${name}`;
        const r = await simulate(spec, { main, name, seed, samples: Number(samples), traces: 1, invariant: inv.join(' '), mbt: false });
        if (r === 'ok') {
          drop(name);
          say(`CHECK-OK ${check} ${name} samples=${samples}`);
        } else {
          keep(name, path.join(out, 'logs'));
          say(`CHECK-VIOLATED ${check} ${name} trace=${path.join(out, 'logs', name + '_0.itf.json.gz')}`);
        }
      } else {
        say(`FAILED ${kind} line ${i + 1}: unknown job kind`);
      }
    } catch (e) {
      say(`FAILED ${current}: ${String(e.message || e).replace(/\s+/g, ' ')}`);
    }
    current = null;
    fs.rmSync(path.join(claims, `busy.${k}`), { force: true });
  }
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'cpus') {
  console.log(cpus(Number(rest[0] || 0)));
} else if (cmd === 'work' && rest.length === 4) {
  work(rest[0], rest[1], rest[2], Number(rest[3])).then(
    () => process.exit(0),
    e => {
      fs.writeSync(1, `FAILED worker ${rest[3]}: ${String(e.message || e).replace(/\s+/g, ' ')}\n`);
      process.exit(1);
    },
  );
} else {
  console.error('usage: quint_jobs.js work <quint> <jobs-file> <out-dir> <worker> | cpus [own]');
  process.exit(2);
}
