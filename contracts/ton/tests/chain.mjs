// The emulated chain the tests run on. With TON_EMULATOR set to a native
// libemulator (the TON node's own transaction emulator, from a TON release),
// every transaction and get method runs on the native TVM; otherwise on the
// sandbox's bundled emulator.
import { Blockchain } from '@ton/sandbox';
import { serializeTuple } from '@ton/core';

const VERBOSITY = { short: 0, full: 1, full_location: 2, full_location_gas: 3, full_location_stack: 4, full_location_stack_verbose: 5 };

async function nativeExecutor(lib) {
  const koffi = (await import('koffi')).default;
  const so = koffi.load(lib);
  const f = (sig) => so.func(sig);
  const tx = {
    create: f('void *transaction_emulator_create(const char *config, int verbosity)'),
    unixtime: f('bool transaction_emulator_set_unixtime(void *em, uint32_t t)'),
    lt: f('bool transaction_emulator_set_lt(void *em, uint64_t lt)'),
    seed: f('bool transaction_emulator_set_rand_seed(void *em, const char *seed)'),
    chksig: f('bool transaction_emulator_set_ignore_chksig(void *em, bool ignore)'),
    libs: f('bool transaction_emulator_set_libs(void *em, const char *libs)'),
    debug: f('bool transaction_emulator_set_debug_enabled(void *em, bool on)'),
    run: f('const char *transaction_emulator_emulate_transaction(void *em, const char *account, const char *msg)'),
    destroy: f('void transaction_emulator_destroy(void *em)'),
  };
  const vm = {
    create: f('void *tvm_emulator_create(const char *code, const char *data, int verbosity)'),
    libs: f('bool tvm_emulator_set_libraries(void *em, const char *libs)'),
    c7: f('bool tvm_emulator_set_c7(void *em, const char *address, uint32_t now, uint64_t balance, const char *seed, const char *config)'),
    gas: f('bool tvm_emulator_set_gas_limit(void *em, int64_t gas)'),
    debug: f('bool tvm_emulator_set_debug_enabled(void *em, bool on)'),
    run: f('const char *tvm_emulator_run_get_method(void *em, int method, const char *stack)'),
    destroy: f('void tvm_emulator_destroy(void *em)'),
  };
  const must = (ok, what) => {
    if (!ok) throw new Error(`native emulator refused ${what}`);
  };
  const transaction = (args, message) => {
    const em = tx.create(args.config, VERBOSITY[args.verbosity]);
    if (!em) throw new Error('native emulator: bad config');
    try {
      must(tx.unixtime(em, args.now), 'unixtime');
      must(tx.lt(em, args.lt), 'lt');
      if (args.randomSeed) must(tx.seed(em, args.randomSeed.toString('hex')), 'rand seed');
      must(tx.chksig(em, args.ignoreChksig), 'ignore_chksig');
      if (args.libs) must(tx.libs(em, args.libs.toBoc().toString('base64')), 'libs');
      must(tx.debug(em, args.debugEnabled), 'debug');
      const r = JSON.parse(tx.run(em, args.shardAccount, message));
      return {
        result: r.success
          ? { success: true, transaction: r.transaction, shardAccount: r.shard_account, vmLog: r.vm_log, actions: r.actions ?? null }
          : { success: false, error: r.error, vmResults: 'vm_log' in r ? { vmLog: r.vm_log, vmExitCode: r.vm_exit_code } : undefined },
        logs: '',
        debugLogs: '',
      };
    } finally {
      tx.destroy(em);
    }
  };
  return {
    async runTransaction(args) {
      return transaction(args, args.message.toBoc().toString('base64'));
    },
    async runTickTock() {
      throw new Error('tick-tock transactions are not used by these tests');
    },
    async runGetMethod(args) {
      const em = vm.create(args.code.toBoc().toString('base64'), args.data.toBoc().toString('base64'), VERBOSITY[args.verbosity]);
      try {
        if (args.libs) must(vm.libs(em, args.libs.toBoc().toString('base64')), 'libs');
        must(vm.c7(em, args.address.toRawString(), args.unixTime, args.balance, args.randomSeed.toString('hex'), args.config), 'c7');
        must(vm.gas(em, args.gasLimit), 'gas limit');
        must(vm.debug(em, args.debugEnabled), 'debug');
        const stack = serializeTuple(args.stack).toBoc().toString('base64');
        return { output: JSON.parse(vm.run(em, args.methodId, stack)), logs: '', debugLogs: '' };
      } finally {
        vm.destroy(em);
      }
    },
  };
}

export async function createChain() {
  const lib = process.env.TON_EMULATOR;
  return Blockchain.create(lib ? { executor: await nativeExecutor(lib) } : undefined);
}
