//! Fuzzes what a validator does with bytes a committee member sends it over
//! an authenticated channel: bounded frame decoding, then every message of
//! the frame through the protocol core. The property is that no frame can
//! panic the core or make it hold unbounded state.

#![no_main]

use std::sync::Mutex;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tenzro_consensus::{
    ConsensusConfig, Core, EpochStart, Frame, TimeRules, ValidatorInfo, ValidatorPublicKey, ValidatorSet,
};
use tenzro_types::primitives::Address;

fn key(seed: u8) -> ValidatorPublicKey {
    let ml_dsa = tenzro_crypto::pq::MlDsaSigningKey::from_seed(&[seed; 32]).expect("seed");
    let p256 = tenzro_crypto::P256KeyPair::from_secret_bytes(&[seed; 32]).expect("scalar");
    ValidatorPublicKey::new(ml_dsa.verifying_key_bytes().to_vec(), p256.public_key_sec1().to_vec()).expect("key")
}

fn core() -> &'static Mutex<Core> {
    static CORE: OnceLock<Mutex<Core>> = OnceLock::new();
    CORE.get_or_init(|| {
        let infos = (1..=4u8)
            .map(|i| ValidatorInfo::new(Address::new([i; 32]), key(i), [i; 32], 100))
            .collect();
        let set = ValidatorSet::new(0, infos).expect("set");
        let committee = tenzro_consensus::committee::from_validator_set(&set, 4).expect("committee");
        let start = EpochStart {
            first_height: 1,
            first_checkpoint: 0,
            prev_checkpoint: [0; 32],
            timestamp_ms: 0,
            base_blocks: vec![(0, [0; 32], [0; 32])],
            leader_lookahead_rounds: tenzro_consensus::schedule::LOOKAHEAD_ROUNDS,
        };
        let mut core = Core::new(ConsensusConfig::default().core(7, [0; 32], &TimeRules::default()), committee, 0, start);
        core.start(0);
        Mutex::new(core)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&from, rest)) = data.split_first() else { return };
    let Ok(frame) = Frame::decode(rest) else { return };
    let mut core = core().lock().expect("not poisoned");
    core.on_messages(u16::from(from % 4), frame.items, 1_000);
    core.on_tick(1_000);
    let _ = core.take_outbox();
    let _ = core.take_events();
    let _ = core.take_journal();
});
