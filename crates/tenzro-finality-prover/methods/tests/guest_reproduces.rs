//! The embedded programs are exactly what RISC Zero's guest-builder
//! container builds from each guest's source, so the image ids the chain
//! names follow from the source. Rebuilding needs Docker and the RISC Zero
//! toolchain (x86-64), so the tests are ignored by default:
//!
//! ```text
//! cargo test --release -p tenzro-finality-methods --test guest_reproduces -- --ignored
//! ```
//!
//! After a change to a guest, copy the rebuilt binary its test names over
//! the embedded file in `methods/`. For the finality guest, also record its
//! image id and source digest in `methods/finality-guest.source`
//! (`tests/guest_source.rs` prints the digest), and name the image id in
//! `config/genesis-prod.toml`.

use std::path::Path;

use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};

/// Rebuilds the guest package in `methods/<package>` and checks the
/// program `name` it builds is `elf` with image id `id`.
fn rebuilt_matches(package: &str, name: &str, embedded: &str, elf: &[u8], id: &[u32; 8]) {
    let methods = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = methods.join("../../..").canonicalize().expect("the repository root");
    let docker = DockerOptionsBuilder::default().root_dir(root).build().expect("docker options");
    let options = GuestOptionsBuilder::default().use_docker(docker).build().expect("guest options");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-rebuild"));
    let built = risc0_build::build_package(&risc0_build::get_package(methods.join(package)), &out, options)
        .expect("the guest builds");
    let guest = built.iter().find(|g| g.name == name).expect("the guest program");
    assert!(
        guest.elf.as_ref() == elf,
        "methods/{embedded} is stale: copy {} over it",
        guest.path
    );
    assert_eq!(guest.image_id.as_words(), &id[..]);
}

#[test]
#[ignore]
fn the_embedded_program_is_the_guest_builder_output() {
    rebuilt_matches(
        "guest",
        "finality-guest",
        "finality-guest.bin",
        tenzro_finality_methods::FINALITY_GUEST_ELF,
        &tenzro_finality_methods::FINALITY_GUEST_ID,
    );
}

#[test]
#[ignore]
fn the_embedded_handover_program_is_the_guest_builder_output() {
    rebuilt_matches(
        "handover-guest",
        "handover-guest",
        "handover-guest.bin",
        tenzro_finality_methods::HANDOVER_GUEST_ELF,
        &tenzro_finality_methods::HANDOVER_GUEST_ID,
    );
}
