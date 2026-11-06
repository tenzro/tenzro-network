//! Embeds the guest programs: `finality-guest.bin` and `handover-guest.bin`,
//! each as RISC Zero's guest-builder container builds it, and their image
//! ids, computed here. The container fixes the image id on every machine, and
//! embedding its output instead of building it lets the prover build on any
//! host, including the aarch64 GPU hosts the container and toolchain do not
//! run on. `tests/guest_reproduces.rs` rebuilds the guests and checks the
//! files.

use std::fmt::Write as _;
use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = String::new();
    for (file, name, what) in [
        ("finality-guest.bin", "FINALITY_GUEST", "finality program"),
        ("handover-guest.bin", "HANDOVER_GUEST", "handover program"),
    ] {
        let bin = dir.join(file);
        println!("cargo:rerun-if-changed={}", bin.display());
        let elf = std::fs::read(&bin).unwrap_or_else(|e| panic!("methods/{file}: {e}"));
        let id = risc0_binfmt::compute_image_id(&elf)
            .unwrap_or_else(|e| panic!("the {what}'s image id: {e}"));
        write!(
            out,
            "/// The {what}.\npub const {name}_ELF: &[u8] = include_bytes!({:?});\n\
             /// The {what}'s image id.\npub const {name}_ID: [u32; 8] = {:?};\n",
            bin.display().to_string(),
            id.as_words(),
        )
        .expect("formatting methods.rs");
    }
    let path = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("methods.rs");
    std::fs::write(path, out).expect("writing methods.rs");
}
