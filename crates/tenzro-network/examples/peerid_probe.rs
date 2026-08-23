//! Print the node identity this machine derives for a given data directory.
//!
//! Operator diagnostic for the hardware-rooted identity. Run it twice, or
//! after clearing the data directory, and the PeerId must not change — that
//! is the property the derivation exists to provide. A different data
//! directory is a different node and must print a different PeerId.
//!
//! ```text
//! cargo run -p tenzro-network --example peerid_probe -- /var/lib/tenzro
//! ```
//!
//! Exits non-zero when the machine has no hardware root, which is the same
//! condition that stops a node from starting.

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: peerid_probe <data_dir>");
        std::process::exit(2);
    };
    let data_dir = Some(std::path::PathBuf::from(dir));
    match tenzro_network::service::node_identity_keypair(&data_dir) {
        Ok(kp) => println!("{}", libp2p::PeerId::from(kp.public())),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
