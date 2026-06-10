//! Offline validator-key generator for Phase A (10 GCE validators).
//!
//! Produces, for each validator index 0..N-1:
//!   - `consensus.seed` (32 bytes, raw Ed25519 seed)
//!   - `pq.seed`        (32 bytes, raw ML-DSA-65 seed)
//!   - `p2p.seed`       (libp2p protobuf-encoded Ed25519 keypair)
//!   - `consensus.pub`  (64-char hex, 32-byte Ed25519 public key)
//!   - `pq.pub`         (hex, 1952-byte ML-DSA-65 verifying key)
//!   - `peer_id.txt`    (multihash-encoded libp2p peer ID, base58)
//!
//! Plus a single `genesis-prod.toml` at the output root with all N validators
//! pre-populated (stake = `--stake-per-validator`, default 1000 TNZO each).
//!
//! Run on a trusted laptop, NOT in CI. Upload the *.seed files to GCP Secret
//! Manager with `gcloud secrets versions add`, then commit
//! `config/genesis-prod.toml` and copy the validator-0 peer ID into the
//! Terraform `bootstrap_peer_id` variable.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libp2p::identity::Keypair as Libp2pKeypair;
use rand::RngCore;
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::{KeyPair, KeyType};

#[derive(Debug)]
struct Args {
    out_dir: PathBuf,
    count: usize,
    chain_id: u64,
    stake_per_validator: u64,
    /// Per-validator stakes (overrides `stake_per_validator` when set).
    /// Length must match `count`. Used to model the three-tier model
    /// at genesis (e.g. v0 at Tier 3 with 100,000 TNZO, v1..vN at
    /// Tier 1 with 0 TNZO).
    per_validator_stakes: Option<Vec<u64>>,
}

fn parse_args() -> Result<Args> {
    let mut out_dir: Option<PathBuf> = None;
    let mut count: usize = 10;
    let mut chain_id: u64 = 1338; // distinct from local 1337
    let mut stake_per_validator: u64 = 1000;
    let mut per_validator_stakes: Option<Vec<u64>> = None;

    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--out" => {
                out_dir = Some(PathBuf::from(
                    argv.next().context("--out requires a directory path")?,
                ));
            }
            "--count" => {
                count = argv
                    .next()
                    .context("--count requires a number")?
                    .parse()
                    .context("--count must be a positive integer")?;
            }
            "--chain-id" => {
                chain_id = argv
                    .next()
                    .context("--chain-id requires a number")?
                    .parse()
                    .context("--chain-id must be u64")?;
            }
            "--stake-per-validator" => {
                stake_per_validator = argv
                    .next()
                    .context("--stake-per-validator requires a number")?
                    .parse()
                    .context("--stake-per-validator must be u64")?;
            }
            "--stakes" => {
                let raw = argv
                    .next()
                    .context("--stakes requires a comma-separated list of u64s")?;
                let parts: std::result::Result<Vec<u64>, _> =
                    raw.split(',').map(|s| s.trim().parse::<u64>()).collect();
                per_validator_stakes = Some(parts.context("--stakes parse")?);
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    if let Some(s) = &per_validator_stakes
        && s.len() != count
    {
        anyhow::bail!(
            "--stakes length ({}) must match --count ({})",
            s.len(),
            count
        );
    }

    Ok(Args {
        out_dir: out_dir.context("--out is required")?,
        count,
        chain_id,
        stake_per_validator,
        per_validator_stakes,
    })
}

fn print_help() {
    println!(
        "tenzro-genkeys — offline validator key generator\n\n\
         USAGE:\n  \
           tenzro-genkeys --out <DIR> [--count 10] [--chain-id 1338] \\\n  \
           [--stake-per-validator 1000] [--stakes 100000,0,0,0]\n\n\
         Produces per-validator subdirs under <DIR>/validator-{{i}}/ plus a top-level\n\
         genesis-prod.toml. Files have permission 0600.\n\n\
         --stakes accepts a comma-separated list of per-validator stakes (length\n\
         must match --count). Use this to model the three-tier model at genesis:\n  \
           --stakes 100000,0,0,0  → v0 Tier 3 (RPC provider), v1..v3 Tier 1\n\
         When --stakes is unset, all validators receive --stake-per-validator.\n"
    );
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::File::create(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    f.sync_all().ok();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_public(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

fn main() -> Result<()> {
    let args = parse_args()?;

    if args.out_dir.exists() {
        anyhow::bail!(
            "refusing to overwrite existing directory {}: pick a fresh --out path",
            args.out_dir.display()
        );
    }
    fs::create_dir_all(&args.out_dir)?;
    fs::set_permissions(&args.out_dir, fs::Permissions::from_mode(0o700))?;

    let mut genesis_validators: Vec<String> = Vec::with_capacity(args.count);
    let mut peer_id_summary: Vec<(usize, String)> = Vec::with_capacity(args.count);

    for i in 0..args.count {
        let vdir = args.out_dir.join(format!("validator-{i}"));
        fs::create_dir_all(&vdir)?;
        fs::set_permissions(&vdir, fs::Permissions::from_mode(0o700))?;

        // 1) Ed25519 consensus key — generate raw 32-byte seed (the loader
        //    in node.rs expects KeyPair::to_bytes() output, which for an
        //    Ed25519 keypair generated via KeyPair::generate is the raw
        //    seed). We mirror that by generating a fresh keypair and
        //    persisting its `to_bytes()`.
        let consensus_kp =
            KeyPair::generate(KeyType::Ed25519).context("generate Ed25519 keypair")?;
        let consensus_seed = consensus_kp.to_bytes();
        let consensus_pub = consensus_kp.public_key();
        write_secret(&vdir.join("consensus.seed"), &consensus_seed)?;
        write_public(
            &vdir.join("consensus.pub"),
            &hex::encode(consensus_pub.as_bytes()),
        )?;

        // 2) ML-DSA-65 post-quantum key — store the 32-byte seed; verifying
        //    key (1952 bytes) is rederived deterministically. Matches
        //    load_or_generate_validator_pq_key in node.rs.
        let mut pq_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut pq_seed);
        let pq_sk = MlDsaSigningKey::from_seed(&pq_seed)
            .context("derive ML-DSA-65 signing key from seed")?;
        let pq_vk_hex = hex::encode(pq_sk.verifying_key_bytes());
        write_secret(&vdir.join("pq.seed"), &pq_seed)?;
        write_public(&vdir.join("pq.pub"), &pq_vk_hex)?;

        // 3) libp2p Ed25519 keypair — protobuf-encoded so the existing
        //    load_or_generate_keypair() in tenzro-network/src/service.rs
        //    can decode it without changes.
        let libp2p_kp = Libp2pKeypair::generate_ed25519();
        let libp2p_pb = libp2p_kp.to_protobuf_encoding()?;
        let peer_id = libp2p_kp.public().to_peer_id().to_string();
        write_secret(&vdir.join("p2p.seed"), &libp2p_pb)?;
        write_public(&vdir.join("peer_id.txt"), &peer_id)?;

        // 4) BLS12-381 (min_pk) — for consensus QC signature aggregation.
        //    Genesis schema v3 requires `bls_public_key` per validator;
        //    the running fleet has been on v3 since the genesis schema
        //    rev shipped in the PQ wave.
        let bls_kp = BlsKeyPair::generate().context("generate BLS12-381 keypair")?;
        let bls_seed = bls_kp.secret_key().to_bytes();
        let bls_pub_hex = hex::encode(bls_kp.public_key().to_bytes());
        write_secret(&vdir.join("bls.seed"), &bls_seed)?;
        write_public(&vdir.join("bls.pub"), &bls_pub_hex)?;

        // Per-validator stake derives from --stakes (if set) or
        // --stake-per-validator (uniform). Used to model the
        // three-tier model at genesis: e.g. v0 = 100,000 (Tier 3 RPC
        // provider), v1..vN = 0 (Tier 1 resource-only). The tier is
        // derived from the stake by `ValidatorTier::from_stake` at
        // node startup against the registry config thresholds.
        let stake = match &args.per_validator_stakes {
            Some(stakes) => stakes[i],
            None => args.stake_per_validator,
        };
        let tier_label = if stake >= 100_000 {
            "Tier 3 (RPC provider)"
        } else if stake >= 10_000 {
            "Tier 2 (staked)"
        } else {
            "Tier 1 (resource-only)"
        };

        // Genesis entry — comments preserved across roundtrip via toml_edit
        // would be nicer, but a plain string template is sufficient and
        // mirrors the format of config/genesis-local.toml exactly.
        genesis_validators.push(format!(
            "[[validators]]\n# validator-{i} (peer_id={peer_id}) — {tier_label}\n\
             public_key = \"{}\"\npq_public_key = \"{}\"\nbls_public_key = \"{}\"\nstake = {}\n",
            hex::encode(consensus_pub.as_bytes()),
            pq_vk_hex,
            bls_pub_hex,
            stake,
        ));
        peer_id_summary.push((i, peer_id));
    }

    // Assemble the full genesis-prod.toml. Schema must match
    // crates/tenzro-node/src/config.rs (Genesis struct, version = 3 with
    // three pubkeys per validator: Ed25519 + ML-DSA-65 + BLS12-381).
    let mut genesis = String::new();
    genesis.push_str("# Auto-generated by tools/genkeys/.\n");
    genesis.push_str("# DO NOT EDIT BY HAND — regenerate with tenzro-genkeys.\n");
    genesis.push_str("version = 3\n");
    genesis.push_str(&format!("chain_id = {}\n", args.chain_id));
    genesis.push_str("timestamp = 0\n\n");
    for entry in &genesis_validators {
        genesis.push_str(entry);
        genesis.push('\n');
    }
    // Mirror the local genesis: two seed accounts + a faucet entry. Operators
    // can edit these post-generation; the validator set must remain untouched.
    genesis.push_str(
        "[[accounts]]\n\
         address = \"0000000000000000000000000000000000000000000000000000000000000010\"\n\
         balance = 1000000\n\n\
         [[accounts]]\n\
         address = \"0000000000000000000000000000000000000000000000000000000000000011\"\n\
         balance = 1000000\n\n\
         [faucet]\n\
         address = \"0000000000000000000000000000000000000000000000000000000000ffffff\"\n\
         amount_per_request = 100\n\
         cooldown_seconds = 86400\n\
         enabled = true\n",
    );

    fs::write(args.out_dir.join("genesis-prod.toml"), &genesis)?;

    // Peer-id summary — operator copies validator-0's into Terraform.
    let mut summary = String::new();
    summary.push_str("# Validator peer IDs (for Terraform bootstrap_peer_id + cookbook)\n");
    for (i, pid) in &peer_id_summary {
        summary.push_str(&format!("validator-{i}: {pid}\n"));
    }
    fs::write(args.out_dir.join("PEER_IDS.txt"), &summary)?;

    eprintln!(
        "Generated {} validator key sets at {}",
        args.count,
        args.out_dir.display()
    );
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Inspect {}/genesis-prod.toml", args.out_dir.display());
    eprintln!(
        "  2. Copy it: cp {0}/genesis-prod.toml config/genesis-prod.toml",
        args.out_dir.display()
    );
    eprintln!(
        "  3. Set Terraform var bootstrap_peer_id={}",
        peer_id_summary[0].1
    );
    eprintln!("  4. Upload secrets:");
    for i in 0..args.count {
        eprintln!(
            "       gcloud secrets versions add tenzro-validator-{i}-consensus \\\n         --data-file={0}/validator-{i}/consensus.seed --project=tenzro-operator-project",
            args.out_dir.display()
        );
        eprintln!(
            "       gcloud secrets versions add tenzro-validator-{i}-pq \\\n         --data-file={0}/validator-{i}/pq.seed --project=tenzro-operator-project",
            args.out_dir.display()
        );
        eprintln!(
            "       gcloud secrets versions add tenzro-validator-{i}-p2p \\\n         --data-file={0}/validator-{i}/p2p.seed --project=tenzro-operator-project",
            args.out_dir.display()
        );
        eprintln!(
            "       gcloud secrets versions add tenzro-validator-{i}-bls \\\n         --data-file={0}/validator-{i}/bls.seed --project=tenzro-operator-project",
            args.out_dir.display()
        );
    }
    eprintln!();
    eprintln!("After upload, securely wipe {} (the seeds must not", args.out_dir.display());
    eprintln!("remain on disk):  shred -uvz {}/validator-*/*.seed", args.out_dir.display());

    Ok(())
}
