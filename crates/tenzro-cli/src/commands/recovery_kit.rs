//! `tenzro recovery-kit`: what a holder keeps offline to get a passkey
//! account back.
//!
//! A kit is a directory made on the holder's own machine:
//!
//! - `kit-code.txt`: a new one-time recovery code. It is the only
//!   secret in the kit; whoever reads it can start a recovery of the account.
//! - `set-recovery-code.json`: the keystore change that sets the code's
//!   commitment, for the account's passkeys to approve and send with
//!   `tenzro passkey update`. The kit restores nothing until that change is
//!   on chain.
//! - `public-record.json`: the account, its chain, its owner, its linked
//!   passkeys, its recovery signers and threshold, as the chain held them
//!   when the kit was made. Nothing in it is secret.
//! - `README.txt`: what the kit is, how to use it and what it cannot do.
//! - `manifest.json`: the SHA-256 of every other file, signed by this
//!   machine's hardware key, so a later reader can tell the kit is as it was
//!   made.
//!
//! `verify` checks a kit against its manifest and, with a node, against the
//! chain. `claim` turns a kit and a new passkey into the two keystore
//! changes that recover the account: the claim, sent by another account,
//! and the reveal, sent once the claim has aged.
//!
//! Nobody else holds a copy of the code. A kit that is lost restores
//! nothing, and a kit that is read by someone else is theirs to use.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_types::keystore::{
    KeystoreCredential, KeystoreOp, KeystoreRecord, KeystoreUpdate, RecoveryCodeCommitment,
    recovery_code_claim, recovery_code_commitment,
};

use crate::output;
use crate::rpc::RpcClient;

const CODE_FILE: &str = "kit-code.txt";
const SET_FILE: &str = "set-recovery-code.json";
const RECORD_FILE: &str = "public-record.json";
const README_FILE: &str = "README.txt";
const MANIFEST_FILE: &str = "manifest.json";
/// The files a manifest covers.
const COVERED: [&str; 4] = [CODE_FILE, SET_FILE, RECORD_FILE, README_FILE];

const README: &str = "\
TENZRO RECOVERY KIT

This directory can bring a Tenzro passkey account back after its devices are
lost. Keep it offline, apart from those devices.

AT YOUR OWN RISK. Nobody else holds a copy of anything here: not the network,
not a node operator, not a wallet provider. If this kit is lost it restores
nothing. Anyone who reads kit-code.txt can start a recovery of the
account, so treat that file like the account itself.

What is here
  kit-code.txt       the one-time recovery code (secret)
  set-recovery-code.json  the keystore change that arms the code
  public-record.json      the account and its keystore when the kit was made
  manifest.json           hashes of these files, signed by the machine that
                          made the kit

Before the kit can restore anything
  The account's passkeys approve set-recovery-code.json and it is sent with
      tenzro passkey update set-recovery-code.json
  Check afterwards with
      tenzro recovery-kit verify <this directory> --rpc <node>

To recover
  1. Create a passkey on a new device.
  2. tenzro recovery-kit claim <this directory> --credential <passkey.json>
     writes claim.json and reveal.json.
  3. Send claim.json from any other account, wait for the claim to age,
     add the new passkey's proof of possession to reveal.json and send it.
  4. After the recovery's wait, complete it (finish_recovery).
  The code works once. Set a new one, and make a new kit, afterwards.

What this kit cannot do
  It holds no key and signs nothing. It does not recover a machine identity,
  an agent or a delegated device key. If the account's recovery code is
  changed or turned off after this kit was made, this kit is void.
";

#[derive(Debug, Subcommand)]
pub enum RecoveryKitCommand {
    /// Make a kit for an account: a new recovery code and the change that
    /// arms it
    Create(CreateCmd),
    /// Check a kit against its manifest and, with --rpc, against the chain
    Verify(VerifyCmd),
    /// From a kit and a new passkey, write the two changes that recover the
    /// account
    Claim(ClaimCmd),
}

impl RecoveryKitCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Create(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Claim(cmd) => cmd.execute(),
        }
    }
}

/// The account and its keystore as the chain held them when a kit was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRecord {
    /// The chain the account's changes are signed for.
    pub chain_id: u64,
    /// The account, hex.
    pub account: String,
    /// The keystore, as `tenzro_getKeystore` returned it.
    pub keystore: KeystoreRecord,
    /// Hex commitment of the keystore the change in the kit was made against.
    pub keystore_commitment: String,
    /// Hex commitment of the kit's recovery code.
    pub recovery_code_commitment: String,
}

/// What a manifest's signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBody {
    /// The version of the tool that made the kit.
    pub made_by: String,
    /// When, in milliseconds since the Unix epoch.
    pub created_at_ms: i64,
    /// Hex SHA-256 of each file in the kit, by name.
    pub files: BTreeMap<String, String>,
}

/// A kit's manifest and the signature of the machine that made it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub body: ManifestBody,
    /// The signing hardware key, uncompressed SEC1 P-256, hex.
    pub public_key: String,
    /// ECDSA P-256 over SHA-256 of the body's JSON, `r || s`, hex.
    pub signature: String,
}

/// A hardware signature over a message: the uncompressed SEC1 public key and
/// `r || s`.
pub type Signed = ([u8; 65], [u8; 64]);

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn account_bytes(account: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(account.trim_start_matches("0x")).context("the account is not hex")?;
    if bytes.len() != 20 {
        bail!("a passkey account is 20 bytes, not {}", bytes.len());
    }
    Ok(bytes)
}

/// The files of a kit for `keystore` on chain `chain_id` with recovery code
/// `code`, by name.
pub fn kit_files(
    chain_id: u64,
    keystore: &KeystoreRecord,
    code: &[u8; 32],
) -> Result<BTreeMap<&'static str, Vec<u8>>> {
    let commitment = recovery_code_commitment(chain_id, &keystore.account, code);
    let set = KeystoreUpdate {
        chain_id,
        account: keystore.account.clone(),
        anchor: None,
        previous_commitment: keystore.commitment().to_vec(),
        op: KeystoreOp::SetRecoveryCode {
            commitment: Some(RecoveryCodeCommitment(commitment.to_vec())),
        },
        approvals: Vec::new(),
        possession: None,
    };
    let record = PublicRecord {
        chain_id,
        account: hex::encode(&keystore.account),
        keystore: keystore.clone(),
        keystore_commitment: hex::encode(keystore.commitment()),
        recovery_code_commitment: hex::encode(commitment),
    };
    let mut files = BTreeMap::new();
    files.insert(CODE_FILE, format!("{}\n", hex::encode(code)).into_bytes());
    files.insert(SET_FILE, serde_json::to_vec_pretty(&set)?);
    files.insert(RECORD_FILE, serde_json::to_vec_pretty(&record)?);
    files.insert(README_FILE, README.as_bytes().to_vec());
    Ok(files)
}

/// Write a kit into `dir`, which must be empty or absent, signing its
/// manifest with `sign`.
pub fn write_kit(
    dir: &Path,
    files: &BTreeMap<&'static str, Vec<u8>>,
    created_at_ms: i64,
    sign: impl FnOnce(&[u8]) -> Result<Signed>,
) -> Result<()> {
    if dir.exists()
        && std::fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .next()
            .is_some()
    {
        bail!(
            "{} is not empty; a kit is written into a directory of its own",
            dir.display()
        );
    }
    let body = ManifestBody {
        made_by: format!("tenzro {}", env!("CARGO_PKG_VERSION")),
        created_at_ms,
        files: files
            .iter()
            .map(|(name, bytes)| (name.to_string(), sha256_hex(bytes)))
            .collect(),
    };
    let (public_key, signature) = sign(&serde_json::to_vec(&body)?)?;
    let manifest = Manifest {
        body,
        public_key: hex::encode(public_key),
        signature: hex::encode(signature),
    };
    for (name, bytes) in files {
        crate::private_file::write_private(&dir.join(name), bytes)
            .with_context(|| format!("writing {name}"))?;
    }
    crate::private_file::write_private(
        &dir.join(MANIFEST_FILE),
        &serde_json::to_vec_pretty(&manifest)?,
    )
    .context("writing the manifest")?;
    Ok(())
}

/// A kit read back from disk and checked against its manifest.
#[derive(Debug, Clone)]
pub struct Kit {
    pub code: [u8; 32],
    pub record: PublicRecord,
    pub manifest: Manifest,
}

/// Read the kit in `dir`: every file is the one its manifest names, the
/// manifest's signature verifies under the key it carries, and the code is
/// the one the public record commits to.
pub fn read_kit(dir: &Path) -> Result<Kit> {
    use p256::ecdsa::signature::Verifier as _;
    let read = |name: &str| {
        std::fs::read(dir.join(name)).with_context(|| format!("the kit has no readable {name}"))
    };
    let manifest: Manifest =
        serde_json::from_slice(&read(MANIFEST_FILE)?).context("the manifest does not parse")?;
    let key = hex::decode(&manifest.public_key).context("the manifest's key is not hex")?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
        .map_err(|_| anyhow!("the manifest's key is not a P-256 key"))?;
    let signature = hex::decode(&manifest.signature)
        .ok()
        .and_then(|s| p256::ecdsa::Signature::from_slice(&s).ok())
        .ok_or_else(|| anyhow!("the manifest's signature is malformed"))?;
    key.verify(&serde_json::to_vec(&manifest.body)?, &signature)
        .map_err(|_| anyhow!("the manifest's signature does not verify: the kit was changed"))?;
    for name in COVERED {
        let listed = manifest
            .body
            .files
            .get(name)
            .ok_or_else(|| anyhow!("the manifest does not list {name}"))?;
        if *listed != sha256_hex(&read(name)?) {
            bail!("{name} is not the file the manifest was signed over");
        }
    }
    let code: [u8; 32] = hex::decode(String::from_utf8_lossy(&read(CODE_FILE)?).trim())
        .ok()
        .and_then(|c| c.try_into().ok())
        .ok_or_else(|| anyhow!("{CODE_FILE} does not hold a 32-byte code"))?;
    let record: PublicRecord =
        serde_json::from_slice(&read(RECORD_FILE)?).context("the public record does not parse")?;
    let account = account_bytes(&record.account)?;
    if hex::encode(recovery_code_commitment(record.chain_id, &account, &code))
        != record.recovery_code_commitment
    {
        bail!("the code is not the one the public record commits to");
    }
    Ok(Kit {
        code,
        record,
        manifest,
    })
}

/// The two changes that recover the kit's account to `credential`: the
/// claim, which another account sends, and the reveal, which carries the
/// code and is sent once the claim has aged. `previous_commitment` is the
/// commitment of the keystore on chain now. The reveal still needs the new
/// passkey's proof of possession.
pub fn recovery_updates(
    kit: &Kit,
    credential: &KeystoreCredential,
    previous_commitment: &[u8],
) -> Result<(KeystoreUpdate, KeystoreUpdate)> {
    let account = account_bytes(&kit.record.account)?;
    let update = |op| KeystoreUpdate {
        chain_id: kit.record.chain_id,
        account: account.clone(),
        anchor: None,
        previous_commitment: previous_commitment.to_vec(),
        op,
        approvals: Vec::new(),
        possession: None,
    };
    let claim = update(KeystoreOp::ClaimRecoveryCode {
        claim: recovery_code_claim(kit.record.chain_id, &account, &kit.code, credential).to_vec(),
    });
    let reveal = update(KeystoreOp::RecoverWithCode {
        code: kit.code.to_vec(),
        credential: credential.clone(),
    });
    Ok((claim, reveal))
}

async fn chain_id(rpc: &RpcClient) -> Result<u64> {
    let chain: String = rpc.call("eth_chainId", json!([])).await?;
    u64::from_str_radix(chain.trim_start_matches("0x"), 16).map_err(|e| anyhow!("eth_chainId: {e}"))
}

async fn keystore_on_chain(rpc: &RpcClient, account: &str) -> Result<KeystoreRecord> {
    let answer: Value = rpc
        .call("tenzro_getKeystore", json!({ "account": account }))
        .await?;
    if answer["on_chain"] != Value::Bool(true) {
        bail!(
            "account {account} has no keystore on chain yet; its passkey makes a first change \
             (for example linking a second device) before a kit can be made for it"
        );
    }
    serde_json::from_value(answer["keystore"].clone()).context("the node's keystore record")
}

#[derive(Debug, Args)]
pub struct CreateCmd {
    /// The passkey account, hex
    pub account: String,
    /// The directory to write the kit into; it must be empty or absent
    #[arg(long)]
    pub out: PathBuf,
    /// Key namespace of this machine's hardware key that signs the manifest
    #[arg(long, default_value = "default")]
    pub key_namespace: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl CreateCmd {
    async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let account = hex::encode(account_bytes(&self.account)?);
        let keystore = keystore_on_chain(&rpc, &account).await?;
        let mut code = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut code);
        let files = kit_files(chain_id(&rpc).await?, &keystore, &code)?;
        let namespace = self.key_namespace.clone();
        write_kit(
            &self.out,
            &files,
            chrono::Utc::now().timestamp_millis(),
            |message| {
                let (public_key, signature, _) = crate::keystore::sign_p256(&namespace, message)?;
                Ok((public_key, signature))
            },
        )?;
        output::print_success(&format!("Recovery kit written to {}", self.out.display()));
        output::print_warning(
            "AT YOUR OWN RISK: nobody else holds a copy of this kit. If it is lost it restores \
             nothing, and anyone who reads kit-code.txt can start a recovery of the account.",
        );
        output::print_warning(&format!(
            "The kit restores nothing yet. Have the account's passkeys approve {} and send it \
             with: tenzro passkey update {}",
            SET_FILE,
            self.out.join(SET_FILE).display()
        ));
        if keystore.recovery_code.is_some() {
            output::print_warning(
                "The account already has a recovery code; sending the change replaces it, and \
                 any earlier kit stops working.",
            );
        }
        if keystore.credentials.len() < 2 && keystore.recovery_signers.is_empty() {
            output::print_warning(
                "This account has one passkey and no recovery signers: until the change above \
                 is on chain, losing that device loses the account.",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct VerifyCmd {
    /// The kit directory
    pub dir: PathBuf,
    /// A node to compare the kit with the chain; without it only the kit's
    /// own files are checked
    #[arg(long)]
    pub rpc: Option<String>,
}

/// Whether the keystore on chain still holds the kit's code.
fn armed(kit: &Kit, on_chain: &KeystoreRecord) -> bool {
    on_chain
        .recovery_code
        .as_ref()
        .is_some_and(|c| hex::encode(&c.commitment) == kit.record.recovery_code_commitment)
}

impl VerifyCmd {
    async fn execute(&self) -> Result<()> {
        let kit = read_kit(&self.dir)?;
        output::print_success("The kit's files are the ones its manifest was signed over");
        output::print_field("Account", &kit.record.account);
        output::print_field("Chain", &kit.record.chain_id.to_string());
        output::print_field("Made by", &kit.manifest.body.made_by);
        output::print_field("Signed by key", &kit.manifest.public_key);
        let Some(url) = &self.rpc else {
            output::print_warning(
                "Not compared with the chain (no --rpc): whether the account still holds this \
                 kit's code is unknown.",
            );
            return Ok(());
        };
        let rpc = RpcClient::new(url);
        let node_chain = chain_id(&rpc).await?;
        if node_chain != kit.record.chain_id {
            bail!(
                "the kit is for chain {}, but the node runs chain {node_chain}",
                kit.record.chain_id
            );
        }
        let on_chain = keystore_on_chain(&rpc, &kit.record.account).await?;
        if armed(&kit, &on_chain) {
            output::print_success(
                "The account holds this kit's recovery code: the kit can recover it",
            );
            Ok(())
        } else {
            bail!(
                "the account does not hold this kit's recovery code (never set, replaced, or \
                 already used): this kit cannot recover it"
            )
        }
    }
}

#[derive(Debug, Args)]
pub struct ClaimCmd {
    /// The kit directory
    pub dir: PathBuf,
    /// The new passkey as JSON (rp_id, credential_id, public_key, aaguid,
    /// backup_eligible, backup_state, label), or a file holding it
    #[arg(long)]
    pub credential: String,
    /// Hex commitment of the account's keystore on chain now
    /// (`tenzro passkey keystore <account>`): the changes are made against
    /// it, and setting the kit's code moved it from the one the kit recorded
    #[arg(long)]
    pub previous_commitment: String,
    /// Where to write claim.json and reveal.json; the current directory
    /// when omitted
    #[arg(long, default_value = ".")]
    pub out: PathBuf,
}

impl ClaimCmd {
    fn execute(&self) -> Result<()> {
        let kit = read_kit(&self.dir)?;
        let raw =
            std::fs::read_to_string(&self.credential).unwrap_or_else(|_| self.credential.clone());
        let credential: KeystoreCredential =
            serde_json::from_str(raw.trim()).context("--credential is not a passkey record")?;
        let previous = hex::decode(self.previous_commitment.trim_start_matches("0x"))
            .context("--previous-commitment is not hex")?;
        let (claim, reveal) = recovery_updates(&kit, &credential, &previous)?;
        for (name, update) in [("claim.json", &claim), ("reveal.json", &reveal)] {
            crate::private_file::write_private(
                &self.out.join(name),
                &serde_json::to_vec_pretty(update)?,
            )
            .with_context(|| format!("writing {name}"))?;
        }
        output::print_success("Wrote claim.json and reveal.json");
        output::print_warning(
            "Send claim.json from an account other than the one being recovered, wait for the \
             claim to age, add the new passkey's proof of possession to reveal.json and send it. \
             reveal.json holds the recovery code: keep it as closely as the kit.",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use tenzro_types::keystore::{KeystoreAnchor, RecoveryCode};

    fn machine_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn sign(message: &[u8]) -> Result<Signed> {
        let key = machine_key();
        let signature: p256::ecdsa::Signature = key.sign(message);
        let public: [u8; 65] = key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        Ok((public, signature.to_bytes().into()))
    }

    fn keystore() -> KeystoreRecord {
        let mut public_key = vec![4u8; 64];
        public_key[0] = 9;
        KeystoreRecord::genesis(&KeystoreAnchor {
            rp_id: "tenzro.com".into(),
            credential_id: vec![1; 16],
            public_key,
            aaguid: vec![0; 16],
            backup_eligible: false,
            backup_state: false,
            salt: 0,
        })
    }

    fn new_passkey() -> KeystoreCredential {
        KeystoreCredential {
            rp_id: "tenzro.com".into(),
            credential_id: vec![2; 16],
            public_key: vec![5; 64],
            aaguid: vec![0; 16],
            backup_eligible: false,
            backup_state: false,
            counts_as_root_from_ms: 0,
            label: "new phone".into(),
            added_at_ms: 0,
        }
    }

    /// A kit made in one directory is read back in full: its code, the
    /// change that arms it and the two changes that recover the account are
    /// the ones the chain's own functions give for that code.
    #[test]
    fn a_kit_rebuilds_the_recovery_of_its_account_from_a_clean_directory() {
        let dir = tempfile::tempdir().unwrap();
        let kit_dir = dir.path().join("kit");
        let ks = keystore();
        let code = [0x5a; 32];
        write_kit(&kit_dir, &kit_files(1337, &ks, &code).unwrap(), 1, sign).unwrap();

        let kit = read_kit(&kit_dir).unwrap();
        assert_eq!(kit.code, code);
        assert_eq!(kit.record.keystore, ks);
        let commitment = recovery_code_commitment(1337, &ks.account, &code);

        // The arming change sets exactly the kit's commitment, against the
        // keystore the kit recorded, and is a change the chain would read.
        let set: KeystoreUpdate =
            serde_json::from_slice(&std::fs::read(kit_dir.join(SET_FILE)).unwrap()).unwrap();
        assert_eq!(set.previous_commitment, ks.commitment().to_vec());
        assert_eq!(
            set.op,
            KeystoreOp::SetRecoveryCode {
                commitment: Some(RecoveryCodeCommitment(commitment.to_vec()))
            }
        );

        // Once armed, the keystore on chain holds the kit's code.
        let mut armed_ks = ks.clone();
        armed_ks.version += 1;
        armed_ks.recovery_code = Some(RecoveryCode {
            commitment: commitment.to_vec(),
        });
        assert!(armed(&kit, &armed_ks));
        assert!(!armed(&kit, &ks), "not before the change is on chain");

        let passkey = new_passkey();
        let (claim, reveal) = recovery_updates(&kit, &passkey, &armed_ks.commitment()).unwrap();
        assert_eq!(
            claim.op,
            KeystoreOp::ClaimRecoveryCode {
                claim: recovery_code_claim(1337, &ks.account, &code, &passkey).to_vec()
            }
        );
        assert_eq!(
            reveal.op,
            KeystoreOp::RecoverWithCode {
                code: code.to_vec(),
                credential: passkey,
            }
        );
        for update in [&claim, &reveal] {
            assert_eq!(update.chain_id, 1337);
            assert_eq!(update.account, ks.account);
            assert_eq!(update.previous_commitment, armed_ks.commitment().to_vec());
        }
    }

    #[test]
    fn a_changed_kit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let make = |name: &str| {
            let kit_dir = dir.path().join(name);
            write_kit(
                &kit_dir,
                &kit_files(1337, &keystore(), &[0x5a; 32]).unwrap(),
                1,
                sign,
            )
            .unwrap();
            kit_dir
        };

        // Another code in place of the kit's.
        let swapped = make("swapped");
        std::fs::write(swapped.join(CODE_FILE), hex::encode([0x5b; 32])).unwrap();
        assert!(read_kit(&swapped).is_err());

        // A public record naming another account, with the manifest's hash
        // updated to match but no new signature.
        let forged = make("forged");
        let mut record: PublicRecord =
            serde_json::from_slice(&std::fs::read(forged.join(RECORD_FILE)).unwrap()).unwrap();
        record.account = hex::encode([0xee; 20]);
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        std::fs::write(forged.join(RECORD_FILE), &bytes).unwrap();
        let mut manifest: Manifest =
            serde_json::from_slice(&std::fs::read(forged.join(MANIFEST_FILE)).unwrap()).unwrap();
        manifest
            .body
            .files
            .insert(RECORD_FILE.to_string(), sha256_hex(&bytes));
        std::fs::write(
            forged.join(MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(read_kit(&forged).is_err());

        // A file removed.
        let missing = make("missing");
        std::fs::remove_file(missing.join(README_FILE)).unwrap();
        assert!(read_kit(&missing).is_err());

        assert!(read_kit(&make("intact")).is_ok());
    }

    #[test]
    fn a_kit_is_not_written_over_other_files_and_its_code_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"mine").unwrap();
        let files = kit_files(1337, &keystore(), &[0x5a; 32]).unwrap();
        assert!(write_kit(dir.path(), &files, 1, sign).is_err());
        assert!(!dir.path().join(CODE_FILE).exists());

        let kit_dir = dir.path().join("kit");
        write_kit(&kit_dir, &files, 1, sign).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(kit_dir.join(CODE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let readme = std::fs::read_to_string(kit_dir.join(README_FILE)).unwrap();
        assert!(readme.contains("AT YOUR OWN RISK"));
    }
}
