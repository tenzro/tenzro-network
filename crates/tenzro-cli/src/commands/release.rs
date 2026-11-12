//! `tenzro release notice sign|verify|publish`: the publisher's side of
//! release notices (`docs/UPDATE-NOTICE.md`).
//!
//! The release key never lives in a file. The signing happens in the release
//! signing run (`RELEASE-SIGNING-PLAN`): `sign --prepare` writes the exact bytes to sign,
//! the TPM signs them like it signs `SHA256SUMS`, and `sign --finish` attaches
//! that signature after checking it against the release public key. Nothing
//! here reaches the network.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use tenzro_update_notice::notice::{self, Notice, Policy, Version};

use crate::output;

/// Release process commands
#[derive(Debug, Subcommand)]
pub enum ReleaseCommand {
    /// Release notices: the signed message that tells nodes a release exists
    #[command(subcommand)]
    Notice(NoticeCommand),
}

/// `tenzro release notice`
#[derive(Debug, Subcommand)]
pub enum NoticeCommand {
    /// Prepare and finish the release signing run
    Sign(SignCmd),
    /// Check a signed notice the way a node does
    Verify(VerifyCmd),
    /// Put a verified notice into a release directory as notice.json
    Publish(PublishCmd),
}

impl ReleaseCommand {
    pub fn execute(&self) -> Result<()> {
        match self {
            Self::Notice(NoticeCommand::Sign(c)) => c.execute(),
            Self::Notice(NoticeCommand::Verify(c)) => c.execute(),
            Self::Notice(NoticeCommand::Publish(c)) => c.execute(),
        }
    }
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn read_public_key(path: &Path) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(notice::public_key_from_pem(&text)?)
}

/// `tenzro release notice sign`
#[derive(Debug, Parser)]
pub struct SignCmd {
    /// The unsigned notice, JSON. `issued_ms` and `expires_ms` of 0 are filled (now, and 30 days on).
    notice: Option<PathBuf>,
    /// Write the signed notice here.
    #[arg(long)]
    out: Option<PathBuf>,
    /// A PKCS#8 PEM key file the tests sign with. It is not a command-line argument.
    #[cfg(test)]
    #[arg(skip)]
    test_key: Option<PathBuf>,
    /// Release signing run, step 1: write `payload.json` and `notice.msg` (the bytes the release key signs) into this directory.
    #[arg(long, conflicts_with = "finish")]
    prepare: Option<PathBuf>,
    /// Release signing run, step 2: the directory `--prepare` wrote; attach `--signature`.
    #[arg(long, requires_all = ["signature", "public_key", "out"])]
    finish: Option<PathBuf>,
    /// The signature the release signing run made over `notice.msg`: a file holding hex or base64 of an ECDSA P-256 signature (raw or DER).
    #[arg(long)]
    signature: Option<PathBuf>,
    /// The release public key, PEM (`tenzro-release.pub`).
    #[arg(long)]
    public_key: Option<PathBuf>,
}

impl SignCmd {
    fn execute(&self) -> Result<()> {
        if let Some(dir) = &self.finish {
            let payload = std::fs::read(dir.join("payload.json"))
                .with_context(|| format!("read {}/payload.json", dir.display()))?;
            let sig = std::fs::read_to_string(self.signature.as_ref().expect("clap requires it"))?;
            let key = read_public_key(self.public_key.as_ref().expect("clap requires it"))?;
            let signed = notice::assemble(&payload, &key, &sig)?;
            let out = self.out.as_ref().expect("clap requires it");
            std::fs::write(out, &signed).with_context(|| format!("write {}", out.display()))?;
            output::print_success(&format!(
                "Signed notice written to {}. Check it with: tenzro release notice verify {}",
                out.display(),
                out.display()
            ));
            return Ok(());
        }
        let Some(path) = &self.notice else {
            bail!("give the notice file to sign");
        };
        let mut n: Notice = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )
        .with_context(|| format!("{} is not a notice document", path.display()))?;
        if n.issued_ms == 0 {
            n.issued_ms = now_ms();
        }
        if n.expires_ms == 0 {
            n.expires_ms = n.issued_ms + 30 * 24 * 3600 * 1000;
        }
        n.check_shape()?;
        let payload = serde_json::to_vec(&n)?;
        if let Some(dir) = &self.prepare {
            std::fs::create_dir_all(dir)?;
            std::fs::write(dir.join("payload.json"), &payload)?;
            let msg = notice::signing_message(&payload);
            std::fs::write(dir.join("notice.msg"), &msg)?;
            output::print_success(&format!(
                "Wrote {0}/payload.json and {0}/notice.msg",
                dir.display()
            ));
            output::print_field("SHA-256 of notice.msg", &hex::encode(Sha256::digest(&msg)));
            println!(
                "Read the release, version, severity and every archive digest in payload.json against the build record, then sign notice.msg with the release key in the release signing run, and finish with --finish."
            );
            return Ok(());
        }
        #[cfg(test)]
        if let Some(key_path) = &self.test_key {
            return self.sign_with_key_file(key_path, path, &payload);
        }
        bail!("give --prepare for the release signing run, or --finish to attach its signature");
    }

    /// Signs with a PEM key read from a file. Compiled for tests only: a release build has no
    /// code path that reads a private key from a file.
    #[cfg(test)]
    fn sign_with_key_file(&self, key_path: &Path, path: &Path, payload: &[u8]) -> Result<()> {
        let key = notice::LocalKey::from_pem(
            &std::fs::read_to_string(key_path)
                .with_context(|| format!("read {}", key_path.display()))?,
        )?;
        if key.is_release_key() {
            bail!(
                "that is the release key: it signs only in the release signing run (use --prepare and --finish)"
            );
        }
        let signed = key.sign(payload);
        let out = self
            .out
            .clone()
            .unwrap_or_else(|| path.with_extension("signed.json"));
        std::fs::write(&out, &signed).with_context(|| format!("write {}", out.display()))?;
        output::print_success(&format!("Signed; written to {}.", out.display()));
        Ok(())
    }
}

/// `tenzro release notice verify`
#[derive(Debug, Parser)]
pub struct VerifyCmd {
    /// The signed notice.
    signed: PathBuf,
    /// The public key to verify against, PEM. Default: the embedded release key.
    #[arg(long)]
    public_key: Option<PathBuf>,
    /// The channel the notice must be for.
    #[arg(long, default_value = "stable")]
    channel: String,
    /// The release to treat as running, for the downgrade check.
    #[arg(long, default_value = "0.0.0")]
    running: String,
    /// The clock to check expiry against, Unix milliseconds; default now.
    #[arg(long)]
    now_ms: Option<u64>,
}

fn verify_file(
    path: &Path,
    key: Option<&Path>,
    channel: &str,
    running: &str,
    now: u64,
) -> Result<Notice> {
    let keys = match key {
        Some(p) => vec![read_public_key(p)?],
        None => vec![notice::release_key_sec1()],
    };
    let running: Version = running.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(notice::verify(
        &bytes,
        &Policy {
            keys: &keys,
            channel,
            running,
            now_ms: now,
        },
    )?)
}

impl VerifyCmd {
    fn execute(&self) -> Result<()> {
        let n = verify_file(
            &self.signed,
            self.public_key.as_deref(),
            &self.channel,
            &self.running,
            self.now_ms.unwrap_or_else(now_ms),
        )?;
        output::print_success(&format!(
            "Valid notice: tenzro {} on {}, severity {}",
            n.version,
            n.channel,
            n.severity.as_str()
        ));
        output::print_field(
            "Platforms",
            &n.platforms
                .iter()
                .map(|p| p.platform.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
        output::print_field("Expires (unix ms)", &n.expires_ms.to_string());
        Ok(())
    }
}

/// `tenzro release notice publish`
#[derive(Debug, Parser)]
pub struct PublishCmd {
    /// The signed notice.
    signed: PathBuf,
    /// The release directory (the channel's files); the notice becomes `notice.json` in it.
    #[arg(long)]
    dir: PathBuf,
    /// The public key to verify against, PEM. Default: the embedded release key.
    #[arg(long)]
    public_key: Option<PathBuf>,
    /// The channel the notice must be for.
    #[arg(long, default_value = "stable")]
    channel: String,
}

impl PublishCmd {
    fn execute(&self) -> Result<()> {
        let n = verify_file(
            &self.signed,
            self.public_key.as_deref(),
            &self.channel,
            "0.0.0",
            now_ms(),
        )?;
        let target = self.dir.join("notice.json");
        // A notice older than the one already there would roll nodes' view back.
        if target.is_file()
            && let Ok(held) = verify_file(
                &target,
                self.public_key.as_deref(),
                &self.channel,
                "0.0.0",
                now_ms(),
            )
            && n.order() < held.order()
        {
            bail!(
                "{} already holds tenzro {} (signed later); not replacing it with {}",
                target.display(),
                held.version,
                n.version
            );
        }
        let bytes = std::fs::read(&self.signed)?;
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join("notice.json.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &target)?;
        output::print_success(&format!(
            "Published tenzro {} to {}",
            n.version,
            target.display()
        ));
        println!(
            "The release process uploads it with the channel's other files; nodes then fetch it and pass it on."
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_update_notice::Severity;
    use tenzro_update_notice::notice::LocalKey;
    use tenzro_update_notice::notice::fixture::{key, notice as sample};

    fn write_pub(dir: &Path, k: &LocalKey) -> PathBuf {
        use p256::pkcs8::EncodePublicKey;
        let pk = p256::PublicKey::from_sec1_bytes(&k.public_sec1()).unwrap();
        let p = dir.join("test.pub");
        std::fs::write(&p, pk.to_public_key_pem(Default::default()).unwrap()).unwrap();
        p
    }

    fn template(dir: &Path) -> PathBuf {
        let now = now_ms();
        let mut n = sample("9.9.9", Severity::RequiredByEpoch { epoch: 12 });
        n.released_ms = now - 1000;
        n.issued_ms = 0;
        n.expires_ms = 0;
        let p = dir.join("notice.json");
        std::fs::write(&p, serde_json::to_vec_pretty(&n).unwrap()).unwrap();
        p
    }

    fn sign_args(dir: &Path) -> SignCmd {
        SignCmd {
            notice: Some(template(dir)),
            out: Some(dir.join("signed.json")),
            test_key: None,
            prepare: None,
            finish: None,
            signature: None,
            public_key: None,
        }
    }

    #[test]
    fn sign_verify_publish_with_a_test_key() {
        let d = tempfile::tempdir().unwrap();
        let k = key(3);
        std::fs::write(d.path().join("k.pem"), k.to_pem()).unwrap();
        let public = write_pub(d.path(), &k);
        SignCmd {
            test_key: Some(d.path().join("k.pem")),
            ..sign_args(d.path())
        }
        .execute()
        .unwrap();
        let signed = d.path().join("signed.json");
        VerifyCmd {
            signed: signed.clone(),
            public_key: Some(public.clone()),
            channel: "stable".into(),
            running: "0.2.1".into(),
            now_ms: None,
        }
        .execute()
        .unwrap();
        // The embedded release key does not vouch for a test key's notice.
        assert!(verify_file(&signed, None, "stable", "0.2.1", now_ms()).is_err());
        let dist = d.path().join("dist");
        PublishCmd {
            signed: signed.clone(),
            dir: dist.clone(),
            public_key: Some(public.clone()),
            channel: "stable".into(),
        }
        .execute()
        .unwrap();
        assert_eq!(
            std::fs::read(dist.join("notice.json")).unwrap(),
            std::fs::read(&signed).unwrap()
        );
    }

    #[test]
    fn a_tampered_notice_is_not_published_and_an_older_one_does_not_replace_a_newer() {
        let d = tempfile::tempdir().unwrap();
        let k = key(3);
        std::fs::write(d.path().join("k.pem"), k.to_pem()).unwrap();
        let public = write_pub(d.path(), &k);
        SignCmd {
            test_key: Some(d.path().join("k.pem")),
            ..sign_args(d.path())
        }
        .execute()
        .unwrap();
        let signed = d.path().join("signed.json");
        let mut text = std::fs::read_to_string(&signed).unwrap();
        text = text.replacen("\"payload\": \"", "\"payload\": \"A", 1);
        let tampered = d.path().join("tampered.json");
        std::fs::write(&tampered, text).unwrap();
        let dist = d.path().join("dist");
        assert!(
            PublishCmd {
                signed: tampered,
                dir: dist.clone(),
                public_key: Some(public.clone()),
                channel: "stable".into()
            }
            .execute()
            .is_err()
        );
        assert!(!dist.join("notice.json").exists());
        // Publish 9.9.9, then try 9.9.8.
        PublishCmd {
            signed,
            dir: dist.clone(),
            public_key: Some(public.clone()),
            channel: "stable".into(),
        }
        .execute()
        .unwrap();
        let mut older = sample("9.9.8", Severity::Normal);
        older.issued_ms = now_ms() - 10;
        older.expires_ms = now_ms() + 86_400_000;
        std::fs::write(
            d.path().join("older.json"),
            serde_json::to_vec(&older).unwrap(),
        )
        .unwrap();
        SignCmd {
            notice: Some(d.path().join("older.json")),
            out: Some(d.path().join("older.signed.json")),
            test_key: Some(d.path().join("k.pem")),
            ..sign_args(d.path())
        }
        .execute()
        .unwrap();
        let err = PublishCmd {
            signed: d.path().join("older.signed.json"),
            dir: dist,
            public_key: Some(public),
            channel: "stable".into(),
        }
        .execute()
        .unwrap_err();
        assert!(err.to_string().contains("not replacing"), "{err}");
    }

    #[test]
    fn the_release_signing_run_prepares_the_bytes_and_a_signature_made_elsewhere_finishes_them() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let d = tempfile::tempdir().unwrap();
        let k = key(4);
        let public = write_pub(d.path(), &k);
        let work = d.path().join("work");
        SignCmd {
            prepare: Some(work.clone()),
            ..sign_args(d.path())
        }
        .execute()
        .unwrap();
        // The release signing run signs notice.msg; here a test key stands in for the TPM.
        let msg = std::fs::read(work.join("notice.msg")).unwrap();
        let pem = k.to_pem();
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(&pem).unwrap();
        let digest: [u8; 32] = Sha256::digest(&msg).into();
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
        use base64::Engine as _;
        std::fs::write(
            d.path().join("sig.b64"),
            base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()),
        )
        .unwrap();
        SignCmd {
            notice: None,
            finish: Some(work),
            signature: Some(d.path().join("sig.b64")),
            public_key: Some(public.clone()),
            ..sign_args(d.path())
        }
        .execute()
        .unwrap();
        verify_file(
            &d.path().join("signed.json"),
            Some(&public),
            "stable",
            "0.2.1",
            now_ms(),
        )
        .unwrap();
        // A signature from another key is refused at finish time.
        let other = write_pub(&d.path().join("."), &key(5));
        let again = SignCmd {
            notice: None,
            finish: Some(d.path().join("work")),
            signature: Some(d.path().join("sig.b64")),
            public_key: Some(other),
            ..sign_args(d.path())
        };
        assert!(again.execute().is_err());
    }
}
