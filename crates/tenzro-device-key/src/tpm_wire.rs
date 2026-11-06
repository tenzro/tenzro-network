//! TPM 2.0 command encoding and response parsing, independent of transport.
//!
//! Every function here is a pure byte transform: it builds a command buffer or
//! parses a response buffer. Nothing talks to a device. The TPM backend
//! ([`crate::backend_tpm`]) carries these buffers to the TPM; the
//! verifier side (`tenzro-tee`'s TPM attestation module) parses the same
//! structures out of evidence a remote machine produced. Keeping the encoding
//! apart from the transport means the byte layout is tested on every platform,
//! including hosts with no TPM at all.
//!
//! Structures and constants follow TCG TPM 2.0 Library Part 2 (structures) and
//! Part 3 (commands). Field order is the order the specification declares;
//! every variable-length field is walked structurally, never at fixed offsets.

use sha2::{Digest, Sha256, Sha384};

/// Errors from building or parsing a TPM2 buffer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("truncated TPM2 structure")]
    Truncated,
    #[error("TPM refused the command: response code 0x{0:08X}")]
    ResponseCode(u32),
    #[error("malformed TPM2 structure: {0}")]
    Malformed(&'static str),
}

pub type WireResult<T> = std::result::Result<T, WireError>;

// --- Constants (TCG Part 2). ------------------------------------------------

pub const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM2_ST_SESSIONS: u16 = 0x8002;
pub const TPM2_ST_ATTEST_QUOTE: u16 = 0x8018;
pub const TPM2_ST_ATTEST_CERTIFY: u16 = 0x8017;
pub const TPM2_ST_HASHCHECK: u16 = 0x8024;

/// `TPM_GENERATED_VALUE`: the magic every `TPMS_ATTEST` a TPM produces starts
/// with. A restricted signing key refuses to sign data beginning with it, so a
/// signature over a buffer carrying it came from the TPM's own attestation
/// commands.
pub const TPM2_GENERATED_VALUE: u32 = 0xFF54_4347;

pub const TPM2_CC_NV_READ: u32 = 0x0000_014E;
pub const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub const TPM2_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
pub const TPM2_CC_POLICY_SECRET: u32 = 0x0000_0151;
pub const TPM2_CC_ECDH_ZGEN: u32 = 0x0000_0154;
pub const TPM2_CC_QUOTE: u32 = 0x0000_0158;
pub const TPM2_CC_CERTIFY: u32 = 0x0000_0148;
pub const TPM2_CC_SIGN: u32 = 0x0000_015D;
pub const TPM2_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub const TPM2_CC_READ_PUBLIC: u32 = 0x0000_0173;
pub const TPM2_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub const TPM2_CC_GET_CAPABILITY: u32 = 0x0000_017A;
pub const TPM2_CC_CREATE: u32 = 0x0000_0153;
pub const TPM2_CC_HMAC: u32 = 0x0000_0155;
pub const TPM2_CC_LOAD: u32 = 0x0000_0157;
pub const TPM2_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const TPM2_CC_POLICY_SIGNED: u32 = 0x0000_0160;
pub const TPM2_CC_HASH: u32 = 0x0000_017D;
pub const TPM2_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM2_CC_POLICY_PCR: u32 = 0x0000_017F;
pub const TPM2_CC_EVICT_CONTROL: u32 = 0x0000_0120;
/// `TPM2_SignSequenceComplete`, added in TPM 2.0 library specification v1.85.
pub const TPM2_CC_SIGN_SEQUENCE_COMPLETE: u32 = 0x0000_01A4;
/// `TPM2_SignSequenceStart`, added in TPM 2.0 library specification v1.85.
pub const TPM2_CC_SIGN_SEQUENCE_START: u32 = 0x0000_01AA;
/// `TPM_CAP_ALGS`: the algorithms the TPM implements.
pub const TPM2_CAP_ALGS: u32 = 0x0000_0000;
/// `TPM_CAP_ECC_CURVES`: the ECC curves the TPM implements.
pub const TPM2_CAP_ECC_CURVES: u32 = 0x0000_0008;
/// Largest `TPM2B_MAX_BUFFER` (`MAX_DIGEST_BUFFER`), 1024 on every chip.
pub const TPM2_MAX_BUFFER: usize = 1024;

pub const TPM2_RH_OWNER: u32 = 0x4000_0001;
pub const TPM2_RH_ENDORSEMENT: u32 = 0x4000_000B;
pub const TPM2_RH_NULL: u32 = 0x4000_0007;
pub const TPM2_RS_PW: u32 = 0x4000_0009;

pub const TPM2_ALG_RSA: u16 = 0x0001;
pub const TPM2_ALG_HMAC: u16 = 0x0005;
pub const TPM2_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM2_ALG_SHA256: u16 = 0x000B;
pub const TPM2_ALG_SHA384: u16 = 0x000C;
pub const TPM2_ALG_NULL: u16 = 0x0010;
pub const TPM2_ALG_ECDSA: u16 = 0x0018;
pub const TPM2_ALG_ECC: u16 = 0x0023;
pub const TPM2_ALG_AES: u16 = 0x0006;
pub const TPM2_ALG_CFB: u16 = 0x0043;
/// ML-DSA (FIPS 204), added in TPM 2.0 library specification v1.85.
pub const TPM2_ALG_MLDSA: u16 = 0x00A1;
/// `TPMI_MLDSA_PARAMETER_SET` of ML-DSA-65.
pub const TPM2_MLDSA_65: u16 = 0x0002;
/// `TPMI_MLDSA_PARAMETER_SET` of ML-DSA-87.
pub const TPM2_MLDSA_87: u16 = 0x0003;
pub const TPM2_ECC_NIST_P256: u16 = 0x0003;
pub const TPM2_ECC_NIST_P384: u16 = 0x0004;

pub const TPM2_SE_POLICY: u8 = 0x01;

/// Persistent handle of the TCG-standard ECC P-256 endorsement key.
///
/// Read with `TPM2_ReadPublic`, never recreated: reading a persistent handle
/// needs no transient object slot, so it answers even when the chip is out of
/// object memory, and the value is fixed by the endorsement seed regardless.
pub const EK_ECC_PERSISTENT_HANDLE: u32 = 0x8101_0020;
/// Persistent handle of the TCG-standard RSA-2048 endorsement key.
pub const EK_RSA_PERSISTENT_HANDLE: u32 = 0x8101_0001;
/// Persistent handle of the ECC P-384 endorsement key (template H-3), the
/// handle numbered after its certificate's NV index, as swtpm also keeps it.
pub const EK_ECC_P384_PERSISTENT_HANDLE: u32 = 0x8101_0016;
/// Persistent handle of the RSA-3072 endorsement key (template H-6).
pub const EK_RSA_3072_PERSISTENT_HANDLE: u32 = 0x8101_001C;
/// NV index of the ECC P-256 EK certificate (TCG EK Credential Profile).
pub const EK_CERT_NV_ECC: u32 = 0x01C0_000A;
/// NV index of the RSA-2048 EK certificate (template L-1).
pub const EK_CERT_NV_RSA: u32 = 0x01C0_0002;
/// NV index of the ECC P-384 EK certificate (template H-3).
pub const EK_CERT_NV_ECC_P384: u32 = 0x01C0_0016;
/// NV index of the RSA-3072 EK certificate (template H-6).
pub const EK_CERT_NV_RSA_3072: u32 = 0x01C0_001C;
/// First NV index of the EK certificate chain: the intermediates between the
/// EK certificate and the manufacturer root, one certificate per index,
/// allocated upwards from here (TCG EK Credential Profile).
pub const EK_CHAIN_NV_FIRST: u32 = 0x01C0_0100;
/// Last NV index the EK certificate chain may occupy.
pub const EK_CHAIN_NV_LAST: u32 = 0x01C0_01FF;

/// Persistent handle of the node's storage root: the endorsement-hierarchy
/// storage parent every other node key is a child of. Made persistent once,
/// by provisioning; never created while the node runs.
pub const NODE_STORAGE_ROOT_HANDLE: u32 = 0x8101_8000;
/// Persistent handle of the machine attestation key (restricted signing).
pub const NODE_ATTESTATION_HANDLE: u32 = 0x8101_8001;
/// Persistent handle of the default node identity key. A node running under
/// a key namespace has its own slot, see [`node_identity_handle`].
pub const NODE_IDENTITY_HANDLE: u32 = 0x8101_8100;

/// The first persistent handle tried for the identity key labelled
/// `label`: the default slot for the un-namespaced identity, otherwise one
/// of [`NAMESPACE_IDENTITY_SLOTS`] slots after it chosen by the label. Two
/// labels that land in the same slot are told apart by the key's
/// `authPolicy`, which binds the label (see [`identity_template`]); the
/// second one goes to the next free slot (`find_identity_slot` in
/// `tpm_provision`).
pub fn node_identity_handle(label: &str, namespaced: bool) -> u32 {
    if !namespaced {
        return NODE_IDENTITY_HANDLE;
    }
    let d = label_unique(label);
    NODE_IDENTITY_HANDLE
        + 1
        + u32::from(u16::from_be_bytes([d[0], d[1]])) % NAMESPACE_IDENTITY_SLOTS
}

/// Persistent slots after [`NODE_IDENTITY_HANDLE`] that key namespaces'
/// identity keys occupy.
pub const NAMESPACE_IDENTITY_SLOTS: u32 = 255;

pub const TPMA_OBJECT_FIXEDTPM: u32 = 0x0000_0002;
pub const TPMA_OBJECT_FIXEDPARENT: u32 = 0x0000_0010;
pub const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x0000_0020;
pub const TPMA_OBJECT_USERWITHAUTH: u32 = 0x0000_0040;
pub const TPMA_OBJECT_ADMINWITHPOLICY: u32 = 0x0000_0080;
pub const TPMA_OBJECT_NODA: u32 = 0x0000_0400;
pub const TPMA_OBJECT_RESTRICTED: u32 = 0x0001_0000;
pub const TPMA_OBJECT_DECRYPT: u32 = 0x0002_0000;
pub const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 0x0004_0000;

const BASE_ATTRIBUTES: u32 = TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH;

/// A general-purpose signing key: signs any caller-supplied digest.
pub const SIGNING_KEY_ATTRIBUTES: u32 = BASE_ATTRIBUTES | TPMA_OBJECT_SIGN_ENCRYPT;
/// An attestation key: restricted, so it signs only TPM-generated structures
/// (quotes, certifications) and never an arbitrary digest.
pub const ATTESTATION_KEY_ATTRIBUTES: u32 =
    BASE_ATTRIBUTES | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT;
/// A key-agreement key: `TPM2_ECDH_ZGen` only, never signs.
pub const AGREEMENT_KEY_ATTRIBUTES: u32 = BASE_ATTRIBUTES | TPMA_OBJECT_DECRYPT;

/// PCRs a quote covers by default: 0-7, the firmware and boot-loader
/// measurements on a PC platform.
pub const DEFAULT_QUOTE_PCRS: [u8; 3] = [0xFF, 0x00, 0x00];

// --- Buffers. ---------------------------------------------------------------

/// Big-endian command builder.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    /// A `TPM2B_*`: a 16-bit length followed by that many bytes.
    pub fn tpm2b(&mut self, b: &[u8]) -> &mut Self {
        self.u16(b.len() as u16);
        self.0.extend_from_slice(b);
        self
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Cursor-based big-endian reader.
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> WireResult<&'a [u8]> {
        let s = self
            .bytes
            .get(self.pos..self.pos + n)
            .ok_or(WireError::Truncated)?;
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> WireResult<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> WireResult<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> WireResult<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> WireResult<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn tpm2b(&mut self) -> WireResult<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }
    pub fn skip(&mut self, n: usize) -> WireResult<()> {
        self.take(n).map(|_| ())
    }
}

fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut cmd = Writer::new();
    cmd.u16(tag);
    cmd.u32(10 + body.len() as u32);
    cmd.u32(code);
    cmd.bytes(body);
    cmd.finish()
}

/// One password authorization with an empty password.
fn pw_session(w: &mut Writer) {
    w.u32(TPM2_RS_PW);
    w.tpm2b(&[]); // nonceCaller
    w.u8(0); // sessionAttributes
    w.tpm2b(&[]); // hmac (the password)
}

/// Authorization area holding one empty-password session.
fn write_pw_auth_area(w: &mut Writer) {
    let mut s = Writer::new();
    pw_session(&mut s);
    let s = s.finish();
    w.u32(s.len() as u32);
    w.bytes(&s);
}

/// Checks the response code and returns a reader positioned after the
/// 10-byte header.
pub fn response_body(response: &[u8]) -> WireResult<Reader<'_>> {
    let mut r = Reader::new(response);
    let _tag = r.u16()?;
    let size = r.u32()? as usize;
    if size != response.len() {
        return Err(WireError::Malformed(
            "response size field disagrees with length",
        ));
    }
    let code = r.u32()?;
    if code != 0 {
        return Err(WireError::ResponseCode(code));
    }
    Ok(r)
}

// --- Public areas. ----------------------------------------------------------

/// Which key a template describes. Each is created as a primary in the
/// endorsement hierarchy, so the same chip and the same template always
/// produce the same key and nothing has to be stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    Signing,
    Attestation,
    Agreement,
}

impl KeyRole {
    pub fn attributes(self) -> u32 {
        match self {
            Self::Signing => SIGNING_KEY_ATTRIBUTES,
            Self::Attestation => ATTESTATION_KEY_ATTRIBUTES,
            Self::Agreement => AGREEMENT_KEY_ATTRIBUTES,
        }
    }
}

/// The `unique.x` field of a labelled template.
///
/// The TPM derives a primary key from its hierarchy seed and a digest of the
/// whole template, `unique` included, so two labels give two unrelated keys
/// on the same chip and the same label always gives the same key.
pub fn label_unique(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/tpm/primary-label\0");
    h.update(label.as_bytes());
    h.finalize().into()
}

/// A `TPMT_PUBLIC` for an ECC P-256 key in the given role.
pub fn ecc_p256_template(role: KeyRole, label: &str) -> Vec<u8> {
    ecc_p256_template_with_policy(role, label, &[])
}

/// The template of a persistent identity key: a signing key whose
/// `authPolicy` carries the label digest. `userWithAuth` is set and
/// `adminWithPolicy` clear, so the policy never gates a use; it is there so
/// `TPM2_ReadPublic` of the persistent slot shows which label the key is.
pub fn identity_template(label: &str) -> Vec<u8> {
    ecc_p256_template_with_policy(KeyRole::Signing, label, &label_unique(label))
}

fn ecc_p256_template_with_policy(role: KeyRole, label: &str, auth_policy: &[u8]) -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_ECC);
    p.u16(TPM2_ALG_SHA256);
    p.u32(role.attributes());
    p.tpm2b(auth_policy);
    p.u16(TPM2_ALG_NULL); // symmetric
    match role {
        KeyRole::Signing | KeyRole::Attestation => {
            p.u16(TPM2_ALG_ECDSA);
            p.u16(TPM2_ALG_SHA256);
        }
        KeyRole::Agreement => {
            p.u16(TPM2_ALG_NULL);
        }
    }
    p.u16(TPM2_ECC_NIST_P256);
    p.u16(TPM2_ALG_NULL); // kdf
    p.tpm2b(&label_unique(label));
    p.tpm2b(&[]);
    p.finish()
}

/// The template of an ECDSA signing key over NIST P-384 with SHA-384, a
/// child of the storage root generated inside the TPM.
pub fn ecc_p384_signing_template(label: &str) -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_ECC);
    p.u16(TPM2_ALG_SHA256);
    p.u32(SIGNING_KEY_ATTRIBUTES);
    p.tpm2b(&[]);
    p.u16(TPM2_ALG_NULL); // symmetric
    p.u16(TPM2_ALG_ECDSA);
    p.u16(TPM2_ALG_SHA384);
    p.u16(TPM2_ECC_NIST_P384);
    p.u16(TPM2_ALG_NULL); // kdf
    p.tpm2b(&label_unique(label));
    p.tpm2b(&[]);
    p.finish()
}

/// The template of a pure ML-DSA signing key of `parameter_set`
/// ([`TPM2_MLDSA_65`] or [`TPM2_MLDSA_87`]), a child of the storage root
/// generated inside the TPM. External mu is not allowed: the TPM signs the
/// message it is given, never a caller-computed mu.
pub fn ml_dsa_template(parameter_set: u16) -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_MLDSA);
    p.u16(TPM2_ALG_SHA256);
    p.u32(SIGNING_KEY_ATTRIBUTES);
    p.tpm2b(&[]);
    p.u16(parameter_set);
    p.u8(0); // allowExternalMu: NO
    p.tpm2b(&[]); // unique: the TPM fills in the public key
    p.finish()
}

/// A parsed `TPMT_PUBLIC`, holding the fields verifiers act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicArea {
    /// The exact `TPMT_PUBLIC` bytes, needed to compute the object's name.
    pub raw: Vec<u8>,
    pub alg: u16,
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    /// `(algorithm, keyBits, mode)` of a storage or endorsement key's
    /// symmetric definition; `None` when the key has none.
    pub symmetric: Option<(u16, u16, u16)>,
    pub key: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// P-256 point, `x || y`, each 32 bytes.
    EccP256 {
        x: [u8; 32],
        y: [u8; 32],
        scheme: u16,
    },
    /// P-384 point, `x || y`, each 48 bytes. Only endorsement keys are
    /// P-384 here; every key this crate creates is P-256.
    EccP384 {
        x: [u8; 48],
        y: [u8; 48],
        scheme: u16,
    },
    /// RSA modulus and exponent (0 means the default 65537).
    Rsa { modulus: Vec<u8>, exponent: u32 },
    /// An ML-DSA public key of a `TPMI_MLDSA_PARAMETER_SET`.
    MlDsa {
        parameter_set: u16,
        allow_external_mu: bool,
        key: Vec<u8>,
    },
}

impl PublicArea {
    /// `TPM2B_NAME` contents: `nameAlg || H(TPMT_PUBLIC)`.
    pub fn name(&self) -> WireResult<Vec<u8>> {
        let mut n = Vec::with_capacity(50);
        n.extend_from_slice(&self.name_alg.to_be_bytes());
        match self.name_alg {
            TPM2_ALG_SHA256 => n.extend_from_slice(&Sha256::digest(&self.raw)),
            TPM2_ALG_SHA384 => n.extend_from_slice(&Sha384::digest(&self.raw)),
            _ => {
                return Err(WireError::Malformed(
                    "only SHA-256 and SHA-384 object names are supported",
                ));
            }
        }
        Ok(n)
    }

    /// Uncompressed SEC1 point for a P-256 key.
    pub fn p256_sec1(&self) -> Option<[u8; 65]> {
        match &self.key {
            PublicKey::EccP256 { x, y, .. } => {
                let mut out = [0u8; 65];
                out[0] = 0x04;
                out[1..33].copy_from_slice(x);
                out[33..].copy_from_slice(y);
                Some(out)
            }
            PublicKey::EccP384 { .. } | PublicKey::Rsa { .. } | PublicKey::MlDsa { .. } => None,
        }
    }

    /// Uncompressed SEC1 point for a P-384 key.
    pub fn p384_sec1(&self) -> Option<[u8; 97]> {
        match &self.key {
            PublicKey::EccP384 { x, y, .. } => {
                let mut out = [0u8; 97];
                out[0] = 0x04;
                out[1..49].copy_from_slice(x);
                out[49..].copy_from_slice(y);
                Some(out)
            }
            _ => None,
        }
    }
}

fn pad32(b: &[u8]) -> WireResult<[u8; 32]> {
    pad::<32>(b)
}

fn pad<const N: usize>(b: &[u8]) -> WireResult<[u8; N]> {
    if b.len() > N {
        return Err(WireError::Malformed("ECC coordinate longer than its curve"));
    }
    let mut out = [0u8; N];
    out[N - b.len()..].copy_from_slice(b);
    Ok(out)
}

/// Parse a `TPMT_PUBLIC` (not the `TPM2B` wrapper).
pub fn parse_public(raw: &[u8]) -> WireResult<PublicArea> {
    let mut r = Reader::new(raw);
    let alg = r.u16()?;
    let name_alg = r.u16()?;
    let attributes = r.u32()?;
    let auth_policy = r.tpm2b()?.to_vec();
    if alg == TPM2_ALG_MLDSA {
        // TPMS_MLDSA_PARMS has no symmetric definition and no scheme.
        let parameter_set = r.u16()?;
        let allow_external_mu = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(WireError::Malformed("allowExternalMu is not a TPMI_YES_NO")),
        };
        let key = r.tpm2b()?.to_vec();
        if r.remaining() != 0 {
            return Err(WireError::Malformed("trailing bytes after TPMT_PUBLIC"));
        }
        return Ok(PublicArea {
            raw: raw.to_vec(),
            alg,
            name_alg,
            attributes,
            auth_policy,
            symmetric: None,
            key: PublicKey::MlDsa {
                parameter_set,
                allow_external_mu,
                key,
            },
        });
    }
    // symmetric: TPMT_SYM_DEF_OBJECT
    let sym = r.u16()?;
    let symmetric = if sym != TPM2_ALG_NULL {
        Some((sym, r.u16()?, r.u16()?))
    } else {
        None
    };
    let key = match alg {
        TPM2_ALG_ECC => {
            let scheme = r.u16()?;
            if scheme != TPM2_ALG_NULL {
                r.u16()?; // scheme hash
            }
            let curve = r.u16()?;
            if curve != TPM2_ECC_NIST_P256 && curve != TPM2_ECC_NIST_P384 {
                return Err(WireError::Malformed(
                    "only NIST P-256 and P-384 ECC keys are supported",
                ));
            }
            let kdf = r.u16()?;
            if kdf != TPM2_ALG_NULL {
                r.u16()?;
            }
            let (x, y) = (r.tpm2b()?, r.tpm2b()?);
            if curve == TPM2_ECC_NIST_P256 {
                PublicKey::EccP256 {
                    x: pad32(x)?,
                    y: pad32(y)?,
                    scheme,
                }
            } else {
                PublicKey::EccP384 {
                    x: pad(x)?,
                    y: pad(y)?,
                    scheme,
                }
            }
        }
        TPM2_ALG_RSA => {
            let scheme = r.u16()?;
            if scheme != TPM2_ALG_NULL {
                r.u16()?;
            }
            let _bits = r.u16()?;
            let exponent = r.u32()?;
            let modulus = r.tpm2b()?.to_vec();
            PublicKey::Rsa { modulus, exponent }
        }
        _ => return Err(WireError::Malformed("unsupported public key type")),
    };
    if r.remaining() != 0 {
        return Err(WireError::Malformed("trailing bytes after TPMT_PUBLIC"));
    }
    Ok(PublicArea {
        raw: raw.to_vec(),
        alg,
        name_alg,
        attributes,
        auth_policy,
        symmetric,
        key,
    })
}

// --- Commands. --------------------------------------------------------------

/// `TPM2_CreatePrimary` in the endorsement hierarchy for `template`.
pub fn create_primary_command(template: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(TPM2_RH_ENDORSEMENT);
    write_pw_auth_area(&mut b);
    let mut sensitive = Writer::new();
    sensitive.tpm2b(&[]); // userAuth
    sensitive.tpm2b(&[]); // data
    b.tpm2b(&sensitive.finish());
    b.tpm2b(template);
    b.tpm2b(&[]); // outsideInfo
    b.u32(0); // creationPCR: empty selection
    command(TPM2_ST_SESSIONS, TPM2_CC_CREATE_PRIMARY, &b.finish())
}

/// Parse a `TPM2_CreatePrimary` response: the transient handle and the
/// public area the TPM filled in.
pub fn parse_create_primary_response(response: &[u8]) -> WireResult<(u32, PublicArea)> {
    let mut r = response_body(response)?;
    let handle = r.u32()?;
    r.u32()?; // parameterSize
    let public = parse_public(r.tpm2b()?)?;
    Ok((handle, public))
}

/// `TPM2_ReadPublic` of a loaded or persistent object.
pub fn read_public_command(handle: u32) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(handle);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_READ_PUBLIC, &b.finish())
}

pub fn parse_read_public_response(response: &[u8]) -> WireResult<PublicArea> {
    let mut r = response_body(response)?;
    parse_public(r.tpm2b()?)
}

/// `TPM2_GetCapability(TPM_CAP_ALGS)` asking about exactly `alg`.
pub fn get_algorithm_command(alg: u16) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(TPM2_CAP_ALGS).u32(alg as u32).u32(1);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_GET_CAPABILITY, &b.finish())
}

/// Whether a `TPM_CAP_ALGS` response lists `alg`. The TPM answers with the
/// algorithms at or after the one asked for, so the first entry must be it.
pub fn parse_algorithm_supported(response: &[u8], alg: u16) -> WireResult<bool> {
    let mut r = response_body(response)?;
    r.u8()?; // moreData
    if r.u32()? != TPM2_CAP_ALGS {
        return Err(WireError::Malformed(
            "capability response is not TPM_CAP_ALGS",
        ));
    }
    let count = r.u32()?;
    if count == 0 {
        return Ok(false);
    }
    let first = r.u16()?;
    r.u32()?; // algProperties
    Ok(first == alg)
}

/// `TPM2_GetCapability(TPM_CAP_ECC_CURVES)` asking about exactly `curve`.
pub fn get_ecc_curve_command(curve: u16) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(TPM2_CAP_ECC_CURVES).u32(curve as u32).u32(1);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_GET_CAPABILITY, &b.finish())
}

/// Whether a `TPM_CAP_ECC_CURVES` response lists `curve`. The TPM answers
/// with the curves at or after the one asked for, so the first must be it.
pub fn parse_ecc_curve_supported(response: &[u8], curve: u16) -> WireResult<bool> {
    let mut r = response_body(response)?;
    r.u8()?; // moreData
    if r.u32()? != TPM2_CAP_ECC_CURVES {
        return Err(WireError::Malformed(
            "capability response is not TPM_CAP_ECC_CURVES",
        ));
    }
    if r.u32()? == 0 {
        return Ok(false);
    }
    Ok(r.u16()? == curve)
}

/// `TPM2_Sign` of a SHA-384 digest with a P-384 key, through the
/// null-ticket path.
pub fn sign_p384_command(key_handle: u32, digest: &[u8; 48]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(key_handle);
    write_pw_auth_area(&mut b);
    b.tpm2b(digest);
    b.u16(TPM2_ALG_ECDSA);
    b.u16(TPM2_ALG_SHA384);
    b.u16(TPM2_ST_HASHCHECK);
    b.u32(TPM2_RH_NULL);
    b.tpm2b(&[]);
    command(TPM2_ST_SESSIONS, TPM2_CC_SIGN, &b.finish())
}

/// A `TPM2_Sign` response holding an ECDSA-P384-SHA384 signature, as raw
/// `r || s`.
pub fn parse_sign_p384_response(response: &[u8]) -> WireResult<[u8; 96]> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    if r.u16()? != TPM2_ALG_ECDSA {
        return Err(WireError::Malformed("signature is not ECDSA"));
    }
    if r.u16()? != TPM2_ALG_SHA384 {
        return Err(WireError::Malformed("signature hash is not SHA-384"));
    }
    let sr = pad::<48>(r.tpm2b()?)?;
    let ss = pad::<48>(r.tpm2b()?)?;
    let mut out = [0u8; 96];
    out[..48].copy_from_slice(&sr);
    out[48..].copy_from_slice(&ss);
    Ok(out)
}

/// `TPM2_SignSequenceStart` for the ML-DSA key at `key_handle`, with the
/// FIPS 204 context string `context`. The sequence gets an empty
/// authorization value; the key needs no session to start one.
pub fn sign_sequence_start_command(key_handle: u32, context: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(key_handle);
    b.tpm2b(&[]); // auth of the sequence
    b.tpm2b(context);
    command(
        TPM2_ST_NO_SESSIONS,
        TPM2_CC_SIGN_SEQUENCE_START,
        &b.finish(),
    )
}

/// The sequence handle `TPM2_SignSequenceStart` returned.
pub fn parse_sign_sequence_start_response(response: &[u8]) -> WireResult<u32> {
    let mut r = response_body(response)?;
    r.u32()
}

/// `TPM2_SignSequenceComplete`: signs `message` (at most
/// [`TPM2_MAX_BUFFER`] bytes) with the sequence's key. Both the sequence and
/// the key take an empty-password session.
pub fn sign_sequence_complete_command(sequence: u32, key_handle: u32, message: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(sequence);
    b.u32(key_handle);
    let mut s = Writer::new();
    pw_session(&mut s);
    pw_session(&mut s);
    let s = s.finish();
    b.u32(s.len() as u32);
    b.bytes(&s);
    b.tpm2b(message);
    command(
        TPM2_ST_SESSIONS,
        TPM2_CC_SIGN_SEQUENCE_COMPLETE,
        &b.finish(),
    )
}

/// The ML-DSA signature of a `TPM2_SignSequenceComplete` response: a
/// `TPMT_SIGNATURE` of `TPM_ALG_MLDSA`, whose body is the bare signature.
pub fn parse_ml_dsa_signature_response(response: &[u8]) -> WireResult<Vec<u8>> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    if r.u16()? != TPM2_ALG_MLDSA {
        return Err(WireError::Malformed("signature is not ML-DSA"));
    }
    Ok(r.tpm2b()?.to_vec())
}

/// `TPM2_Sign` over a digest, through the null-ticket path (the key is not
/// restricted, so an external digest needs no validation ticket).
pub fn sign_command(key_handle: u32, digest: &[u8; 32]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(key_handle);
    write_pw_auth_area(&mut b);
    b.tpm2b(digest);
    b.u16(TPM2_ALG_ECDSA);
    b.u16(TPM2_ALG_SHA256);
    b.u16(TPM2_ST_HASHCHECK);
    b.u32(TPM2_RH_NULL);
    b.tpm2b(&[]);
    command(TPM2_ST_SESSIONS, TPM2_CC_SIGN, &b.finish())
}

/// Parse a `TPMT_SIGNATURE` holding an ECDSA signature into raw `r || s`.
pub fn parse_ecdsa_signature(r: &mut Reader<'_>) -> WireResult<[u8; 64]> {
    let alg = r.u16()?;
    if alg != TPM2_ALG_ECDSA {
        return Err(WireError::Malformed("signature is not ECDSA"));
    }
    let hash = r.u16()?;
    if hash != TPM2_ALG_SHA256 {
        return Err(WireError::Malformed("signature hash is not SHA-256"));
    }
    let sr = pad32(r.tpm2b()?)?;
    let ss = pad32(r.tpm2b()?)?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sr);
    out[32..].copy_from_slice(&ss);
    Ok(out)
}

pub fn parse_sign_response(response: &[u8]) -> WireResult<[u8; 64]> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    parse_ecdsa_signature(&mut r)
}

/// `TPM2_ECDH_ZGen`: the shared point's x-coordinate for a peer point.
pub fn ecdh_zgen_command(key_handle: u32, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(key_handle);
    write_pw_auth_area(&mut b);
    let mut point = Writer::new();
    point.tpm2b(peer_x);
    point.tpm2b(peer_y);
    b.tpm2b(&point.finish());
    command(TPM2_ST_SESSIONS, TPM2_CC_ECDH_ZGEN, &b.finish())
}

pub fn parse_ecdh_zgen_response(response: &[u8]) -> WireResult<[u8; 32]> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    let mut point = Reader::new(r.tpm2b()?);
    pad32(point.tpm2b()?)
}

/// `TPM2_Quote` of the given PCR bitmap (SHA-256 bank) over `qualifying_data`.
pub fn quote_command(ak_handle: u32, qualifying_data: &[u8], pcrs: &[u8; 3]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(ak_handle);
    write_pw_auth_area(&mut b);
    b.tpm2b(qualifying_data);
    b.u16(TPM2_ALG_NULL); // inScheme: use the key's own scheme
    b.u32(1); // TPML_PCR_SELECTION count
    b.u16(TPM2_ALG_SHA256);
    b.u8(3);
    b.bytes(pcrs);
    command(TPM2_ST_SESSIONS, TPM2_CC_QUOTE, &b.finish())
}

/// `TPM2_Certify`: the attestation key `sign_handle` certifies that the
/// object `object_handle` is loaded in this TPM, over `qualifying_data`.
/// Both handles take an empty-password session.
pub fn certify_command(object_handle: u32, sign_handle: u32, qualifying_data: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(object_handle);
    b.u32(sign_handle);
    let mut sessions = Writer::new();
    pw_session(&mut sessions);
    pw_session(&mut sessions);
    let sessions = sessions.finish();
    b.u32(sessions.len() as u32);
    b.bytes(&sessions);
    b.tpm2b(qualifying_data);
    b.u16(TPM2_ALG_NULL); // inScheme: use the signing key's own scheme
    command(TPM2_ST_SESSIONS, TPM2_CC_CERTIFY, &b.finish())
}

/// Parse a `TPM2_Certify` response into the signed `TPMS_ATTEST` bytes and
/// the raw `r || s` signature. The layout matches a quote response.
pub fn parse_certify_response(response: &[u8]) -> WireResult<(Vec<u8>, [u8; 64])> {
    parse_quote_response(response)
}

/// Parse a `TPM2_Quote` response into the signed `TPMS_ATTEST` bytes and the
/// raw `r || s` signature.
pub fn parse_quote_response(response: &[u8]) -> WireResult<(Vec<u8>, [u8; 64])> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    let attest = r.tpm2b()?.to_vec();
    let sig = parse_ecdsa_signature(&mut r)?;
    Ok((attest, sig))
}

/// `TPM2_NV_ReadPublic`.
pub fn nv_read_public_command(index: u32) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(index);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_NV_READ_PUBLIC, &b.finish())
}

/// The data size of an NV index from its `TPM2B_NV_PUBLIC`.
pub fn parse_nv_read_public_response(response: &[u8]) -> WireResult<u16> {
    let mut r = response_body(response)?;
    let mut p = Reader::new(r.tpm2b()?);
    p.u32()?; // nvIndex
    p.u16()?; // nameAlg
    p.u32()?; // attributes
    p.tpm2b()?; // authPolicy
    p.u16()
}

/// `TPM2_NV_Read` of `size` bytes at `offset`, authorised by the index itself
/// with an empty password (the EK certificate indices allow this).
pub fn nv_read_command(index: u32, size: u16, offset: u16) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(index); // authHandle
    b.u32(index); // nvIndex
    write_pw_auth_area(&mut b);
    b.u16(size);
    b.u16(offset);
    command(TPM2_ST_SESSIONS, TPM2_CC_NV_READ, &b.finish())
}

pub fn parse_nv_read_response(response: &[u8]) -> WireResult<Vec<u8>> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    Ok(r.tpm2b()?.to_vec())
}

/// `TPM2_StartAuthSession` for an unbound, unsalted SHA-256 policy session.
pub fn start_policy_session_command(nonce_caller: &[u8; 16]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(TPM2_RH_NULL); // tpmKey
    b.u32(TPM2_RH_NULL); // bind
    b.tpm2b(nonce_caller);
    b.tpm2b(&[]); // encryptedSalt
    b.u8(TPM2_SE_POLICY);
    b.u16(TPM2_ALG_NULL); // symmetric
    b.u16(TPM2_ALG_SHA256); // authHash
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_START_AUTH_SESSION, &b.finish())
}

pub fn parse_start_auth_session_response(response: &[u8]) -> WireResult<u32> {
    let mut r = response_body(response)?;
    r.u32()
}

/// The session handle and the `nonceTPM` of a `TPM2_StartAuthSession`
/// response; a policy authorised by a signature signs that nonce.
pub fn parse_start_auth_session_nonce(response: &[u8]) -> WireResult<(u32, Vec<u8>)> {
    let mut r = response_body(response)?;
    let handle = r.u32()?;
    let nonce = r.tpm2b()?.to_vec();
    Ok((handle, nonce))
}

/// `TPM2_PolicySecret(TPM_RH_ENDORSEMENT)`, the policy the TCG EK templates
/// carry as their `authPolicy`.
pub fn policy_secret_endorsement_command(session: u32) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(TPM2_RH_ENDORSEMENT); // authHandle
    b.u32(session); // policySession
    write_pw_auth_area(&mut b);
    b.tpm2b(&[]); // nonceTPM
    b.tpm2b(&[]); // cpHashA
    b.tpm2b(&[]); // policyRef
    b.u32(0); // expiration
    command(TPM2_ST_SESSIONS, TPM2_CC_POLICY_SECRET, &b.finish())
}

/// `TPM2_ActivateCredential`: the attestation key (password auth) and the
/// endorsement key (policy session) together recover the secret a verifier
/// encrypted to this TPM for this attestation key.
pub fn activate_credential_command(
    ak_handle: u32,
    ek_handle: u32,
    ek_policy_session: u32,
    credential_blob: &[u8],
    encrypted_secret: &[u8],
) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(ak_handle);
    b.u32(ek_handle);
    let mut sessions = Writer::new();
    pw_session(&mut sessions);
    sessions.u32(ek_policy_session);
    sessions.tpm2b(&[]);
    sessions.u8(0);
    sessions.tpm2b(&[]);
    let sessions = sessions.finish();
    b.u32(sessions.len() as u32);
    b.bytes(&sessions);
    b.tpm2b(credential_blob);
    b.tpm2b(encrypted_secret);
    command(TPM2_ST_SESSIONS, TPM2_CC_ACTIVATE_CREDENTIAL, &b.finish())
}

pub fn parse_activate_credential_response(response: &[u8]) -> WireResult<Vec<u8>> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    Ok(r.tpm2b()?.to_vec())
}

// --- Policy-bound HMAC keys. ------------------------------------------------

/// Attributes of a storage parent: a restricted decryption key that wraps its
/// children, so a child blob is useless on any other chip.
pub const STORAGE_PARENT_ATTRIBUTES: u32 = TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH
    | TPMA_OBJECT_NODA
    | TPMA_OBJECT_RESTRICTED
    | TPMA_OBJECT_DECRYPT;

/// Attributes of a policy-bound HMAC key.
///
/// - `fixedTPM`, `fixedParent`: it cannot be duplicated off this chip.
/// - `sensitiveDataOrigin`: the TPM chose the key; nobody supplied its bytes.
/// - `userWithAuth` CLEAR: a plain password session is refused, so every use
///   goes through the key's `authPolicy`.
/// - `adminWithPolicy`: administrative use needs the policy too.
/// - `noDA`: a wrong authorization does not count towards the TPM's
///   dictionary-attack lockout. The authorization is 32 bytes of hash output,
///   so guessing is not a threat, while lockout would let any local process
///   disable every DA-protected key on the chip by failing on purpose.
/// - `sign`: it computes HMACs.
pub const POLICY_HMAC_KEY_ATTRIBUTES: u32 = TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_ADMINWITHPOLICY
    | TPMA_OBJECT_NODA
    | TPMA_OBJECT_SIGN_ENCRYPT;

/// `TPM2_PolicySigned` by the object named `auth_name` with `policy_ref`,
/// extending the policy digest `prev`:
/// `H(H(prev || TPM_CC_PolicySigned || auth_name) || policy_ref)`.
pub fn policy_signed_update(prev: &[u8; 32], auth_name: &[u8], policy_ref: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(TPM2_CC_POLICY_SIGNED.to_be_bytes());
    h.update(auth_name);
    let first: [u8; 32] = h.finalize().into();
    let mut h = Sha256::new();
    h.update(first);
    h.update(policy_ref);
    h.finalize().into()
}

/// A `TPML_PCR_SELECTION` of one SHA-256 PCR.
fn pcr_selection(w: &mut Writer, pcr: u8) {
    w.u32(1); // count
    w.u16(TPM2_ALG_SHA256);
    w.u8(3); // sizeofSelect
    let mut select = [0u8; 3];
    select[usize::from(pcr / 8)] = 1 << (pcr % 8);
    w.bytes(&select);
}

/// `TPM2_PolicyPCR` on one SHA-256 PCR whose value hashes to `pcr_digest`,
/// extending the policy digest `prev`:
/// `H(prev || TPM_CC_PolicyPCR || pcrSelection || pcr_digest)`.
pub fn policy_pcr_update(prev: &[u8; 32], pcr: u8, pcr_digest: &[u8; 32]) -> [u8; 32] {
    let mut sel = Writer::new();
    pcr_selection(&mut sel, pcr);
    let mut h = Sha256::new();
    h.update(prev);
    h.update(TPM2_CC_POLICY_PCR.to_be_bytes());
    h.update(sel.finish());
    h.update(pcr_digest);
    h.finalize().into()
}

/// The digest `TPM2_PolicyPCR` compares for one PCR: SHA-256 of its value.
pub fn pcr_digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// `TPM2_PCR_Read` of one SHA-256 PCR.
pub fn pcr_read_command(pcr: u8) -> Vec<u8> {
    let mut b = Writer::new();
    pcr_selection(&mut b, pcr);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_PCR_READ, &b.finish())
}

/// The value of the one PCR a `TPM2_PCR_Read` response carries.
pub fn parse_pcr_read_response(response: &[u8]) -> WireResult<Vec<u8>> {
    let mut r = response_body(response)?;
    r.u32()?; // pcrUpdateCounter
    let count = r.u32()?; // pcrSelectionOut
    for _ in 0..count {
        r.u16()?;
        let n = r.u8()?;
        r.skip(usize::from(n))?;
    }
    if r.u32()? != 1 {
        return Err(WireError::Malformed(
            "TPM2_PCR_Read did not return one PCR value",
        ));
    }
    Ok(r.tpm2b()?.to_vec())
}

/// `TPM2_PolicyPCR` in `session` on one SHA-256 PCR. An empty `pcr_digest`
/// has the TPM use the PCR's current value; the session's policy then
/// matches only an object bound to that value.
pub fn policy_pcr_command(session: u32, pcr_digest: &[u8], pcr: u8) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(session);
    b.tpm2b(pcr_digest);
    pcr_selection(&mut b, pcr);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_PCR, &b.finish())
}

/// The digest a key signs to satisfy `TPM2_PolicySigned`:
/// `H(nonceTPM || expiration || cpHashA || policyRef)`, with an empty
/// `cpHashA`.
pub fn policy_signed_message(nonce_tpm: &[u8], expiration: i32, policy_ref: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(nonce_tpm.len() + 4 + policy_ref.len());
    m.extend_from_slice(nonce_tpm);
    m.extend_from_slice(&expiration.to_be_bytes());
    m.extend_from_slice(policy_ref);
    m
}

/// PolicySecret(TPM_RH_ENDORSEMENT), the `authPolicy` of the TCG EK templates.
pub const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

/// The `authPolicy` of the TCG high-range EK templates with a SHA-384 name
/// algorithm (PolicyB: PolicyOR of PolicySecret(TPM_RH_ENDORSEMENT) and the
/// PolicyAuthorizeNV branch), EK Credential Profile 2.5.
pub const EK_POLICY_B_SHA384: [u8; 48] = [
    0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc, 0xf5, 0xfd, 0x3a, 0x1a,
    0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4, 0x19, 0xca,
    0xcb, 0x47, 0xba, 0x09, 0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3, 0xf8, 0x0e, 0x12,
];

/// Attributes of the TCG low-range EK templates (L-1, L-2): use needs the
/// PolicySecret(TPM_RH_ENDORSEMENT) policy.
pub const EK_LOW_RANGE_ATTRIBUTES: u32 = TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_ADMINWITHPOLICY
    | TPMA_OBJECT_RESTRICTED
    | TPMA_OBJECT_DECRYPT;

/// Attributes of the TCG high-range EK templates (H-1 to H-7): as the low
/// range, plus `userWithAuth`, so user-role use takes the (empty) password.
pub const EK_HIGH_RANGE_ATTRIBUTES: u32 = EK_LOW_RANGE_ATTRIBUTES | TPMA_OBJECT_USERWITHAUTH;

/// The TCG default RSA-2048 endorsement key template (template L-1).
pub fn ek_rsa2048_template() -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_RSA).u16(TPM2_ALG_SHA256);
    p.u32(EK_LOW_RANGE_ATTRIBUTES);
    p.tpm2b(&EK_POLICY);
    p.u16(TPM2_ALG_AES).u16(128).u16(TPM2_ALG_CFB);
    p.u16(TPM2_ALG_NULL); // scheme
    p.u16(2048).u32(0); // keyBits, exponent (default)
    p.tpm2b(&[0u8; 256]);
    p.finish()
}

/// The TCG ECC P-384 endorsement key template (template H-3).
pub fn ek_ecc_p384_template() -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_ECC).u16(TPM2_ALG_SHA384);
    p.u32(EK_HIGH_RANGE_ATTRIBUTES);
    p.tpm2b(&EK_POLICY_B_SHA384);
    p.u16(TPM2_ALG_AES).u16(256).u16(TPM2_ALG_CFB);
    p.u16(TPM2_ALG_NULL); // scheme
    p.u16(TPM2_ECC_NIST_P384);
    p.u16(TPM2_ALG_NULL); // kdf
    p.tpm2b(&[]).tpm2b(&[]); // unique: empty in the high range
    p.finish()
}

/// The TCG RSA-3072 endorsement key template (template H-6).
pub fn ek_rsa3072_template() -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_RSA).u16(TPM2_ALG_SHA384);
    p.u32(EK_HIGH_RANGE_ATTRIBUTES);
    p.tpm2b(&EK_POLICY_B_SHA384);
    p.u16(TPM2_ALG_AES).u16(256).u16(TPM2_ALG_CFB);
    p.u16(TPM2_ALG_NULL); // scheme
    p.u16(3072).u32(0);
    p.tpm2b(&[]);
    p.finish()
}

/// One kind of manufacturer-certified endorsement key: where its certificate
/// lives, the template that recreates the key, and the persistent handle it
/// is kept at. `tenzro-node tpm provision` makes the key persistent there;
/// attestation only reads it.
#[derive(Clone, Copy, Debug)]
pub struct EkProfile {
    /// Short name, for messages.
    pub name: &'static str,
    /// NV index of the EK certificate.
    pub cert_index: u32,
    /// The TCG template that recreates the key as an endorsement primary.
    pub template: fn() -> Vec<u8>,
    /// Persistent handle the key is kept at.
    pub persistent: u32,
}

/// The endorsement keys a TPM may carry a manufacturer certificate for, in
/// the order a machine offers them.
pub const EK_PROFILES: [EkProfile; 4] = [
    EkProfile {
        name: "ECC P-256 (L-2)",
        cert_index: EK_CERT_NV_ECC,
        template: ek_ecc_template,
        persistent: EK_ECC_PERSISTENT_HANDLE,
    },
    EkProfile {
        name: "RSA-2048 (L-1)",
        cert_index: EK_CERT_NV_RSA,
        template: ek_rsa2048_template,
        persistent: EK_RSA_PERSISTENT_HANDLE,
    },
    EkProfile {
        name: "ECC P-384 (H-3)",
        cert_index: EK_CERT_NV_ECC_P384,
        template: ek_ecc_p384_template,
        persistent: EK_ECC_P384_PERSISTENT_HANDLE,
    },
    EkProfile {
        name: "RSA-3072 (H-6)",
        cert_index: EK_CERT_NV_RSA_3072,
        template: ek_rsa3072_template,
        persistent: EK_RSA_3072_PERSISTENT_HANDLE,
    },
];

/// `TPM2_ActivateCredential` with the endorsement key authorised by the
/// empty password (high-range EKs, which set `userWithAuth`).
pub fn activate_credential_password_command(
    ak_handle: u32,
    ek_handle: u32,
    credential_blob: &[u8],
    encrypted_secret: &[u8],
) -> Vec<u8> {
    activate_credential_command(
        ak_handle,
        ek_handle,
        TPM2_RS_PW,
        credential_blob,
        encrypted_secret,
    )
}

/// The TCG default ECC P-256 endorsement key template (EK Credential Profile,
/// template L-2). Creating it as a primary in the endorsement hierarchy gives
/// this TPM's endorsement key, the same key the manufacturer certified,
/// without using any persistent handle.
pub fn ek_ecc_template() -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_ECC);
    p.u16(TPM2_ALG_SHA256);
    p.u32(
        TPMA_OBJECT_FIXEDTPM
            | TPMA_OBJECT_FIXEDPARENT
            | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_ADMINWITHPOLICY
            | TPMA_OBJECT_RESTRICTED
            | TPMA_OBJECT_DECRYPT,
    );
    p.tpm2b(&EK_POLICY);
    p.u16(TPM2_ALG_AES).u16(128).u16(TPM2_ALG_CFB);
    p.u16(TPM2_ALG_NULL); // scheme
    p.u16(TPM2_ECC_NIST_P256);
    p.u16(TPM2_ALG_NULL); // kdf
    p.tpm2b(&[0u8; 32]);
    p.tpm2b(&[0u8; 32]);
    p.finish()
}

/// A `TPMT_PUBLIC` for an ECC P-256 storage parent in the endorsement
/// hierarchy, labelled so different uses get different parents.
pub fn storage_parent_template(label: &str) -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_ECC);
    p.u16(TPM2_ALG_SHA256);
    p.u32(STORAGE_PARENT_ATTRIBUTES);
    p.tpm2b(&[]); // authPolicy
    p.u16(TPM2_ALG_AES).u16(128).u16(TPM2_ALG_CFB); // symmetric
    p.u16(TPM2_ALG_NULL); // scheme
    p.u16(TPM2_ECC_NIST_P256);
    p.u16(TPM2_ALG_NULL); // kdf
    p.tpm2b(&label_unique(label));
    p.tpm2b(&[]);
    p.finish()
}

/// A `TPMT_PUBLIC` for a keyed-hash (HMAC-SHA256) key whose every use must
/// satisfy `policy`.
pub fn policy_hmac_key_template(policy: &[u8; 32]) -> Vec<u8> {
    let mut p = Writer::new();
    p.u16(TPM2_ALG_KEYEDHASH);
    p.u16(TPM2_ALG_SHA256);
    p.u32(POLICY_HMAC_KEY_ATTRIBUTES);
    p.tpm2b(policy);
    p.u16(TPM2_ALG_HMAC); // TPMT_KEYEDHASH_SCHEME
    p.u16(TPM2_ALG_SHA256); // TPMS_SCHEME_HMAC.hashAlg
    p.tpm2b(&[]); // unique
    p.finish()
}

/// The fields of a keyed-hash `TPMT_PUBLIC` a user of the key must check
/// before trusting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyedHashPublic {
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub scheme: u16,
    pub scheme_hash: u16,
}

/// Parse a keyed-hash `TPMT_PUBLIC`. Refuses any other object type.
pub fn parse_keyedhash_public(raw: &[u8]) -> WireResult<KeyedHashPublic> {
    let mut r = Reader::new(raw);
    if r.u16()? != TPM2_ALG_KEYEDHASH {
        return Err(WireError::Malformed("object is not a keyed-hash key"));
    }
    let name_alg = r.u16()?;
    let attributes = r.u32()?;
    let auth_policy = r.tpm2b()?.to_vec();
    let scheme = r.u16()?;
    let scheme_hash = if scheme == TPM2_ALG_NULL {
        TPM2_ALG_NULL
    } else {
        r.u16()?
    };
    r.tpm2b()?; // unique
    if r.remaining() != 0 {
        return Err(WireError::Malformed("trailing bytes after TPMT_PUBLIC"));
    }
    Ok(KeyedHashPublic {
        name_alg,
        attributes,
        auth_policy,
        scheme,
        scheme_hash,
    })
}

/// `TPM2_Create` of a child of `parent` (empty parent authorization), with
/// `user_auth` as the new object's authorization value and no caller-supplied
/// sensitive data.
pub fn create_command(parent: u32, user_auth: &[u8], template: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(parent);
    write_pw_auth_area(&mut b);
    let mut sensitive = Writer::new();
    sensitive.tpm2b(user_auth);
    sensitive.tpm2b(&[]); // data: the TPM generates it
    b.tpm2b(&sensitive.finish());
    b.tpm2b(template);
    b.tpm2b(&[]); // outsideInfo
    b.u32(0); // creationPCR: empty selection
    command(TPM2_ST_SESSIONS, TPM2_CC_CREATE, &b.finish())
}

/// Parse a `TPM2_Create` response into the `TPM2B_PRIVATE` contents (the
/// child's sensitive area, encrypted by the parent) and the `TPMT_PUBLIC`.
pub fn parse_create_response(response: &[u8]) -> WireResult<(Vec<u8>, Vec<u8>)> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    let private = r.tpm2b()?.to_vec();
    let public = r.tpm2b()?.to_vec();
    Ok((private, public))
}

/// `TPM2_Load` of a child under `parent` (empty parent authorization).
pub fn load_command(parent: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(parent);
    write_pw_auth_area(&mut b);
    b.tpm2b(private);
    b.tpm2b(public);
    command(TPM2_ST_SESSIONS, TPM2_CC_LOAD, &b.finish())
}

/// The transient handle `TPM2_Load` returned.
pub fn parse_load_response(response: &[u8]) -> WireResult<u32> {
    let mut r = response_body(response)?;
    r.u32()
}

/// `TPM2_Hash` of `data` (at most 1024 bytes) in `hierarchy`: the digest and
/// the `TPMT_TK_HASHCHECK` ticket that lets a restricted key sign it. The TPM
/// withholds the ticket (a null ticket) when `data` starts with
/// `TPM_GENERATED_VALUE`.
pub fn hash_command(data: &[u8], hierarchy: u32) -> Vec<u8> {
    let mut b = Writer::new();
    b.tpm2b(data);
    b.u16(TPM2_ALG_SHA256);
    b.u32(hierarchy);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_HASH, &b.finish())
}

/// The digest and the raw `TPMT_TK_HASHCHECK` of a `TPM2_Hash` response.
pub fn parse_hash_response(response: &[u8]) -> WireResult<([u8; 32], Vec<u8>)> {
    let mut r = response_body(response)?;
    let digest: [u8; 32] = r
        .tpm2b()?
        .try_into()
        .map_err(|_| WireError::Malformed("TPM2_Hash digest is not 32 bytes"))?;
    let start = r.position();
    r.u16()?; // tag
    r.u32()?; // hierarchy
    r.tpm2b()?; // ticket digest
    let ticket = response[start..r.position()].to_vec();
    Ok((digest, ticket))
}

/// `TPM2_Sign` of `digest` with the key at `key_handle` (empty password),
/// presenting `validation`, a raw `TPMT_TK_HASHCHECK` from `TPM2_Hash`, as a
/// restricted key requires.
pub fn sign_validated_command(key_handle: u32, digest: &[u8; 32], validation: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(key_handle);
    write_pw_auth_area(&mut b);
    b.tpm2b(digest);
    b.u16(TPM2_ALG_ECDSA);
    b.u16(TPM2_ALG_SHA256);
    b.bytes(validation);
    command(TPM2_ST_SESSIONS, TPM2_CC_SIGN, &b.finish())
}

/// `TPM2_PolicySigned`: `auth_object` (loaded, public part only needed)
/// signed `nonce_tpm`, `expiration` and `policy_ref` for this session.
pub fn policy_signed_command(
    auth_object: u32,
    session: u32,
    nonce_tpm: &[u8],
    policy_ref: &[u8],
    expiration: i32,
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(auth_object);
    b.u32(session);
    b.tpm2b(nonce_tpm);
    b.tpm2b(&[]); // cpHashA
    b.tpm2b(policy_ref);
    b.u32(expiration as u32);
    b.u16(TPM2_ALG_ECDSA);
    b.u16(TPM2_ALG_SHA256);
    b.tpm2b(&signature[..32]);
    b.tpm2b(&signature[32..]);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_SIGNED, &b.finish())
}

/// `TPM2_HMAC` over `data` (at most 1024 bytes) with the keyed-hash key at
/// `key`, authorised by the policy session `session` carrying `auth`. The
/// session is not continued, so the TPM closes it after this command.
pub fn hmac_command(key: u32, session: u32, auth: &[u8], data: &[u8]) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(key);
    let mut s = Writer::new();
    s.u32(session);
    s.tpm2b(&[]); // nonceCaller
    s.u8(0); // sessionAttributes: continueSession clear
    s.tpm2b(auth);
    let s = s.finish();
    b.u32(s.len() as u32);
    b.bytes(&s);
    b.tpm2b(data);
    b.u16(TPM2_ALG_SHA256);
    command(TPM2_ST_SESSIONS, TPM2_CC_HMAC, &b.finish())
}

pub fn parse_hmac_response(response: &[u8]) -> WireResult<[u8; 32]> {
    let mut r = response_body(response)?;
    r.u32()?; // parameterSize
    let mac = r.tpm2b()?;
    mac.try_into()
        .map_err(|_| WireError::Malformed("HMAC-SHA256 output is not 32 bytes"))
}

/// `TPM2_FlushContext`: free a transient object or session.
pub fn flush_context_command(handle: u32) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(handle);
    command(TPM2_ST_NO_SESSIONS, TPM2_CC_FLUSH_CONTEXT, &b.finish())
}

/// `TPM2_EvictControl` under owner authorization (empty password): make the
/// loaded `object` persistent at `persistent`.
pub fn evict_control_command(object: u32, persistent: u32) -> Vec<u8> {
    let mut b = Writer::new();
    b.u32(TPM2_RH_OWNER);
    b.u32(object);
    write_pw_auth_area(&mut b);
    b.u32(persistent);
    command(TPM2_ST_SESSIONS, TPM2_CC_EVICT_CONTROL, &b.finish())
}

/// The command code of a framed command, `None` when it is too short.
pub fn command_code(command: &[u8]) -> Option<u32> {
    command
        .get(6..10)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

// --- Certify structure. -----------------------------------------------------

/// The fields of a `TPMS_ATTEST` of type certify that a verifier acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifyInfo {
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    /// Name of the certified object.
    pub name: Vec<u8>,
    /// Qualified name of the certified object.
    pub qualified_name: Vec<u8>,
}

/// Parse `TPMS_ATTEST` bytes. Refuses anything that is not a TPM-generated
/// certification.
pub fn parse_certify(attest: &[u8]) -> WireResult<CertifyInfo> {
    let mut r = Reader::new(attest);
    if r.u32()? != TPM2_GENERATED_VALUE {
        return Err(WireError::Malformed(
            "attestation does not carry TPM_GENERATED_VALUE",
        ));
    }
    if r.u16()? != TPM2_ST_ATTEST_CERTIFY {
        return Err(WireError::Malformed("attestation is not a certification"));
    }
    let qualified_signer = r.tpm2b()?.to_vec();
    let extra_data = r.tpm2b()?.to_vec();
    r.skip(8 + 4 + 4 + 1)?; // clockInfo
    r.skip(8)?; // firmwareVersion
    let name = r.tpm2b()?.to_vec();
    let qualified_name = r.tpm2b()?.to_vec();
    if r.remaining() != 0 {
        return Err(WireError::Malformed("trailing bytes after TPMS_ATTEST"));
    }
    Ok(CertifyInfo {
        qualified_signer,
        extra_data,
        name,
        qualified_name,
    })
}

// --- Quote structure. -------------------------------------------------------

/// The fields of a `TPMS_ATTEST` of type quote that a verifier acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteInfo {
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware_version: u64,
    /// `(hashAlg, bitmap)` for each bank in the selection.
    pub pcr_selection: Vec<(u16, Vec<u8>)>,
    pub pcr_digest: Vec<u8>,
}

/// Parse `TPMS_ATTEST` bytes. Refuses anything that is not a TPM-generated
/// quote.
pub fn parse_quote(attest: &[u8]) -> WireResult<QuoteInfo> {
    let mut r = Reader::new(attest);
    if r.u32()? != TPM2_GENERATED_VALUE {
        return Err(WireError::Malformed(
            "attestation does not carry TPM_GENERATED_VALUE",
        ));
    }
    if r.u16()? != TPM2_ST_ATTEST_QUOTE {
        return Err(WireError::Malformed("attestation is not a quote"));
    }
    let qualified_signer = r.tpm2b()?.to_vec();
    let extra_data = r.tpm2b()?.to_vec();
    let clock = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    let safe = r.u8()? != 0;
    let firmware_version = r.u64()?;
    let count = r.u32()?;
    if count > 16 {
        return Err(WireError::Malformed("implausible PCR selection count"));
    }
    let mut pcr_selection = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let hash = r.u16()?;
        let size = r.u8()? as usize;
        pcr_selection.push((hash, r.take(size)?.to_vec()));
    }
    let pcr_digest = r.tpm2b()?.to_vec();
    if r.remaining() != 0 {
        return Err(WireError::Malformed("trailing bytes after TPMS_ATTEST"));
    }
    Ok(QuoteInfo {
        qualified_signer,
        extra_data,
        clock,
        reset_count,
        restart_count,
        safe,
        firmware_version,
        pcr_selection,
        pcr_digest,
    })
}

/// The qualified name of a primary object in the endorsement hierarchy:
/// `nameAlg || H(QN(TPM_RH_ENDORSEMENT) || Name(object))`, where the
/// hierarchy's qualified name is its handle.
pub fn endorsement_primary_qualified_name(name: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(TPM2_RH_ENDORSEMENT.to_be_bytes());
    h.update(name);
    let mut out = Vec::with_capacity(34);
    out.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());
    out.extend_from_slice(&h.finalize());
    out
}

/// Whether a response code means a handle the command named no longer
/// refers to a loaded object or session.
pub fn handle_lost(code: u32) -> bool {
    const TPM_RC_INITIALIZE: u32 = 0x100;
    const RC_FMT1: u32 = 0x080;
    const RC_HANDLE: u32 = 0x00B;
    const TPM_RC_REFERENCE_H0: u32 = 0x910;
    const TPM_RC_REFERENCE_S6: u32 = 0x91E;
    code == TPM_RC_INITIALIZE
        || (code & RC_FMT1 != 0 && code & 0x3F == RC_HANDLE)
        || (TPM_RC_REFERENCE_H0..=TPM_RC_REFERENCE_S6).contains(&code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_response(algs: &[u16]) -> Vec<u8> {
        let mut body = Writer::new();
        body.u8(0).u32(TPM2_CAP_ALGS).u32(algs.len() as u32);
        for a in algs {
            body.u16(*a).u32(0);
        }
        let body = body.finish();
        let mut w = Writer::new();
        w.u16(TPM2_ST_NO_SESSIONS)
            .u32(10 + body.len() as u32)
            .u32(0)
            .bytes(&body);
        w.finish()
    }

    #[test]
    fn algorithm_support_is_read_from_the_first_listed_entry() {
        assert!(
            parse_algorithm_supported(&caps_response(&[TPM2_ALG_MLDSA]), TPM2_ALG_MLDSA).unwrap()
        );
        // A TPM without ML-DSA answers with the next algorithm it has, or none.
        assert!(!parse_algorithm_supported(&caps_response(&[0x00B0]), TPM2_ALG_MLDSA).unwrap());
        assert!(!parse_algorithm_supported(&caps_response(&[]), TPM2_ALG_MLDSA).unwrap());
    }

    fn header(cmd: &[u8]) -> (u16, u32, u32) {
        let mut r = Reader::new(cmd);
        (r.u16().unwrap(), r.u32().unwrap(), r.u32().unwrap())
    }

    fn ok_response(tag: u16, body: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(tag).u32(10 + body.len() as u32).u32(0).bytes(body);
        w.finish()
    }

    #[test]
    fn p384_and_ml_dsa_templates_parse_as_their_key_types() {
        let p = parse_public(&ecc_p384_signing_template("tenzro/test")).unwrap();
        assert_eq!(p.attributes, SIGNING_KEY_ATTRIBUTES);
        assert!(matches!(
            p.key,
            PublicKey::EccP384 {
                scheme: TPM2_ALG_ECDSA,
                ..
            }
        ));
        for set in [TPM2_MLDSA_65, TPM2_MLDSA_87] {
            let p = parse_public(&ml_dsa_template(set)).unwrap();
            assert_eq!(p.alg, TPM2_ALG_MLDSA);
            assert_eq!(p.attributes, SIGNING_KEY_ATTRIBUTES);
            assert_eq!(
                p.key,
                PublicKey::MlDsa {
                    parameter_set: set,
                    allow_external_mu: false,
                    key: Vec::new()
                }
            );
        }
        let mut trailing = ml_dsa_template(TPM2_MLDSA_87);
        trailing.push(0);
        assert!(parse_public(&trailing).is_err());
    }

    #[test]
    fn ecc_curve_support_is_read_from_the_first_listed_curve() {
        let resp = |curves: &[u16]| {
            let mut b = Writer::new();
            b.u8(0).u32(TPM2_CAP_ECC_CURVES).u32(curves.len() as u32);
            for c in curves {
                b.u16(*c);
            }
            ok_response(TPM2_ST_NO_SESSIONS, &b.finish())
        };
        let p384 = TPM2_ECC_NIST_P384;
        assert!(parse_ecc_curve_supported(&resp(&[p384]), p384).unwrap());
        // A TPM with P-256 and BN-P256 only answers with the next curve on.
        assert!(!parse_ecc_curve_supported(&resp(&[0x0010]), p384).unwrap());
        assert!(!parse_ecc_curve_supported(&resp(&[]), p384).unwrap());
        assert!(parse_ecc_curve_supported(&caps_response(&[p384]), p384).is_err());
    }

    #[test]
    fn sign_sequence_commands_are_framed() {
        let start = sign_sequence_start_command(0x8000_0001, b"ctx");
        assert_eq!(command_code(&start), Some(TPM2_CC_SIGN_SEQUENCE_START));
        assert_eq!(&start[..2], &TPM2_ST_NO_SESSIONS.to_be_bytes());
        assert_eq!(&start[10..14], &0x8000_0001u32.to_be_bytes());
        assert_eq!(&start[14..], &[0, 0, 0, 3, b'c', b't', b'x']);
        let done = sign_sequence_complete_command(0x8000_0002, 0x8000_0001, b"m");
        assert_eq!(command_code(&done), Some(TPM2_CC_SIGN_SEQUENCE_COMPLETE));
        assert_eq!(&done[10..18], &[0x80, 0, 0, 2, 0x80, 0, 0, 1]);
        // Two empty-password sessions of 9 bytes each.
        assert_eq!(&done[18..22], &18u32.to_be_bytes());
        assert_eq!(&done[22..26], &TPM2_RS_PW.to_be_bytes());
        assert_eq!(&done[31..35], &TPM2_RS_PW.to_be_bytes());
        assert_eq!(&done[40..], &[0, 1, b'm']);
    }

    #[test]
    fn signature_responses_are_parsed_and_others_refused() {
        let mut b = Writer::new();
        b.u32(0).u16(TPM2_ALG_MLDSA).tpm2b(&[7u8; 4627]);
        let sig = parse_ml_dsa_signature_response(&ok_response(TPM2_ST_SESSIONS, &b.finish()));
        assert_eq!(sig.unwrap(), vec![7u8; 4627]);
        let mut b = Writer::new();
        b.u32(0).u16(TPM2_ALG_ECDSA).u16(TPM2_ALG_SHA384);
        b.tpm2b(&[1u8; 47]).tpm2b(&[2u8; 48]);
        let rs = parse_sign_p384_response(&ok_response(TPM2_ST_SESSIONS, &b.finish())).unwrap();
        assert_eq!(rs[0], 0, "a short r is left-padded");
        assert_eq!(&rs[1..48], &[1u8; 47]);
        assert_eq!(&rs[48..], &[2u8; 48]);
        let mut b = Writer::new();
        b.u32(0).u16(TPM2_ALG_ECDSA).u16(TPM2_ALG_SHA256);
        b.tpm2b(&[1u8; 48]).tpm2b(&[2u8; 48]);
        assert!(parse_sign_p384_response(&ok_response(TPM2_ST_SESSIONS, &b.finish())).is_err());
        let mut b = Writer::new();
        b.u32(0).u16(TPM2_ALG_ECDSA).tpm2b(&[0u8; 8]);
        assert!(
            parse_ml_dsa_signature_response(&ok_response(TPM2_ST_SESSIONS, &b.finish())).is_err()
        );
    }

    #[test]
    fn constants_match_the_tcg_registry() {
        assert_eq!(TPM2_CC_CREATE_PRIMARY, 0x131);
        assert_eq!(TPM2_CC_SIGN, 0x15D);
        assert_eq!(TPM2_CC_QUOTE, 0x158);
        assert_eq!(TPM2_CC_ACTIVATE_CREDENTIAL, 0x147);
        assert_eq!(TPM2_CC_READ_PUBLIC, 0x173);
        assert_eq!(TPM2_CC_NV_READ, 0x14E);
        assert_eq!(TPM2_CC_NV_READ_PUBLIC, 0x169);
        assert_eq!(TPM2_CC_POLICY_SECRET, 0x151);
        assert_eq!(TPM2_CC_START_AUTH_SESSION, 0x176);
        assert_eq!(TPM2_GENERATED_VALUE, 0xFF544347);
        assert_eq!(TPM2_ST_ATTEST_QUOTE, 0x8018);
    }

    #[test]
    fn attestation_key_is_restricted_and_signing_key_is_not() {
        assert_ne!(ATTESTATION_KEY_ATTRIBUTES & TPMA_OBJECT_RESTRICTED, 0);
        assert_eq!(SIGNING_KEY_ATTRIBUTES & TPMA_OBJECT_RESTRICTED, 0);
        assert_eq!(SIGNING_KEY_ATTRIBUTES & TPMA_OBJECT_DECRYPT, 0);
        assert_eq!(AGREEMENT_KEY_ATTRIBUTES & TPMA_OBJECT_SIGN_ENCRYPT, 0);
    }

    #[test]
    fn different_labels_give_different_templates() {
        let a = ecc_p256_template(KeyRole::Signing, "a");
        let b = ecc_p256_template(KeyRole::Signing, "b");
        assert_ne!(a, b);
        assert_eq!(a, ecc_p256_template(KeyRole::Signing, "a"));
    }

    #[test]
    fn template_round_trips_through_the_parser() {
        let t = ecc_p256_template(KeyRole::Attestation, "ak");
        let p = parse_public(&t).unwrap();
        assert_eq!(p.alg, TPM2_ALG_ECC);
        assert_eq!(p.attributes, ATTESTATION_KEY_ATTRIBUTES);
        match p.key {
            PublicKey::EccP256 { x, scheme, .. } => {
                assert_eq!(x, label_unique("ak"));
                assert_eq!(scheme, TPM2_ALG_ECDSA);
            }
            _ => panic!("expected ECC P-256"),
        }
        assert_eq!(p.name().unwrap().len(), 34);
    }

    #[test]
    fn endorsement_templates_parse_as_their_key_types() {
        let rsa = parse_public(&ek_rsa2048_template()).unwrap();
        assert_eq!(rsa.attributes, EK_LOW_RANGE_ATTRIBUTES);
        assert_eq!(rsa.auth_policy, EK_POLICY);
        assert!(
            matches!(&rsa.key, PublicKey::Rsa { modulus, exponent: 0 } if modulus.len() == 256)
        );
        let p384 = parse_public(&ek_ecc_p384_template()).unwrap();
        assert_eq!(p384.name_alg, TPM2_ALG_SHA384);
        assert_eq!(p384.attributes, EK_HIGH_RANGE_ATTRIBUTES);
        assert_eq!(p384.symmetric, Some((TPM2_ALG_AES, 256, TPM2_ALG_CFB)));
        assert!(matches!(p384.key, PublicKey::EccP384 { .. }));
        assert_eq!(p384.name().unwrap().len(), 50);
        assert_eq!(&p384.name().unwrap()[..2], &TPM2_ALG_SHA384.to_be_bytes());
        let rsa3072 = parse_public(&ek_rsa3072_template()).unwrap();
        assert_eq!(rsa3072.name_alg, TPM2_ALG_SHA384);
        assert!(matches!(&rsa3072.key, PublicKey::Rsa { modulus, .. } if modulus.is_empty()));
        let ecc = parse_public(&ek_ecc_template()).unwrap();
        assert_eq!(ecc.attributes, EK_LOW_RANGE_ATTRIBUTES);
        assert!(ecc.p256_sec1().is_some() && ecc.p384_sec1().is_none());
    }

    #[test]
    fn password_activation_names_the_password_session_for_the_ek() {
        let cmd = activate_credential_password_command(0x8101_8001, 0x8000_0001, &[1, 2], &[3]);
        assert_eq!(command_code(&cmd), Some(TPM2_CC_ACTIVATE_CREDENTIAL));
        let pw = TPM2_RS_PW.to_be_bytes();
        let sessions = &cmd[18..];
        // Both sessions are the password session.
        assert_eq!(sessions.windows(4).filter(|w| *w == pw).count(), 2);
    }

    #[test]
    fn create_primary_command_is_framed() {
        let cmd = create_primary_command(&ecc_p256_template(KeyRole::Signing, "x"));
        let (tag, size, code) = header(&cmd);
        assert_eq!(tag, TPM2_ST_SESSIONS);
        assert_eq!(size as usize, cmd.len());
        assert_eq!(code, TPM2_CC_CREATE_PRIMARY);
    }

    #[test]
    fn a_refused_command_surfaces_its_code() {
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_NO_SESSIONS).u32(10).u32(0x902);
        assert_eq!(
            response_body(&resp.finish()).err(),
            Some(WireError::ResponseCode(0x902))
        );
    }

    #[test]
    fn quote_parser_refuses_non_tpm_data() {
        let mut a = Writer::new();
        a.u32(0x1234_5678).u16(TPM2_ST_ATTEST_QUOTE);
        assert!(parse_quote(&a.finish()).is_err());
    }

    #[test]
    fn quote_parser_reads_every_field() {
        let mut a = Writer::new();
        a.u32(TPM2_GENERATED_VALUE)
            .u16(TPM2_ST_ATTEST_QUOTE)
            .tpm2b(&[1, 2])
            .tpm2b(&[9; 32])
            .bytes(&7u64.to_be_bytes())
            .u32(1)
            .u32(2)
            .u8(1)
            .bytes(&5u64.to_be_bytes())
            .u32(1)
            .u16(TPM2_ALG_SHA256)
            .u8(3)
            .bytes(&DEFAULT_QUOTE_PCRS)
            .tpm2b(&[4; 32]);
        let q = parse_quote(&a.finish()).unwrap();
        assert_eq!(q.extra_data, vec![9; 32]);
        assert_eq!(q.clock, 7);
        assert!(q.safe);
        assert_eq!(
            q.pcr_selection,
            vec![(TPM2_ALG_SHA256, DEFAULT_QUOTE_PCRS.to_vec())]
        );
        assert_eq!(q.pcr_digest, vec![4; 32]);
    }

    #[test]
    fn quote_parser_refuses_trailing_bytes() {
        let mut a = Writer::new();
        a.u32(TPM2_GENERATED_VALUE)
            .u16(TPM2_ST_ATTEST_QUOTE)
            .tpm2b(&[])
            .tpm2b(&[])
            .bytes(&[0; 17])
            .bytes(&[0; 8])
            .u32(0)
            .tpm2b(&[])
            .u8(0);
        assert!(parse_quote(&a.finish()).is_err());
    }
}
