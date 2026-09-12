//! Windows TPM 2.0 backend for the [`crate::DeviceKey`] trait — the signing
//! counterpart to [`crate::backend_tpm`]'s decrypt-only `TpmDecapsulator`.
//!
//! # Why a third TPM module, not an extension of the other two
//!
//! Three TPM keys, three attribute sets, on purpose — a TPM key's attributes
//! are fixed at creation and a key that could both sign and decrypt would be
//! refused by any TPM that enforces the spec's "restricted or plain, not
//! both" posture correctly:
//!
//! - [`crate::backend_tpm::TpmDecapsulator`] — ECC P-256, `decrypt`,
//!   `TPM2_ALG_NULL` scheme (any key-exchange scheme), used only for
//!   `TPM2_ECDH_ZGen`. Never signs.
//! - `tenzro-tee`'s `tpm_tbs_windows` — RSA-2048, `sign`, `RSASSA`/SHA-256,
//!   derives a *fixed-label* root secret for network validator identity.
//!   Never handles a caller-supplied digest.
//! - This module — ECC P-256, `sign`, `ECDSA`/SHA-256, signs an
//!   arbitrary caller-supplied prehash, matching [`crate::backend_se`]'s
//!   Apple signing key exactly (same curve, same raw `r ‖ s` output shape)
//!   so [`crate::DeviceKey`] means the same thing on both platforms.
//!
//! The wire encoding below is the union of the other two files' proven
//! pieces — `backend_tpm.rs`'s ECC `TPM2_CreatePrimary` shape with `sign`
//! attributes and an `ECDSA` scheme in place of its `decrypt`/`NULL` pair,
//! and `tpm_tbs_windows.rs`'s `TPM2_Sign`/null-ticket call, generalised
//! from a fixed RSA response to ECDSA's two-component signature. Every
//! numeric constant is cross-checked against the same
//! `tpm2-software/tpm2-tss` header both of those files pin against.
//!
//! # `wrap_secret` / `unwrap_secret`
//!
//! There is no Rust-side single-recipient ECIES primitive in this crate to
//! reuse: [`crate::envelope::EnvelopeBuilder`] is deliberately **un**-usable
//! with fewer than two recipients ("never a single recipient" — see its
//! module docs), which is right for [`crate::sealed::SealedSecret`]'s
//! survive-hardware-loss goal and wrong for `DeviceKey::wrap_secret`'s
//! contract (one key, no operator-supplied recovery slot to fill). Apple's
//! backend sidesteps this the same way — its `wrap_secret`/`unwrap_secret`
//! are opaque CryptoKit calls, never routed through this crate's envelope
//! code either. So this implements RFC 9180 HPKE base-mode single-recipient
//! sealing directly from [`crate::hpke`]'s already RFC-vector-tested
//! primitives (`extract_and_expand`, `key_schedule_base`) — an ephemeral
//! P-256 keypair for encapsulation, [`crate::backend_tpm::TpmDecapsulator`]'s
//! existing `raw_dh` for decapsulation, ChaCha20Poly1305 for the AEAD.
//!
//! # Key derivation, not persistence
//!
//! Same property as the other two files: `TPM2_CreatePrimary` under the
//! endorsement hierarchy with a fixed template is a deterministic function
//! of the TPM's own seed, so `open()` after `create()` (in a fresh process,
//! after a reboot, forever) re-derives the identical key — nothing is
//! written to disk, and there is no `EvictControl` handle to manage or lose.

use std::ffi::c_void;
use std::ptr;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, Tbsi_Context_Create,
    Tbsip_Context_Close, Tbsip_Submit_Command,
};

use crate::backend_tpm::TpmDecapsulator;
use crate::envelope::Decapsulator;
use crate::hpke::{KemId, extract_and_expand, key_schedule_base};
use crate::{Attestation, DeviceKey, DeviceKeyError, DevicePublicKey, DeviceSignature, Result};

/// Domain separation for this module's HPKE `info` — distinct from
/// `envelope.rs`'s own `info` strings so a ciphertext produced by one path
/// can never be mistaken for (or decrypt under) the other.
const WRAP_INFO: &[u8] = b"tenzro-device-key/backend_tpm_sign/wrap_secret/v1";

// --- TPM2 constants, cross-checked against tss2_tpm2_types.h (same header
// backend_tpm.rs and tpm_tbs_windows.rs pin against). ---

const TPM2_ST_SESSIONS: u16 = 0x8002;
const TPM2_ST_HASHCHECK: u16 = 0x8024;

const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM2_CC_SIGN: u32 = 0x0000_015D;

const TPM2_RH_ENDORSEMENT: u32 = 0x4000_000B;
const TPM2_RH_NULL: u32 = 0x4000_0007;
const TPM2_RS_PW: u32 = 0x4000_0009;

const TPM2_ALG_ECC: u16 = 0x0023;
const TPM2_ALG_SHA256: u16 = 0x000B;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_ALG_ECDSA: u16 = 0x0018;
const TPM2_ECC_NIST_P256: u16 = 0x0003;

const TPMA_OBJECT_FIXEDTPM: u32 = 0x0000_0002;
const TPMA_OBJECT_FIXEDPARENT: u32 = 0x0000_0010;
const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x0000_0020;
const TPMA_OBJECT_USERWITHAUTH: u32 = 0x0000_0040;
/// SET, unlike `backend_tpm.rs`'s decrypt key: this key's private half may
/// only sign, never decrypt/ECDH. `restricted` stays CLEAR, matching the
/// other two files, so `TPM2_Sign` accepts an externally-computed digest via
/// the null-ticket path without needing a validation ticket from a
/// restricted key's own hashing.
const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 0x0004_0000;
const OBJECT_ATTRIBUTES: u32 = TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH
    | TPMA_OBJECT_SIGN_ENCRYPT;

fn tpm_err(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Enclave(msg.into())
}

struct TbsContext(*mut c_void);

impl TbsContext {
    fn open() -> Result<Self> {
        let params = TBS_CONTEXT_PARAMS2 {
            version: 2,
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 0b100 },
        };
        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: identical reasoning to backend_tpm.rs's TbsContext::open —
        // `params` outlives the call, `handle` is a valid out-pointer, and
        // TBS_CONTEXT_PARAMS2 shares its leading `version: u32` field with
        // the narrower type the FFI signature declares.
        let rc = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut handle,
            )
        };
        if rc != TBS_SUCCESS || handle.is_null() {
            return Err(tpm_err(format!("Tbsi_Context_Create failed: 0x{rc:08X}")));
        }
        Ok(Self(handle))
    }

    fn submit(&self, command: &[u8]) -> Result<Vec<u8>> {
        let mut result = vec![0u8; 4096];
        let mut result_len: u32 = result.len() as u32;
        // SAFETY: `self.0` is a live context from a successful `open()`;
        // `command`/`result` are valid for their stated lengths for the
        // call's duration; `result_len` is a valid in/out length pointer.
        let rc = unsafe {
            Tbsip_Submit_Command(
                self.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                result.as_mut_ptr(),
                &mut result_len,
            )
        };
        if rc != TBS_SUCCESS {
            return Err(tpm_err(format!("Tbsip_Submit_Command failed: 0x{rc:08X}")));
        }
        result.truncate(result_len as usize);
        Ok(result)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is either null (skipped) or a context this
            // struct solely owns, from a successful `open()`.
            unsafe {
                Tbsip_Context_Close(self.0);
            }
        }
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn tpm2b(&mut self, bytes: &[u8]) -> &mut Self {
        self.u16(bytes.len() as u16);
        self.0.extend_from_slice(bytes);
        self
    }
    fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Cursor-based big-endian reader — walks in declaration order rather than
/// fixed offsets, since `TPMS_SIGNATURE_ECC`'s two variable-length fields
/// shift everything after the first.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn u16(&mut self) -> Result<u16> {
        let v = self
            .bytes
            .get(self.pos..self.pos + 2)
            .map(|s| u16::from_be_bytes(s.try_into().unwrap()))
            .ok_or_else(|| tpm_err("truncated TPM2 response"))?;
        self.pos += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32> {
        let v = self
            .bytes
            .get(self.pos..self.pos + 4)
            .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
            .ok_or_else(|| tpm_err("truncated TPM2 response"))?;
        self.pos += 4;
        Ok(v)
    }
    fn tpm2b(&mut self) -> Result<Vec<u8>> {
        let len = self.u16()? as usize;
        let v = self
            .bytes
            .get(self.pos..self.pos + len)
            .map(|s| s.to_vec())
            .ok_or_else(|| tpm_err("truncated TPM2 response"))?;
        self.pos += len;
        Ok(v)
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.bytes.len() {
            return Err(tpm_err("truncated TPM2 response"));
        }
        self.pos += n;
        Ok(())
    }
}

fn check_response_code(bytes: &[u8]) -> Result<()> {
    let mut r = Reader::new(bytes);
    r.skip(6)?;
    let code = r.u32()?;
    if code != 0 {
        return Err(tpm_err(format!(
            "TPM refused the command: response code 0x{code:08X}"
        )));
    }
    Ok(())
}

fn write_empty_pw_session(w: &mut Writer) {
    let mut session = Writer::new();
    session.u32(TPM2_RS_PW);
    session.tpm2b(&[]); // nonce
    session.0.push(0); // sessionAttributes
    session.tpm2b(&[]); // hmac
    let session = session.finish();
    w.u32(session.len() as u32);
    w.0.extend_from_slice(&session);
}

/// `TPM2_CreatePrimary` in the endorsement hierarchy: ECC P-256, sign-only,
/// `ECDSA`/SHA-256 scheme (fixed, unlike the decrypt key's `NULL` scheme —
/// a signing key's scheme is not "any", `TPM2_Sign` needs one committed at
/// creation). Returns the transient handle plus the public point.
fn create_primary_ecc_sign(ctx: &TbsContext) -> Result<(u32, [u8; 32], [u8; 32])> {
    let response = ctx.submit(&build_create_primary_command())?;
    parse_create_primary_response(&response)
}

fn build_create_primary_command() -> Vec<u8> {
    let mut body = Writer::new();
    body.u32(TPM2_RH_ENDORSEMENT);
    write_empty_pw_session(&mut body);

    let mut sensitive_create = Writer::new();
    sensitive_create.tpm2b(&[]); // userAuth
    sensitive_create.tpm2b(&[]); // data
    body.tpm2b(&sensitive_create.finish());

    let mut public = Writer::new();
    public.u16(TPM2_ALG_ECC); // type
    public.u16(TPM2_ALG_SHA256); // nameAlg
    public.u32(OBJECT_ATTRIBUTES);
    public.tpm2b(&[]); // authPolicy
    // TPMS_ECC_PARMS
    public.u16(TPM2_ALG_NULL); // symmetric — a signing key uses none
    public.u16(TPM2_ALG_ECDSA); // scheme.scheme — fixed, not NULL
    public.u16(TPM2_ALG_SHA256); // scheme.details.hashAlg (ECDSA carries one)
    public.u16(TPM2_ECC_NIST_P256); // curveID
    public.u16(TPM2_ALG_NULL); // kdf
    public.tpm2b(&[]); // unique.x (TPM-generated)
    public.tpm2b(&[]); // unique.y (TPM-generated)
    body.tpm2b(&public.finish());

    body.tpm2b(&[]); // outsideInfo
    body.u32(0); // creationPCR count = 0

    let body = body.finish();
    let mut cmd = Writer::new();
    cmd.u16(TPM2_ST_SESSIONS);
    cmd.u32(10 + body.len() as u32);
    cmd.u32(TPM2_CC_CREATE_PRIMARY);
    cmd.0.extend_from_slice(&body);
    cmd.finish()
}

fn parse_create_primary_response(response: &[u8]) -> Result<(u32, [u8; 32], [u8; 32])> {
    check_response_code(response)?;
    let mut r = Reader::new(response);
    r.skip(10)?; // tag, size, responseCode
    let handle = r.u32()?;
    r.skip(4)?; // parameterSize — unchecked, self-delimiting fields follow
    r.u16()?; // TPM2B_PUBLIC outer size — unused, walked structurally
    r.u16()?; // type
    r.u16()?; // nameAlg
    r.u32()?; // objectAttributes
    r.tpm2b()?; // authPolicy
    r.u16()?; // symmetric
    r.u16()?; // scheme.scheme
    r.u16()?; // scheme.details.hashAlg
    r.u16()?; // curveID
    r.u16()?; // kdf
    let x = r.tpm2b()?;
    let y = r.tpm2b()?;
    if x.len() != 32 || y.len() != 32 {
        return Err(tpm_err(format!(
            "TPM returned a P-256 point of the wrong size: x={} y={}",
            x.len(),
            y.len()
        )));
    }
    let mut xa = [0u8; 32];
    let mut ya = [0u8; 32];
    xa.copy_from_slice(&x);
    ya.copy_from_slice(&y);
    Ok((handle, xa, ya))
}

/// `TPM2_Sign` over `digest` via the null-ticket path — correct here for the
/// same reason `tpm_tbs_windows.rs` uses it: this key is not `restricted`,
/// so an externally-computed digest needs no validation ticket.
fn sign(ctx: &TbsContext, key_handle: u32, digest: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let response = ctx.submit(&build_sign_command(key_handle, digest))?;
    parse_sign_response(&response)
}

fn build_sign_command(key_handle: u32, digest: &[u8; 32]) -> Vec<u8> {
    let mut body = Writer::new();
    body.u32(key_handle);
    write_empty_pw_session(&mut body);

    body.tpm2b(digest);
    // inScheme: TPMT_SIG_SCHEME
    body.u16(TPM2_ALG_ECDSA);
    body.u16(TPM2_ALG_SHA256);
    // validation: TPMT_TK_HASHCHECK, null ticket
    body.u16(TPM2_ST_HASHCHECK);
    body.u32(TPM2_RH_NULL);
    body.tpm2b(&[]);

    let body = body.finish();
    let mut cmd = Writer::new();
    cmd.u16(TPM2_ST_SESSIONS);
    cmd.u32(10 + body.len() as u32);
    cmd.u32(TPM2_CC_SIGN);
    cmd.0.extend_from_slice(&body);
    cmd.finish()
}

/// `TPMT_SIGNATURE{ sigAlg(2) TPMS_SIGNATURE_ECC{ hash(2) signatureR:
/// TPM2B_ECC_PARAMETER signatureS: TPM2B_ECC_PARAMETER } }` — two
/// independent length-prefixed fields, unlike RSA's single flat blob, so
/// this needs its own parser rather than reusing `tpm_tbs_windows.rs`'s.
fn parse_sign_response(response: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    check_response_code(response)?;
    let mut r = Reader::new(response);
    r.skip(10)?; // tag, size, responseCode
    r.skip(4)?; // parameterSize
    r.u16()?; // sigAlg
    r.u16()?; // hash
    let sig_r = r.tpm2b()?;
    let sig_s = r.tpm2b()?;
    Ok((sig_r, sig_s))
}

/// Left-pads a TPM-returned ECC coordinate/scalar to 32 bytes. TPMs
/// minimally encode `TPM2B_ECC_PARAMETER`, so a value with a leading zero
/// byte can come back shorter than 32 — pad rather than reject, and refuse
/// anything actually oversized as a genuine malformed response.
fn pad32(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() > 32 {
        return Err(tpm_err(format!(
            "TPM returned a P-256 scalar of {} bytes, more than 32",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

/// Whether TBS can reach a TPM 2.0 device — same probe as
/// [`crate::backend_tpm::available`], duplicated rather than shared per
/// this crate's own convention of small, self-contained TPM modules.
pub fn available() -> bool {
    TbsContext::open().is_ok()
}

fn label_dir(label: &str) -> Result<()> {
    // The signing key is fully TPM-derived (deterministic CreatePrimary) and
    // needs no on-disk state of its own — `label` only has to be non-empty
    // so a caller cannot silently create/open "the" key under an empty name
    // that every other unlabelled caller would also collide on.
    if label.is_empty() {
        return Err(tpm_err("device key label must not be empty"));
    }
    Ok(())
}

/// One TPM-resident ECC P-256 signing key. Every method re-derives the same
/// deterministic primary rather than caching a handle across calls — TPM
/// object handles are scoped to the `TbsContext` they were created under,
/// and a `TpmSignKey` living longer than one signing operation would
/// otherwise need to keep that context (and its Windows handle) open for no
/// benefit, exactly the same tradeoff `TpmDecapsulator::raw_dh` makes.
pub struct TpmSignKey {
    label: String,
}

impl DeviceKey for TpmSignKey {
    fn label(&self) -> &str {
        &self.label
    }

    fn public_key(&self) -> Result<DevicePublicKey> {
        let ctx = TbsContext::open()?;
        let (_, x, y) = create_primary_ecc_sign(&ctx)?;
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&x);
        out[32..].copy_from_slice(&y);
        Ok(out)
    }

    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<DeviceSignature> {
        let ctx = TbsContext::open()?;
        let (handle, _, _) = create_primary_ecc_sign(&ctx)?;
        let (r, s) = sign(&ctx, handle, hash)?;
        let r = pad32(&r)?;
        let s = pad32(&s)?;
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        Ok(out)
    }

    fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>> {
        if secret.is_empty() {
            return Err(tpm_err("wrap_secret: empty secret"));
        }
        // The decrypt-only TPM key, not this signing key — wrapping targets
        // a key that can ECDH, and a sign-only TPM key refuses
        // TPM2_ECDH_ZGen at the hardware level. Only the public half is
        // needed to encapsulate, so opening it here (rather than requiring
        // the caller to pass a `Recipient`) keeps this call one-argument,
        // matching the trait.
        let pk_r = TpmDecapsulator::open()?.recipient().public_key().to_vec();
        if pk_r.len() != 65 || pk_r[0] != 0x04 {
            return Err(tpm_err("wrap_secret: unexpected recipient key encoding"));
        }

        // Encapsulate: an ephemeral P-256 keypair, ECDH'd against the TPM
        // key's PUBLIC half in software — no hardware operation on this
        // side, matching RFC 9180's `Encap`.
        let eph = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
        let enc = eph.public_key().to_sec1_bytes().to_vec();
        let pk_r_point = p256::PublicKey::from_sec1_bytes(&pk_r)
            .map_err(|_| tpm_err("wrap_secret: malformed recipient key"))?;
        let dh = eph.diffie_hellman(&pk_r_point);
        let dh_bytes = dh.raw_secret_bytes(); // x-coordinate only, 32 bytes

        let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
        kem_context.extend_from_slice(&enc);
        kem_context.extend_from_slice(&pk_r);
        let shared_secret = extract_and_expand(KemId::DhkemP256, dh_bytes.as_slice(), &kem_context)
            .map_err(|e| tpm_err(format!("wrap_secret: {e}")))?;
        let (key, nonce) = key_schedule_base(KemId::DhkemP256, &shared_secret, WRAP_INFO)
            .map_err(|e| tpm_err(format!("wrap_secret: {e}")))?;

        let cipher = ChaCha20Poly1305::new((&*key).into());
        let ct = cipher
            .encrypt((&*nonce).into(), Payload { msg: secret, aad: &enc })
            .map_err(|_| tpm_err("wrap_secret: AEAD seal failed"))?;

        // Wire form: enc (65) || ciphertext-with-tag. `enc` is public (it's
        // the sender's ephemeral key, not a secret) and is exactly what
        // `unwrap_secret` needs to re-derive the same shared secret.
        let mut out = Vec::with_capacity(enc.len() + ct.len());
        out.extend_from_slice(&enc);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap_secret(&self, ciphertext: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if ciphertext.len() <= 65 {
            return Err(tpm_err("unwrap_secret: ciphertext too short to carry `enc`"));
        }
        let (enc, ct) = ciphertext.split_at(65);
        if enc[0] != 0x04 {
            return Err(tpm_err("unwrap_secret: malformed `enc`"));
        }

        let decap = TpmDecapsulator::open()?;
        let pk_r = decap.recipient().public_key().to_vec();
        let dh = decap
            .raw_dh(enc)
            .map_err(|e| tpm_err(format!("unwrap_secret: {e}")))?;

        let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);
        let shared_secret = extract_and_expand(KemId::DhkemP256, dh.as_slice(), &kem_context)
            .map_err(|e| tpm_err(format!("unwrap_secret: {e}")))?;
        let (key, nonce) = key_schedule_base(KemId::DhkemP256, &shared_secret, WRAP_INFO)
            .map_err(|e| tpm_err(format!("unwrap_secret: {e}")))?;

        let cipher = ChaCha20Poly1305::new((&*key).into());
        let pt = cipher
            .decrypt((&*nonce).into(), Payload { msg: ct, aad: enc })
            .map_err(|_| tpm_err("unwrap_secret: AEAD open failed (tampered or wrong key)"))?;
        Ok(zeroize::Zeroizing::new(pt))
    }

    fn attest(&self) -> Result<Attestation> {
        // TPM2_CreatePrimary's creation ticket/hash would let a verifier
        // confirm this key really came from TPM2_CreatePrimary rather than
        // trusting the caller — not wired up yet, so this stays honest
        // about not proving anything, same call `backend_se.rs` makes for
        // the SEP for the same reason.
        Err(DeviceKeyError::AttestationUnsupported)
    }
}

pub fn open(label: &str) -> Result<Box<dyn DeviceKey>> {
    label_dir(label)?;
    if !available() {
        return Err(DeviceKeyError::NotFound(label.to_string()));
    }
    Ok(Box::new(TpmSignKey {
        label: label.to_string(),
    }))
}

/// Create a new key under `label`. Deterministic derivation means this and
/// [`open`] are the same operation — kept as a distinct name only to match
/// [`crate::DeviceKey`]'s cross-platform `create`/`open` split, where the
/// Apple backend's two calls really do differ (one enrolls new SEP state).
pub fn create(label: &str) -> Result<Box<dyn DeviceKey>> {
    label_dir(label)?;
    if !available() {
        return Err(tpm_err("no TPM 2.0 device reachable on this machine"));
    }
    // Prove the primary actually derives before handing back a key that
    // looks usable and is not — mirrors backend_se::open's self-test.
    let ctx = TbsContext::open()?;
    create_primary_ecc_sign(&ctx)?;
    Ok(Box::new(TpmSignKey {
        label: label.to_string(),
    }))
}

/// Idempotent no-op: there is nothing to delete. The key is a pure function
/// of the TPM's own seed plus this module's fixed template, not on-disk
/// state — "deleting" it would mean nothing survives to `open()` after
/// anyway, since `open`/`create` never persist and always re-derive.
pub fn delete(_label: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn constants_match_the_tcg_header() {
        assert_eq!(TPM2_ST_SESSIONS, 0x8002);
        assert_eq!(TPM2_ST_HASHCHECK, 0x8024);
        assert_eq!(TPM2_CC_CREATE_PRIMARY, 0x0000_0131);
        assert_eq!(TPM2_CC_SIGN, 0x0000_015D);
        assert_eq!(TPM2_RH_ENDORSEMENT, 0x4000_000B);
        assert_eq!(TPM2_RH_NULL, 0x4000_0007);
        assert_eq!(TPM2_RS_PW, 0x4000_0009);
        assert_eq!(TPM2_ALG_ECC, 0x0023);
        assert_eq!(TPM2_ALG_SHA256, 0x000B);
        assert_eq!(TPM2_ALG_NULL, 0x0010);
        assert_eq!(TPM2_ALG_ECDSA, 0x0018);
        assert_eq!(TPM2_ECC_NIST_P256, 0x0003);
    }

    #[test]
    fn object_attributes_are_sign_not_decrypt_and_not_restricted() {
        assert_eq!(
            OBJECT_ATTRIBUTES,
            0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000,
            "fixedtpm | fixedparent | sensitivedataorigin | userwithauth | sign"
        );
        assert_eq!(OBJECT_ATTRIBUTES & 0x0001_0000, 0, "restricted must be clear");
        assert_eq!(
            OBJECT_ATTRIBUTES & 0x0002_0000,
            0,
            "decrypt must be clear — this key never does TPM2_ECDH_ZGen"
        );
    }

    #[test]
    fn create_primary_command_carries_a_fixed_ecdsa_scheme_not_null() {
        let cmd = build_create_primary_command();
        let mut r = Reader::new(&cmd);
        r.skip(10).unwrap(); // header
        r.u32().unwrap(); // hierarchy
        let auth_size = r.u32().unwrap();
        r.skip(auth_size as usize).unwrap();
        r.tpm2b().unwrap(); // inSensitive
        let _in_public_len = r.u16().unwrap();
        assert_eq!(r.u16().unwrap(), TPM2_ALG_ECC, "type");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_SHA256, "nameAlg");
        assert_eq!(r.u32().unwrap(), OBJECT_ATTRIBUTES, "objectAttributes");
        assert_eq!(r.tpm2b().unwrap(), Vec::<u8>::new(), "authPolicy");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_NULL, "symmetric");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_ECDSA, "scheme — fixed, not NULL");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_SHA256, "scheme hashAlg");
        assert_eq!(r.u16().unwrap(), TPM2_ECC_NIST_P256, "curveID");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_NULL, "kdf");
        assert_eq!(r.tpm2b().unwrap(), Vec::<u8>::new(), "unique.x");
        assert_eq!(r.tpm2b().unwrap(), Vec::<u8>::new(), "unique.y");
    }

    #[test]
    fn sign_command_carries_ecdsa_scheme() {
        let handle = 0x8000_0001u32;
        let digest = [0x33u8; 32];
        let cmd = build_sign_command(handle, &digest);
        let mut r = Reader::new(&cmd);
        r.skip(10).unwrap();
        assert_eq!(r.u32().unwrap(), handle, "key handle");
        let auth_size = r.u32().unwrap();
        r.skip(auth_size as usize).unwrap();
        assert_eq!(r.tpm2b().unwrap(), digest, "digest, verbatim");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_ECDSA, "inScheme.scheme");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_SHA256, "inScheme.hashAlg");
        assert_eq!(r.u16().unwrap(), TPM2_ST_HASHCHECK, "validation.tag");
        assert_eq!(r.u32().unwrap(), TPM2_RH_NULL, "validation.hierarchy");
        assert_eq!(r.tpm2b().unwrap(), Vec::<u8>::new(), "null ticket digest");
    }

    #[test]
    fn sign_response_parses_two_independent_fields() {
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_SESSIONS);
        resp.u32(0);
        resp.u32(0); // success
        resp.u32(0); // parameterSize — unchecked
        resp.u16(TPM2_ALG_ECDSA); // sigAlg
        resp.u16(TPM2_ALG_SHA256); // hash
        resp.tpm2b(&[0x11u8; 32]); // signatureR
        resp.tpm2b(&[0x22u8; 31]); // signatureS, deliberately short
        let (r, s) = parse_sign_response(&resp.finish()).unwrap();
        assert_eq!(r, vec![0x11u8; 32]);
        assert_eq!(s, vec![0x22u8; 31]);
        assert_eq!(pad32(&s).unwrap()[0], 0, "short scalar left-padded with zero");
        assert_eq!(&pad32(&s).unwrap()[1..], &[0x22u8; 31][..]);
    }

    #[test]
    fn pad32_refuses_an_oversized_scalar() {
        assert!(pad32(&[0u8; 33]).is_err());
    }

    #[test]
    fn empty_label_is_refused() {
        assert!(label_dir("").is_err());
        assert!(open("").is_err());
        assert!(create("").is_err());
    }

    #[test]
    fn availability_is_reported_rather_than_assumed() {
        let _ = available();
    }

    /// `wrap_secret`/`unwrap_secret` round-trip, and a tampered ciphertext is
    /// refused — the same two properties `backend_se.rs`'s
    /// `wrapped_secret_survives_reopen`/`tampered_ciphertext_is_refused`
    /// check for the Apple backend, on real hardware only.
    #[test]
    fn wrap_unwrap_round_trips_and_rejects_tampering() {
        if !available() {
            return;
        }
        let key = create("tpm-wrap-self-test").expect("create");
        let secret = b"a secret worth protecting";
        let ct = key.wrap_secret(secret).expect("wrap_secret");
        let pt = key.unwrap_secret(&ct).expect("unwrap_secret");
        assert_eq!(&pt[..], secret);

        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(
            key.unwrap_secret(&tampered).is_err(),
            "AEAD accepted a tampered ciphertext"
        );
    }

    /// Digest signed against a **known-answer TPM sign key** would need real
    /// hardware; the shape this crate's own `backend_se.rs` tests check —
    /// that a produced signature verifies as plain ECDSA-P256-SHA256 against
    /// the same key's own `public_key()` — is exercised only when a TPM is
    /// actually reachable, same convention as `backend_tpm.rs`'s tests.
    #[test]
    fn round_trip_signs_and_verifies_on_real_hardware_if_present() {
        if !available() {
            return;
        }
        let key = create("tpm-sign-self-test").expect("create");
        let pk = key.public_key().expect("public_key");
        let msg = b"machine sounds guitar rig device key self-test";
        let digest: [u8; 32] = Sha256::digest(msg).into();
        let sig = key.sign_prehash(&digest).expect("sign_prehash");

        use p256::ecdsa::signature::Verifier;
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&pk);
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).expect("sec1 pubkey");
        let s = p256::ecdsa::Signature::from_slice(&sig).expect("r||s");
        vk.verify(msg, &s)
            .expect("signature must verify as plain ECDSA-P256-SHA256");
    }
}
