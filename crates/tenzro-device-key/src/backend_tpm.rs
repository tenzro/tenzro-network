//! Windows TPM 2.0 backend for [`crate::sealed::SealedSecret`]'s hardware
//! [`Decapsulator`] — the Windows counterpart to [`crate::backend_se`]'s
//! `EnclaveDecapsulator`.
//!
//! # Why a TPM here, not the passkey/DeviceKey path
//!
//! Tenzro keeps three identity roots separate: human identity on passkeys,
//! machine identity on a TPM or the Apple Secure Enclave, network security on
//! TEE attestation. A sealed wallet keystore password is machine-bound, not
//! human-bound — losing the machine should not be recoverable by a passkey
//! elsewhere, and a human is not present every time the node unwraps it on
//! boot. That makes the TPM, not `backend::open`'s passkey-adjacent
//! `DeviceKey`, the correct Windows root for it.
//!
//! # Why this is a second, independent TPM module rather than reusing
//! `tenzro-tee::tpm_tbs_windows`
//!
//! That module derives a **signing** identity (RSA, endorsement hierarchy,
//! `TPM2_Sign`) for network-facing validator identity — a different concern
//! from sealing a local secret, per the split above. Following this crate's
//! own convention (`backend_se.rs` talks to CryptoKit directly rather than
//! going through `tenzro-secure-enclave`), this stays self-contained rather
//! than adding a cross-crate dependency for what is, here, a different key
//! (ECC, decrypt-only) doing a different operation (`TPM2_ECDH_ZGen`, not
//! `TPM2_Sign`). The TBS plumbing is small enough that duplicating it costs
//! less than the coupling would.
//!
//! # The operation
//!
//! HPKE decapsulation over `DHKEM(P-256, HKDF-SHA256)` needs exactly one
//! hardware operation: a raw ECDH between this device's private key and a
//! peer's ephemeral public point, producing the shared point's x-coordinate.
//! `TPM2_ECDH_ZGen` is that operation, done without the private key ever
//! leaving the TPM. Every numeric constant and wire structure below is
//! cross-checked against `tpm2-software/tpm2-tss`'s own
//! `include/tss2/tss2_tpm2_types.h`, the same source `tpm_tbs_windows.rs`
//! pins against, plus `google/go-tpm`'s `encodeECDHZGen`/`decodeECDHZGen` for
//! the command's exact byte layout (that header declares the structures but
//! not the command's wire framing).
//!
//! # Key derivation, not persistence
//!
//! Like the signing identity in `tpm_tbs_windows.rs`, this key is not stored
//! anywhere — `TPM2_CreatePrimary` under the endorsement hierarchy with a
//! fixed template is a deterministic function of the TPM's own seed, so the
//! same public key (and the ability to decapsulate what was sealed to it)
//! comes back every time without an `EvictControl` persistent handle to
//! manage or lose.

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, Tbsi_Context_Create,
    Tbsip_Context_Close, Tbsip_Submit_Command,
};
use zeroize::Zeroizing;

use crate::envelope::{Decapsulator, Domain, EnvelopeError, Recipient};
use crate::hpke::KemId;
use crate::{DeviceKeyError, Result};

// --- TPM2 constants, cross-checked against tss2_tpm2_types.h. ---

const TPM2_ST_SESSIONS: u16 = 0x8002;
const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM2_CC_ECDH_ZGEN: u32 = 0x0000_0154;
const TPM2_RH_ENDORSEMENT: u32 = 0x4000_000B;
const TPM2_RS_PW: u32 = 0x4000_0009;
const TPM2_ALG_ECC: u16 = 0x0023;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_ECC_NIST_P256: u16 = 0x0003;

const TPMA_OBJECT_FIXEDTPM: u32 = 0x0000_0002;
const TPMA_OBJECT_FIXEDPARENT: u32 = 0x0000_0010;
const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x0000_0020;
const TPMA_OBJECT_USERWITHAUTH: u32 = 0x0000_0040;
/// SET, not the RSA signing key's `sign`: this key's private half may only
/// decrypt/ECDH, never sign. `restricted` is deliberately CLEAR — matches
/// the signing key's own non-restricted choice, for the same reason:
/// `TPM2_ECDH_ZGen` on a non-restricted key needs no session-bound ticket.
const TPMA_OBJECT_DECRYPT: u32 = 0x0002_0000;
const OBJECT_ATTRIBUTES: u32 = TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH
    | TPMA_OBJECT_DECRYPT;

fn tpm_err(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Enclave(msg.into())
}

struct TbsContext(*mut c_void);

impl TbsContext {
    fn open() -> Result<Self> {
        let params = TBS_CONTEXT_PARAMS2 {
            version: 2, // TPM_VERSION_20
            Anonymous: TBS_CONTEXT_PARAMS2_0 {
                asUINT32: 0b100, // includeTpm20 = 1
            },
        };
        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: `params` lives on the stack for the call's duration and is
        // reinterpreted as the narrower `TBS_CONTEXT_PARAMS` the FFI
        // signature declares — sound because both start with the same
        // `version: u32` field and TBS reads that before anything past it.
        // `handle` is a valid out-pointer.
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
    /// A `TPM2B_*` field: a two-byte length prefix followed by that many bytes.
    fn tpm2b(&mut self, bytes: &[u8]) -> &mut Self {
        self.u16(bytes.len() as u16);
        self.0.extend_from_slice(bytes);
        self
    }
    fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Cursor-based big-endian reader. A response's field offsets shift with
/// every variable-length field ahead of them (`authPolicy`, `unique`'s x/y),
/// so this walks the structure in declaration order rather than indexing
/// fixed byte offsets the way `tpm_tbs_windows.rs` can for its fixed-shape
/// responses.
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
    /// A `TPM2B_*` field: reads its length prefix, then that many bytes.
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
    r.skip(6)?; // tag, size
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

/// `TPM2_CreatePrimary` in the endorsement hierarchy: ECC P-256,
/// decrypt-only, `TPM2_ALG_NULL` scheme/kdf so any key-exchange command
/// (just `TPM2_ECDH_ZGen`, here) may use it. Returns the transient object
/// handle plus its public point — both flushed when `ctx` closes.
fn create_primary_ecc(ctx: &TbsContext) -> Result<(u32, [u8; 32], [u8; 32])> {
    let response = ctx.submit(&build_create_primary_ecc_command())?;
    parse_create_primary_ecc_response(&response)
}

fn build_create_primary_ecc_command() -> Vec<u8> {
    let mut body = Writer::new();
    body.u32(TPM2_RH_ENDORSEMENT);
    write_empty_pw_session(&mut body);

    let mut sensitive_create = Writer::new();
    sensitive_create.tpm2b(&[]); // userAuth
    sensitive_create.tpm2b(&[]); // data
    body.tpm2b(&sensitive_create.finish());

    let mut public = Writer::new();
    public.u16(TPM2_ALG_ECC); // type
    public.u16(0x000B); // nameAlg = TPM2_ALG_SHA256
    public.u32(OBJECT_ATTRIBUTES);
    public.tpm2b(&[]); // authPolicy
    // TPMS_ECC_PARMS
    public.u16(TPM2_ALG_NULL); // symmetric — not a restricted decryption key
    public.u16(TPM2_ALG_NULL); // scheme — any key-exchange scheme, incl. plain ECDH
    public.u16(TPM2_ECC_NIST_P256); // curveID
    public.u16(TPM2_ALG_NULL); // kdf
    // unique: TPMS_ECC_POINT{x, y} — TWO tpm2b fields, both empty (TPM-generated).
    // Getting this wrong (writing one tpm2b, as the RSA template's single
    // TPM2B_PUBLIC_KEY_RSA `unique` does) would silently misalign every
    // field the TPM itself fills in on top of this template.
    public.tpm2b(&[]); // unique.x
    public.tpm2b(&[]); // unique.y
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

fn parse_create_primary_ecc_response(response: &[u8]) -> Result<(u32, [u8; 32], [u8; 32])> {
    check_response_code(response)?;
    let mut r = Reader::new(response);
    r.skip(10)?; // tag, size, responseCode
    let handle = r.u32()?;
    r.skip(4)?; // parameterSize — unchecked, the tpm2b fields below are self-delimiting
    r.u16()?; // TPM2B_PUBLIC's own outer size — unused, walked structurally instead
    r.u16()?; // type (already known: ECC)
    r.u16()?; // nameAlg
    r.u32()?; // objectAttributes
    r.tpm2b()?; // authPolicy
    r.u16()?; // symmetric
    r.u16()?; // scheme
    r.u16()?; // curveID
    r.u16()?; // kdf
    let x = r.tpm2b()?;
    let y = r.tpm2b()?;
    let mut xa = [0u8; 32];
    let mut ya = [0u8; 32];
    if x.len() != 32 || y.len() != 32 {
        return Err(tpm_err(format!(
            "TPM returned a P-256 point of the wrong size: x={} y={}",
            x.len(),
            y.len()
        )));
    }
    xa.copy_from_slice(&x);
    ya.copy_from_slice(&y);
    Ok((handle, xa, ya))
}

/// `TPM2_ECDH_ZGen`: multiplies `peer_point` by the private half of
/// `key_handle`, returning the resulting point's x-coordinate — the DHKEM
/// raw DH output [`Decapsulator::raw_dh`] needs. Wire layout cross-checked
/// against `google/go-tpm`'s `encodeECDHZGen`/`decodeECDHZGen`.
fn ecdh_zgen(
    ctx: &TbsContext,
    key_handle: u32,
    peer_x: &[u8; 32],
    peer_y: &[u8; 32],
) -> Result<[u8; 32]> {
    let response = ctx.submit(&build_ecdh_zgen_command(key_handle, peer_x, peer_y))?;
    parse_ecdh_zgen_response(&response)
}

fn build_ecdh_zgen_command(key_handle: u32, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Vec<u8> {
    let mut body = Writer::new();
    body.u32(key_handle);
    write_empty_pw_session(&mut body);

    // inPoint: TPM2B_ECC_POINT — an outer tpm2b wrapping TPMS_ECC_POINT{x, y},
    // each themselves a tpm2b. Built inner-first so the outer length is right.
    let mut point = Writer::new();
    point.tpm2b(peer_x);
    point.tpm2b(peer_y);
    body.tpm2b(&point.finish());

    let body = body.finish();
    let mut cmd = Writer::new();
    cmd.u16(TPM2_ST_SESSIONS);
    cmd.u32(10 + body.len() as u32);
    cmd.u32(TPM2_CC_ECDH_ZGEN);
    cmd.0.extend_from_slice(&body);
    cmd.finish()
}

fn parse_ecdh_zgen_response(response: &[u8]) -> Result<[u8; 32]> {
    check_response_code(response)?;
    let mut r = Reader::new(response);
    r.skip(10)?; // tag, size, responseCode
    r.skip(4)?; // parameterSize
    r.u16()?; // outPoint's outer TPM2B_ECC_POINT size — unused, structural
    let x = r.tpm2b()?;
    if x.len() != 32 {
        return Err(tpm_err(format!(
            "TPM returned a shared x-coordinate of {} bytes, not 32",
            x.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&x);
    Ok(out)
}

/// Whether TBS can reach a TPM 2.0 device — the Windows counterpart to
/// checking the Secure Enclave is present.
pub fn available() -> bool {
    TbsContext::open().is_ok()
}

/// This device's TPM decrypt key, as an envelope recipient.
///
/// The private half never leaves the TPM; the only operation exposed is a
/// single raw ECDH, which is all HPKE decapsulation actually requires — same
/// shape as [`crate::backend_se::EnclaveDecapsulator`].
pub struct TpmDecapsulator {
    recipient: Recipient,
}

impl TpmDecapsulator {
    pub fn open() -> Result<Self> {
        let ctx = TbsContext::open()?;
        let (_, x, y) = create_primary_ecc(&ctx)?;
        let mut pk = Vec::with_capacity(65);
        pk.push(0x04); // SEC1 uncompressed-point tag
        pk.extend_from_slice(&x);
        pk.extend_from_slice(&y);
        let recipient = Recipient::new(KemId::DhkemP256, &pk, Domain::Hardware)
            .map_err(|e| tpm_err(format!("tpm recipient: {e}")))?;
        Ok(Self { recipient })
    }
}

impl Decapsulator for TpmDecapsulator {
    fn recipient(&self) -> &Recipient {
        &self.recipient
    }

    fn raw_dh(&self, peer_enc: &[u8]) -> std::result::Result<Zeroizing<[u8; 32]>, EnvelopeError> {
        if peer_enc.len() != 65 || peer_enc[0] != 0x04 {
            return Err(EnvelopeError::Malformed(
                "p256 enc must be 65 bytes, SEC1 uncompressed",
            ));
        }
        let mut peer_x = [0u8; 32];
        let mut peer_y = [0u8; 32];
        peer_x.copy_from_slice(&peer_enc[1..33]);
        peer_y.copy_from_slice(&peer_enc[33..65]);

        // Re-derives the same deterministic primary `open()` already proved
        // exists, rather than caching a handle across calls: handles are
        // scoped to one TBS context, and stanza-by-stanza `raw_dh` calls
        // over a long-lived `TpmDecapsulator` would otherwise need to keep
        // that context (and its Windows handle) alive for the object's
        // entire lifetime for no real benefit.
        let ctx = TbsContext::open().map_err(|_| EnvelopeError::BadRecipientKey)?;
        let (handle, _, _) =
            create_primary_ecc(&ctx).map_err(|_| EnvelopeError::BadRecipientKey)?;
        let z_x = ecdh_zgen(&ctx, handle, &peer_x, &peer_y)
            .map_err(|_| EnvelopeError::BadRecipientKey)?;
        Ok(Zeroizing::new(z_x))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_tcg_header() {
        assert_eq!(TPM2_ST_SESSIONS, 0x8002);
        assert_eq!(TPM2_CC_CREATE_PRIMARY, 0x0000_0131);
        assert_eq!(TPM2_CC_ECDH_ZGEN, 0x0000_0154);
        assert_eq!(TPM2_RH_ENDORSEMENT, 0x4000_000B);
        assert_eq!(TPM2_RS_PW, 0x4000_0009);
        assert_eq!(TPM2_ALG_ECC, 0x0023);
        assert_eq!(TPM2_ALG_NULL, 0x0010);
        assert_eq!(TPM2_ECC_NIST_P256, 0x0003);
    }

    #[test]
    fn object_attributes_are_decrypt_not_sign_and_not_restricted() {
        assert_eq!(
            OBJECT_ATTRIBUTES,
            0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0002_0000,
            "fixedtpm | fixedparent | sensitivedataorigin | userwithauth | decrypt"
        );
        assert_eq!(
            OBJECT_ATTRIBUTES & 0x0001_0000,
            0,
            "restricted must be clear"
        );
        assert_eq!(
            OBJECT_ATTRIBUTES & 0x0004_0000,
            0,
            "sign/encrypt must be clear — this key never signs"
        );
    }

    #[test]
    fn create_primary_ecc_command_is_correctly_shaped() {
        let cmd = build_create_primary_ecc_command();
        let mut r = Reader::new(&cmd);
        assert_eq!(r.u16().unwrap(), TPM2_ST_SESSIONS, "tag");
        assert_eq!(r.u32().unwrap(), cmd.len() as u32, "size self-consistency");
        assert_eq!(r.u32().unwrap(), TPM2_CC_CREATE_PRIMARY, "command code");
        assert_eq!(r.u32().unwrap(), TPM2_RH_ENDORSEMENT, "hierarchy handle");

        let auth_size = r.u32().unwrap();
        assert_eq!(
            auth_size, 9,
            "authorizationSize (one empty-password session)"
        );
        r.skip(auth_size as usize).unwrap();

        let sensitive = r.tpm2b().unwrap();
        assert_eq!(
            sensitive,
            Vec::<u8>::new(),
            "inSensitive: empty userAuth + empty data, tpm2b-wrapped"
        );

        // inPublic, walked field by field rather than by offset.
        let _in_public_len = r.u16().unwrap();
        assert_eq!(r.u16().unwrap(), TPM2_ALG_ECC, "public type");
        assert_eq!(r.u16().unwrap(), 0x000B, "nameAlg = SHA-256");
        assert_eq!(r.u32().unwrap(), OBJECT_ATTRIBUTES, "objectAttributes");
        assert_eq!(r.tpm2b().unwrap(), Vec::<u8>::new(), "authPolicy (empty)");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_NULL, "symmetric");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_NULL, "scheme");
        assert_eq!(r.u16().unwrap(), TPM2_ECC_NIST_P256, "curveID");
        assert_eq!(r.u16().unwrap(), TPM2_ALG_NULL, "kdf");
        assert_eq!(
            r.tpm2b().unwrap(),
            Vec::<u8>::new(),
            "unique.x (TPM-generated)"
        );
        assert_eq!(
            r.tpm2b().unwrap(),
            Vec::<u8>::new(),
            "unique.y (TPM-generated)"
        );

        assert_eq!(r.tpm2b().unwrap(), Vec::<u8>::new(), "outsideInfo (empty)");
        assert_eq!(r.u32().unwrap(), 0, "creationPCR count (none)");
        assert_eq!(r.pos, cmd.len(), "creationPCR must be the last field");
    }

    #[test]
    fn ecdh_zgen_command_is_correctly_shaped() {
        let handle = 0x8000_0001u32;
        let peer_x = [0x11u8; 32];
        let peer_y = [0x22u8; 32];
        let cmd = build_ecdh_zgen_command(handle, &peer_x, &peer_y);
        let mut r = Reader::new(&cmd);

        assert_eq!(r.u16().unwrap(), TPM2_ST_SESSIONS, "tag");
        assert_eq!(r.u32().unwrap(), cmd.len() as u32, "size self-consistency");
        assert_eq!(r.u32().unwrap(), TPM2_CC_ECDH_ZGEN, "command code");
        assert_eq!(r.u32().unwrap(), handle, "key handle");
        let auth_size = r.u32().unwrap();
        assert_eq!(auth_size, 9);
        r.skip(auth_size as usize).unwrap();

        let _outer_point_len = r.u16().unwrap();
        assert_eq!(r.tpm2b().unwrap(), peer_x, "inPoint.x, verbatim");
        assert_eq!(r.tpm2b().unwrap(), peer_y, "inPoint.y, verbatim");
        assert_eq!(r.pos, cmd.len(), "inPoint must be the last field");
    }

    #[test]
    fn create_primary_ecc_response_parses_handle_and_point() {
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_SESSIONS);
        resp.u32(0); // size — unchecked
        resp.u32(0); // responseCode = success
        resp.u32(0x8123_4567); // objectHandle

        let mut public = Writer::new();
        public.u16(TPM2_ALG_ECC);
        public.u16(0x000B);
        public.u32(OBJECT_ATTRIBUTES);
        public.tpm2b(&[]);
        public.u16(TPM2_ALG_NULL);
        public.u16(TPM2_ALG_NULL);
        public.u16(TPM2_ECC_NIST_P256);
        public.u16(TPM2_ALG_NULL);
        public.tpm2b(&[0xAAu8; 32]);
        public.tpm2b(&[0xBBu8; 32]);
        let public = public.finish();

        resp.u32(public.len() as u32); // parameterSize
        resp.tpm2b(&public);
        resp.0.extend_from_slice(&[0xCC; 8]); // trailing creationData/hash/ticket/name — unread

        let (handle, x, y) = parse_create_primary_ecc_response(&resp.finish()).unwrap();
        assert_eq!(handle, 0x8123_4567);
        assert_eq!(x, [0xAAu8; 32]);
        assert_eq!(y, [0xBBu8; 32]);
    }

    #[test]
    fn ecdh_zgen_response_parses_the_x_coordinate() {
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_SESSIONS);
        resp.u32(0);
        resp.u32(0); // responseCode = success
        resp.u32(0); // parameterSize — unchecked

        let mut point = Writer::new();
        point.tpm2b(&[0x77u8; 32]);
        point.tpm2b(&[0x88u8; 32]);
        resp.tpm2b(&point.finish());

        let x = parse_ecdh_zgen_response(&resp.finish()).unwrap();
        assert_eq!(x, [0x77u8; 32]);
    }

    #[test]
    fn refused_command_surfaces_as_an_error() {
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_SESSIONS);
        resp.u32(10);
        resp.u32(0x0000_0100); // an arbitrary non-zero TPM_RC
        assert!(parse_create_primary_ecc_response(&resp.finish()).is_err());
    }

    #[test]
    fn availability_is_reported_rather_than_assumed() {
        let _ = available();
    }
}
