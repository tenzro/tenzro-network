//! Windows TPM access for [`crate::tpm_derive`], via TBS rather than a
//! shelled-out CLI.
//!
//! The Unix path in `tpm_derive.rs` shells out to `tpm2_createprimary` and
//! `tpm2_sign` — portable in principle (Windows TSS2 has a TBS-backed TCTI),
//! but only in principle: there is no prebuilt Windows binary of those tools
//! anywhere, so shipping that path to a Windows user would mean bundling and
//! maintaining a separately-built third-party C toolchain. This module gets
//! the same two operations — derive a primary signing key, sign a fixed
//! label with it — a different way: hand-marshaled TPM2 commands submitted
//! directly to Windows' TBS (`Tbs.dll`), the OS's own TPM access broker. No
//! external binary, no bundling, builds as part of this crate like anything
//! else.
//!
//! # Why hand-marshaled rather than a TPM2 crate
//!
//! Two pure-Rust TPM2 marshaling crates exist on crates.io as of this
//! writing. Neither is trustworthy for what this guards: one is under a
//! week old with zero adoption and no declared license; the other's own
//! README calls it "currently very unstable — Everything is subject to
//! change, perhaps on a daily basis." A validator's identity is not the
//! place to take on a dependency like that. What follows is instead scoped
//! to exactly the two fixed-shape commands this file needs, encoded
//! directly against the TCG structures (cross-checked against
//! `tpm2-software/tpm2-tss`'s own `tss2_tpm2_types.h`, the header that
//! `tpm2_createprimary`/`tpm2_sign` themselves are built from) rather than
//! against a general-purpose library that might get either wrong.
//!
//! # Parity with the Unix path
//!
//! Every parameter here is the numeric encoding of the same values
//! [`crate::tpm_derive::TEMPLATE`], [`crate::tpm_derive::ATTRIBUTES`],
//! [`crate::tpm_derive::HIERARCHY`], and [`crate::tpm_derive::ROOT_LABEL`]
//! name on the Unix side — endorsement-hierarchy RSA-2048 RSASSA-SHA256,
//! `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign`, signing the
//! same label. A TPM is a different chip on every machine, so this was
//! never going to produce the *same* identity as the Unix path on the same
//! hardware — what matters is that it derives *a* stable, chip-rooted
//! identity via the identical semantics, not a different scheme that
//! happens to also involve a TPM.
//!
//! `tpm2_sign` (given a plain file rather than a pre-computed digest) hashes
//! the input client-side before calling `TPM2_Sign` — this key is not
//! `restricted`, so `TPM2_Sign` accepts an externally-computed digest
//! without a validation ticket. This file does the same: SHA-256 the label
//! in software, submit the digest, and pass an empty `TPMT_TK_HASHCHECK`
//! (`TPM_RH_NULL`) rather than a real ticket, exactly as the null-ticket
//! case is meant to be used.

use crate::error::{Result as TeeResult, TeeError};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, Tbsi_Context_Create,
    Tbsip_Context_Close, Tbsip_Submit_Command,
};

// --- TPM2 constants, numeric twins of the string/text forms pinned in
// `tpm_derive.rs`. Values cross-checked against tpm2-tss's
// `include/tss2/tss2_tpm2_types.h` (`TPM2_CC_*`, `TPM2_ALG_*`, `TPM2_RH_*`,
// `TPM2_ST_*`, `TPMA_OBJECT_*`) rather than transcribed from a summary. ---

const TPM2_ST_SESSIONS: u16 = 0x8002;
const TPM2_ST_HASHCHECK: u16 = 0x8024;

const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM2_CC_SIGN: u32 = 0x0000_015D;

const TPM2_RH_ENDORSEMENT: u32 = 0x4000_000B;
const TPM2_RH_NULL: u32 = 0x4000_0007;
/// `TPM2_RS_PW` — the password-authorization session handle. Using it with
/// an empty HMAC is exactly what an empty-auth object needs; this is the
/// numeric form of what the CLI does implicitly for an unauthenticated
/// object.
const TPM2_RS_PW: u32 = 0x4000_0009;

const TPM2_ALG_RSA: u16 = 0x0001;
const TPM2_ALG_SHA256: u16 = 0x000B;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_ALG_RSASSA: u16 = 0x0014;

/// `fixedtpm | fixedparent | sensitivedataorigin | userwithauth | sign` —
/// the numeric form of [`crate::tpm_derive::ATTRIBUTES`]. Kept as named
/// bits rather than the bare sum so a diff against that string is legible.
const TPMA_OBJECT_FIXEDTPM: u32 = 0x0000_0002;
const TPMA_OBJECT_FIXEDPARENT: u32 = 0x0000_0010;
const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x0000_0020;
const TPMA_OBJECT_USERWITHAUTH: u32 = 0x0000_0040;
const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 0x0004_0000;
const OBJECT_ATTRIBUTES: u32 = TPMA_OBJECT_FIXEDTPM
    | TPMA_OBJECT_FIXEDPARENT
    | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH
    | TPMA_OBJECT_SIGN_ENCRYPT;

/// RSA-2048 per [`crate::tpm_derive::TEMPLATE`]; this era's TPMs generate it
/// in a tolerable time, and matches the Unix template bit-for-bit.
const RSA_KEY_BITS: u16 = 2048;

/// A TBS context, open for the life of one derivation. Closes and flushes
/// every object created under it (including the primary) on drop, per
/// `Tbsip_Context_Close`'s documented behavior — there is deliberately no
/// explicit `TPM2_FlushContext` call because of that.
///
/// Stored as `*mut c_void` to match `Tbsi_Context_Create`'s out-parameter
/// (`*mut *mut c_void`); `Tbsip_Submit_Command`/`Tbsip_Context_Close` both
/// take the narrower `*const c_void`, which a `*mut` pointer coerces to at
/// the call site.
struct TbsContext(*mut c_void);

impl TbsContext {
    fn open() -> TeeResult<Self> {
        // `Tbsi_Context_Create` takes `*const TBS_CONTEXT_PARAMS` (the
        // one-field v1 struct) unconditionally; passing the v2 struct means
        // reinterpreting its pointer as that type, which is the documented
        // way to opt into TBS_CONTEXT_PARAMS2 — the callee reads `version`
        // first and only reads further when it is TPM_VERSION_20.
        let params = TBS_CONTEXT_PARAMS2 {
            version: 2, // TPM_VERSION_20
            Anonymous: TBS_CONTEXT_PARAMS2_0 {
                asUINT32: 0b100, // includeTpm20 = 1; requestRaw and includeTpm12 = 0
            },
        };
        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: `params` is a valid, fully-initialized TBS_CONTEXT_PARAMS2
        // on the stack for the duration of this call, reinterpreted as the
        // TBS_CONTEXT_PARAMS pointer type the FFI signature requires — valid
        // because TBS_CONTEXT_PARAMS2 starts with the same `version: u32`
        // field TBS_CONTEXT_PARAMS is entirely made of, and TBS reads
        // `version` before reading anything past it. `handle` is a valid
        // out-pointer.
        let rc = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut handle,
            )
        };
        if rc != TBS_SUCCESS || handle.is_null() {
            return Err(TeeError::KeyGenerationFailed(format!(
                "Tbsi_Context_Create failed: 0x{rc:08X}"
            )));
        }
        Ok(Self(handle))
    }

    fn submit(&self, command: &[u8]) -> TeeResult<Vec<u8>> {
        // TPM2 responses are bounded; 4096 bytes is generous for either
        // command this file sends and matches the buffer tpm2-tools itself
        // uses for a single-command round trip.
        let mut result = vec![0u8; 4096];
        let mut result_len: u32 = result.len() as u32;
        // SAFETY: `self.0` is a live context from a successful `open()`,
        // `command`/`result` are valid slices for their stated lengths for
        // the duration of the call, and `result_len` is a valid in/out
        // pointer to that length.
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
            return Err(TeeError::KeyGenerationFailed(format!(
                "Tbsip_Submit_Command failed: 0x{rc:08X}"
            )));
        }
        result.truncate(result_len as usize);
        Ok(result)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is either null (skipped above) or a context
            // this struct is the sole owner of, from a successful `open()`.
            unsafe {
                Tbsip_Context_Close(self.0);
            }
        }
    }
}

// --- Minimal big-endian TPM2 wire writer. TPM2 is exclusively big-endian;
// every multi-byte field below uses `to_be_bytes()` for exactly that reason.

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// A `TPM2B_*` field: a two-byte length prefix followed by that many
    /// bytes. Every variable-sized TPM2 field takes this shape.
    fn tpm2b(&mut self, bytes: &[u8]) -> &mut Self {
        self.u16(bytes.len() as u16);
        self.0.extend_from_slice(bytes);
        self
    }
    fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Reads a big-endian `u32` at `offset`, for the fixed-position response
/// fields this file needs (a response's handle area, its `parameterSize`).
/// Bounds-checked: a short/malformed response from the TPM is a real
/// possibility to guard, not a case to `panic!` on.
fn read_u32(bytes: &[u8], offset: usize) -> TeeResult<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
        .ok_or_else(|| TeeError::KeyGenerationFailed("truncated TPM2 response".into()))
}

fn read_u16(bytes: &[u8], offset: usize) -> TeeResult<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|s| u16::from_be_bytes(s.try_into().unwrap()))
        .ok_or_else(|| TeeError::KeyGenerationFailed("truncated TPM2 response".into()))
}

/// Every response here starts with `tag(2) size(4) responseCode(4)`. A
/// non-zero `responseCode` is the TPM refusing the command outright — surface
/// it rather than reading further into a body that was never produced.
fn check_response_code(bytes: &[u8]) -> TeeResult<()> {
    let code = read_u32(bytes, 6)?;
    if code != 0 {
        return Err(TeeError::KeyGenerationFailed(format!(
            "TPM refused the command: response code 0x{code:08X}"
        )));
    }
    Ok(())
}

/// The empty-password authorization session every command below sends:
/// `sessionHandle(TPM_RS_PW) nonce(empty) sessionAttributes(0) hmac(empty)`,
/// wrapped in its own `authorizationSize`. This is the numeric form of an
/// object with no auth value set, submitted the way the CLI submits it
/// implicitly for a keyless invocation.
fn write_empty_pw_session(w: &mut Writer) {
    let mut session = Writer::new();
    session.u32(TPM2_RS_PW);
    session.tpm2b(&[]); // nonce
    session.u8(0); // sessionAttributes
    session.tpm2b(&[]); // hmac
    let session = session.finish();
    w.u32(session.len() as u32);
    w.0.extend_from_slice(&session);
}

/// `TPM2_CreatePrimary` in the endorsement hierarchy, deriving the same
/// RSA-2048/RSASSA-SHA256/sign-only key the Unix path derives via
/// `tpm2_createprimary -C e -G rsa2048:rsassa-sha256:null -a
/// fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign`.
///
/// Returns the transient object handle TPM2_CreatePrimary allocated. That
/// handle (and anything else created under this context) is flushed when
/// the caller's [`TbsContext`] closes, so there is no matching "delete"
/// call to make here.
fn create_primary(ctx: &TbsContext) -> TeeResult<u32> {
    let response = ctx.submit(&build_create_primary_command())?;
    parse_create_primary_response(&response)
}

/// Builds the `TPM2_CreatePrimary` command bytes. Split out from
/// [`create_primary`] so the wire encoding — the part correctness actually
/// hinges on — is testable without a TPM, real or simulated.
fn build_create_primary_command() -> Vec<u8> {
    let mut body = Writer::new();
    body.u32(TPM2_RH_ENDORSEMENT);
    write_empty_pw_session(&mut body);

    // inSensitive: TPM2B_SENSITIVE_CREATE{ userAuth: empty, data: empty }
    let mut sensitive_create = Writer::new();
    sensitive_create.tpm2b(&[]); // userAuth
    sensitive_create.tpm2b(&[]); // data
    body.tpm2b(&sensitive_create.finish());

    // inPublic: TPM2B_PUBLIC{ TPMT_PUBLIC{ ... } }
    let mut public = Writer::new();
    public.u16(TPM2_ALG_RSA); // type
    public.u16(TPM2_ALG_SHA256); // nameAlg
    public.u32(OBJECT_ATTRIBUTES);
    public.tpm2b(&[]); // authPolicy
    // TPMS_RSA_PARMS
    public.u16(TPM2_ALG_NULL); // symmetric — not a decryption key
    public.u16(TPM2_ALG_RSASSA); // scheme.scheme
    public.u16(TPM2_ALG_SHA256); // scheme.details.hashAlg
    public.u16(RSA_KEY_BITS); // keyBits
    public.u32(0); // exponent — 0 means the default, 2^16+1
    public.tpm2b(&[]); // unique (TPM2B_PUBLIC_KEY_RSA) — TPM-generated
    body.tpm2b(&public.finish());

    body.tpm2b(&[]); // outsideInfo (TPM2B_DATA)
    body.u32(0); // creationPCR (TPML_PCR_SELECTION) — count = 0

    let body = body.finish();
    let mut cmd = Writer::new();
    cmd.u16(TPM2_ST_SESSIONS);
    cmd.u32(10 + body.len() as u32); // header + body
    cmd.u32(TPM2_CC_CREATE_PRIMARY);
    cmd.0.extend_from_slice(&body);

    cmd.finish()
}

fn parse_create_primary_response(response: &[u8]) -> TeeResult<u32> {
    check_response_code(response)?;
    // The handle area is the first thing after the header, before
    // `parameterSize` — always at a fixed offset regardless of the rest of
    // the (variable-length) response.
    read_u32(response, 10)
}

/// `TPM2_Sign` over `digest` with the primary from [`create_primary`], via
/// the null ticket a non-`restricted` key is allowed to use for an
/// externally-computed digest — see the module docs for why that's correct
/// here rather than a shortcut.
fn sign(ctx: &TbsContext, key_handle: u32, digest: &[u8; 32]) -> TeeResult<Vec<u8>> {
    let response = ctx.submit(&build_sign_command(key_handle, digest))?;
    parse_sign_response(&response)
}

/// Builds the `TPM2_Sign` command bytes. Split out for the same reason as
/// [`build_create_primary_command`].
fn build_sign_command(key_handle: u32, digest: &[u8; 32]) -> Vec<u8> {
    let mut body = Writer::new();
    body.u32(key_handle);
    write_empty_pw_session(&mut body);

    body.tpm2b(digest); // digest (TPM2B_DIGEST)
    // inScheme: TPMT_SIG_SCHEME
    body.u16(TPM2_ALG_RSASSA);
    body.u16(TPM2_ALG_SHA256);
    // validation: TPMT_TK_HASHCHECK — the null ticket
    body.u16(TPM2_ST_HASHCHECK);
    body.u32(TPM2_RH_NULL);
    body.tpm2b(&[]); // digest (empty — this is the null ticket)

    let body = body.finish();
    let mut cmd = Writer::new();
    cmd.u16(TPM2_ST_SESSIONS);
    cmd.u32(10 + body.len() as u32);
    cmd.u32(TPM2_CC_SIGN);
    cmd.0.extend_from_slice(&body);

    cmd.finish()
}

fn parse_sign_response(response: &[u8]) -> TeeResult<Vec<u8>> {
    check_response_code(response)?;
    // Response: header(10) parameterSize(4) TPMT_SIGNATURE{ sigAlg(2)
    // TPMS_SIGNATURE_RSA{ hash(2) sig: TPM2B_PUBLIC_KEY_RSA{ size(2) buffer } } }
    let sig_len = read_u16(response, 18)? as usize;
    response
        .get(20..20 + sig_len)
        .map(|s| s.to_vec())
        .ok_or_else(|| TeeError::KeyGenerationFailed("truncated TPM2_Sign response".into()))
}

/// Whether TBS can reach a TPM 2.0 device on this machine — the Windows
/// counterpart to [`crate::tpm_derive::derivation_available`]'s `/dev/tpm*`
/// check. Actually opening a context is the only reliable probe: a closed
/// or disabled TBS service, a TPM 1.2-only chip, or no TPM at all all fail
/// here the same way they would fail a real derivation, which is exactly
/// what this is meant to predict.
pub fn derivation_available() -> bool {
    TbsContext::open().is_ok()
}

/// The Windows counterpart to [`crate::tpm_derive::root_secret`]'s shelled
/// `tpm2_createprimary` + `tpm2_sign`: the same two operations, submitted
/// directly via TBS.
pub fn root_secret(root_label: &[u8]) -> TeeResult<Vec<u8>> {
    let ctx = TbsContext::open()?;
    let primary = create_primary(&ctx)?;
    let digest: [u8; 32] = Sha256::digest(root_label).into();
    sign(&ctx, primary, &digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every numeric constant here is a transcription from
    /// `tpm2-software/tpm2-tss`'s `tss2_tpm2_types.h` — pin them so a typo
    /// fails loudly rather than silently sending the TPM a different
    /// command than intended. Cross-checked against that header directly,
    /// not against a secondary summary, when this file was written.
    #[test]
    fn constants_match_the_tcg_header() {
        assert_eq!(TPM2_ST_SESSIONS, 0x8002);
        assert_eq!(TPM2_ST_HASHCHECK, 0x8024);
        assert_eq!(TPM2_CC_CREATE_PRIMARY, 0x0000_0131);
        assert_eq!(TPM2_CC_SIGN, 0x0000_015D);
        assert_eq!(TPM2_RH_ENDORSEMENT, 0x4000_000B);
        assert_eq!(TPM2_RH_NULL, 0x4000_0007);
        assert_eq!(TPM2_RS_PW, 0x4000_0009);
        assert_eq!(TPM2_ALG_RSA, 0x0001);
        assert_eq!(TPM2_ALG_SHA256, 0x000B);
        assert_eq!(TPM2_ALG_NULL, 0x0010);
        assert_eq!(TPM2_ALG_RSASSA, 0x0014);
    }

    /// The numeric object attributes must be the same set
    /// [`crate::tpm_derive::ATTRIBUTES`] names for the Unix path — this is
    /// the property [`crate::tpm_derive::tests::the_root_is_endorsement_rooted`]
    /// checks on Unix via the string form; this is that check's Windows
    /// counterpart, against the bits this file actually sends.
    #[test]
    fn object_attributes_match_the_unix_string_form() {
        assert_eq!(
            OBJECT_ATTRIBUTES,
            0x0002 | 0x0010 | 0x0020 | 0x0040 | 0x0004_0000,
            "fixedtpm | fixedparent | sensitivedataorigin | userwithauth | sign"
        );
        // An identity that could move, or that the TPM didn't generate
        // itself, is not the property this module exists for.
        assert_ne!(OBJECT_ATTRIBUTES & TPMA_OBJECT_FIXEDTPM, 0);
        assert_ne!(OBJECT_ATTRIBUTES & TPMA_OBJECT_FIXEDPARENT, 0);
        assert_ne!(OBJECT_ATTRIBUTES & TPMA_OBJECT_SENSITIVEDATAORIGIN, 0);
    }

    /// Reads a big-endian u16/u32 at a fixed offset, exactly like the
    /// production parser — used here to walk into a *built command* and
    /// check the fields landed where the TPM2 wire format requires, rather
    /// than trusting one hand-authored byte-array literal not to have the
    /// same off-by-one mistake the code might.
    fn field_u16(bytes: &[u8], offset: usize) -> u16 {
        read_u16(bytes, offset).unwrap()
    }
    fn field_u32(bytes: &[u8], offset: usize) -> u32 {
        read_u32(bytes, offset).unwrap()
    }

    #[test]
    fn create_primary_command_is_correctly_shaped() {
        let cmd = build_create_primary_command();

        // Header.
        assert_eq!(field_u16(&cmd, 0), TPM2_ST_SESSIONS, "tag");
        assert_eq!(
            field_u32(&cmd, 2),
            cmd.len() as u32,
            "the size field must equal the command's actual length"
        );
        assert_eq!(field_u32(&cmd, 6), TPM2_CC_CREATE_PRIMARY, "command code");

        // Handle area: the hierarchy this primary is created under.
        assert_eq!(field_u32(&cmd, 10), TPM2_RH_ENDORSEMENT, "hierarchy handle");

        // Auth area: one empty-password session.
        assert_eq!(field_u32(&cmd, 14), 9, "authorizationSize (one PW session)");
        assert_eq!(field_u32(&cmd, 18), TPM2_RS_PW, "session handle");
        assert_eq!(field_u16(&cmd, 22), 0, "nonce size (empty)");
        assert_eq!(cmd[24], 0, "sessionAttributes");
        assert_eq!(field_u16(&cmd, 25), 0, "hmac size (empty)");

        // Parameters start at 27: inSensitive, inPublic, outsideInfo,
        // creationPCR, in that order.
        let p = 27;
        assert_eq!(
            field_u16(&cmd, p),
            4,
            "inSensitive inner size (empty userAuth+data)"
        );
        let in_public_size_offset = p + 2 + 4;
        let in_public_len = field_u16(&cmd, in_public_size_offset) as usize;
        let tpmt_public = in_public_size_offset + 2;
        assert_eq!(field_u16(&cmd, tpmt_public), TPM2_ALG_RSA, "public type");
        assert_eq!(field_u16(&cmd, tpmt_public + 2), TPM2_ALG_SHA256, "nameAlg");
        assert_eq!(
            field_u32(&cmd, tpmt_public + 4),
            OBJECT_ATTRIBUTES,
            "objectAttributes"
        );
        assert_eq!(
            field_u16(&cmd, tpmt_public + 8),
            0,
            "authPolicy size (empty)"
        );
        let rsa_parms = tpmt_public + 10;
        assert_eq!(
            field_u16(&cmd, rsa_parms),
            TPM2_ALG_NULL,
            "symmetric (not a decryption key)"
        );
        assert_eq!(field_u16(&cmd, rsa_parms + 2), TPM2_ALG_RSASSA, "scheme");
        assert_eq!(
            field_u16(&cmd, rsa_parms + 4),
            TPM2_ALG_SHA256,
            "scheme hash"
        );
        assert_eq!(field_u16(&cmd, rsa_parms + 6), RSA_KEY_BITS, "keyBits");
        assert_eq!(
            field_u32(&cmd, rsa_parms + 8),
            0,
            "exponent (0 = default 2^16+1)"
        );
        assert_eq!(
            field_u16(&cmd, rsa_parms + 12),
            0,
            "unique size (TPM-generated)"
        );
        // rsa_parms + 14 is where TPMT_PUBLIC ends: 10 (type..authPolicy) +
        // 12 (TPMS_RSA_PARMS) + 2 (unique size) = 24 bytes past tpmt_public.
        assert_eq!(in_public_len, 24, "TPMT_PUBLIC body length");

        let after_public = in_public_size_offset + 2 + in_public_len;
        assert_eq!(field_u16(&cmd, after_public), 0, "outsideInfo size (empty)");
        assert_eq!(
            field_u32(&cmd, after_public + 2),
            0,
            "creationPCR count (none)"
        );
        assert_eq!(
            after_public + 6,
            cmd.len(),
            "creationPCR must be the last field in the command"
        );
    }

    #[test]
    fn sign_command_is_correctly_shaped() {
        let handle = 0x8000_0001u32;
        let digest = [0x42u8; 32];
        let cmd = build_sign_command(handle, &digest);

        assert_eq!(field_u16(&cmd, 0), TPM2_ST_SESSIONS, "tag");
        assert_eq!(
            field_u32(&cmd, 2),
            cmd.len() as u32,
            "size self-consistency"
        );
        assert_eq!(field_u32(&cmd, 6), TPM2_CC_SIGN, "command code");
        assert_eq!(field_u32(&cmd, 10), handle, "key handle");
        assert_eq!(field_u32(&cmd, 14), 9, "authorizationSize (one PW session)");

        let p = 27; // handle(4) + authSize(4) + session(9) after the header
        assert_eq!(field_u16(&cmd, p), 32, "digest size");
        assert_eq!(&cmd[p + 2..p + 34], &digest, "digest bytes, verbatim");
        assert_eq!(field_u16(&cmd, p + 34), TPM2_ALG_RSASSA, "inScheme.scheme");
        assert_eq!(
            field_u16(&cmd, p + 36),
            TPM2_ALG_SHA256,
            "inScheme.details.hashAlg"
        );
        assert_eq!(field_u16(&cmd, p + 38), TPM2_ST_HASHCHECK, "validation.tag");
        assert_eq!(
            field_u32(&cmd, p + 40),
            TPM2_RH_NULL,
            "validation.hierarchy (null ticket)"
        );
        assert_eq!(
            field_u16(&cmd, p + 44),
            0,
            "validation.digest size (empty — null ticket)"
        );
        assert_eq!(p + 46, cmd.len(), "validation must be the last field");
    }

    /// Builds a synthetic `TPM2_CreatePrimary` response with a known
    /// handle, at the exact shape [`parse_create_primary_response`] expects,
    /// and confirms it extracts that handle. What follows the handle is
    /// deliberately garbage: the parser must not need it, since the real
    /// response's trailing fields are large and this file never reads them.
    #[test]
    fn create_primary_response_parses_the_handle() {
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_SESSIONS);
        resp.u32(0); // size — unchecked by the parser, left as a placeholder
        resp.u32(0); // responseCode = TPM_RC_SUCCESS
        resp.u32(0x8123_4567); // objectHandle
        resp.0.extend_from_slice(&[0xAA; 16]); // stand-in for the rest
        let resp = resp.finish();

        assert_eq!(parse_create_primary_response(&resp).unwrap(), 0x8123_4567);
    }

    #[test]
    fn create_primary_response_error_code_is_surfaced() {
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_SESSIONS);
        resp.u32(10);
        resp.u32(0x0000_0100); // an arbitrary non-zero TPM_RC
        let resp = resp.finish();

        assert!(parse_create_primary_response(&resp).is_err());
    }

    /// Same shape as [`create_primary_response_parses_the_handle`], for
    /// `TPM2_Sign`'s response: `header(10) parameterSize(4)
    /// TPMT_SIGNATURE{sigAlg hash sig}`.
    #[test]
    fn sign_response_parses_the_signature_bytes() {
        let expected_sig = vec![0x77u8; 256]; // RSA-2048 signature length
        let mut resp = Writer::new();
        resp.u16(TPM2_ST_SESSIONS);
        resp.u32(0);
        resp.u32(0); // responseCode = TPM_RC_SUCCESS
        resp.u32(0); // parameterSize — unchecked by the parser
        resp.u16(TPM2_ALG_RSASSA); // sigAlg
        resp.u16(TPM2_ALG_SHA256); // hash
        resp.tpm2b(&expected_sig); // sig
        let resp = resp.finish();

        assert_eq!(parse_sign_response(&resp).unwrap(), expected_sig);
    }

    /// Confirms [`derivation_available`] fails closed rather than panicking
    /// when there is no TPM/TBS to reach — the property
    /// [`crate::tpm_derive::tests::availability_is_reported_rather_than_assumed`]
    /// checks for the Unix path.
    #[test]
    fn availability_is_reported_rather_than_assumed() {
        let _ = derivation_available();
    }
}
