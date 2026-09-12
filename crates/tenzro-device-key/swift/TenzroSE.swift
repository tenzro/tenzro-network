// TenzroSE.swift — C ABI over CryptoKit's SecureEnclave for tenzro-device-key.
//
// Why CryptoKit and not Security.framework: `SecKeyCreateRandomKey` with
// `kSecAttrIsPermanent` persists into the data-protection keychain, which is
// entitlement-gated (-34018 without a provisioning profile). CryptoKit's
// SecureEnclave API never touches the keychain — it hands back a SEP-wrapped
// blob that we store ourselves — so the gated component is not in the path.
// That is what makes a Tenzro node permissionless on Apple hardware.
//
// Two keys, not one. A single SecKey could do both ECDSA and ECIES; CryptoKit's
// `SecureEnclave.P256.Signing` and `.KeyAgreement` are distinct types with
// distinct blobs, so a key directory holds `sign.key` and `agree.key`.
//
// All functions return 0 on success and a negative TZDK_* code on failure.
// Nothing traps: CryptoKit fatal-errors (SIGTRAP) on a malformed blob, so every
// blob is length-sanity-checked before it is handed to CryptoKit.

import Foundation
import CryptoKit
import Security

// MARK: - Error codes (mirrored in the Rust side)

let TZDK_OK: Int32 = 0
let TZDK_ERR_UNAVAILABLE: Int32 = -1   // no Secure Enclave on this machine
let TZDK_ERR_NOT_FOUND: Int32 = -2   // no key at that label
let TZDK_ERR_IO: Int32 = -3   // could not read/write the blob
let TZDK_ERR_CRYPTO: Int32 = -4   // CryptoKit refused
let TZDK_ERR_BADARG: Int32 = -5   // caller passed something impossible
let TZDK_ERR_BUFFER: Int32 = -6   // output buffer too small
let TZDK_ERR_CORRUPT: Int32 = -7   // blob failed its sanity check

// Observed SEP blob sizes are 271–284 bytes and vary by execution context
// (user session vs LaunchDaemon). Never compare against a constant — this is a
// loose plausibility band purely to keep a truncated file away from CryptoKit,
// which would SIGTRAP rather than throw.
let BLOB_MIN = 64
let BLOB_MAX = 4096

// MARK: - A Digest we can fill from raw bytes
//
// The Rust trait signs a pre-computed 32-byte hash. CryptoKit will hash raw
// Data for you, and offers no public initialiser for SHA256Digest from bytes —
// so signing a prehash means conforming our own type to `Digest`. Verified: the
// resulting signature validates against a genuine SHA256.hash of the same
// message, i.e. this is ordinary ECDSA and interoperates with any verifier.

struct RawSHA256Digest: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]
    init?(_ b: [UInt8]) {
        guard b.count == 32 else { return nil }
        bytes = b
    }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    static func == (l: Self, r: Self) -> Bool { l.bytes == r.bytes }
    func hash(into h: inout Hasher) { h.combine(bytes) }
}

// MARK: - Blob paths

private func keyDir(_ dir: UnsafePointer<CChar>) -> URL {
    URL(fileURLWithPath: String(cString: dir), isDirectory: true)
}

// Result's failure type must conform to Error, so carry the C code inside one.
struct TZErr: Error { let code: Int32 }
private func fail<T>(_ c: Int32) -> Result<T, TZErr> { .failure(TZErr(code: c)) }

private func loadBlob(_ url: URL) -> Result<Data, TZErr> {
    guard FileManager.default.fileExists(atPath: url.path) else { return fail(TZDK_ERR_NOT_FOUND) }
    guard let d = try? Data(contentsOf: url) else { return fail(TZDK_ERR_IO) }
    guard d.count >= BLOB_MIN, d.count <= BLOB_MAX else { return fail(TZDK_ERR_CORRUPT) }
    return .success(d)
}

// Write via a temp file + atomic replace so a crash mid-write cannot leave a
// truncated blob — which would be indistinguishable from a corrupted enclave key.
private func storeBlob(_ data: Data, _ url: URL) -> Int32 {
    do {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return TZDK_OK
    } catch {
        return TZDK_ERR_IO
    }
}

private func signURL(_ d: URL) -> URL { d.appendingPathComponent("sign.key") }
private func agreeURL(_ d: URL) -> URL { d.appendingPathComponent("agree.key") }

private func openSigning(_ d: URL) -> Result<SecureEnclave.P256.Signing.PrivateKey, TZErr> {
    switch loadBlob(signURL(d)) {
    case .failure(let e): return .failure(e)
    case .success(let blob):
        guard let k = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob) else {
            return fail(TZDK_ERR_CORRUPT)
        }
        return .success(k)
    }
}

private func openAgreement(_ d: URL) -> Result<SecureEnclave.P256.KeyAgreement.PrivateKey, TZErr> {
    switch loadBlob(agreeURL(d)) {
    case .failure(let e): return .failure(e)
    case .success(let blob):
        guard let k = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob) else {
            return fail(TZDK_ERR_CORRUPT)
        }
        return .success(k)
    }
}

// MARK: - C ABI

@_cdecl("tzdk_available")
public func tzdk_available() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

/// Create both keys under `dir`. Refuses if either already exists, so a create
/// can never silently discard a key that secrets are already wrapped to.
///
/// `requireUserPresence != 0` gates every private-key use behind Touch ID /
/// the device passcode — correct for a wallet key. A headless node daemon must
/// pass 0, because there is nobody present to satisfy the prompt and the
/// operation would simply hang. The caller decides; there is no safe default,
/// so this is deliberately not optional.
@_cdecl("tzdk_create")
public func tzdk_create(_ dir: UnsafePointer<CChar>, _ requireUserPresence: Int32) -> Int32 {
    guard SecureEnclave.isAvailable else { return TZDK_ERR_UNAVAILABLE }
    let d = keyDir(dir)
    let fm = FileManager.default
    if fm.fileExists(atPath: signURL(d).path) || fm.fileExists(atPath: agreeURL(d).path) {
        return TZDK_ERR_BADARG
    }

    var acl: SecAccessControl? = nil
    if requireUserPresence != 0 {
        var acErr: Unmanaged<CFError>?
        guard let a = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.userPresence, .privateKeyUsage],
                &acErr) else {
            return TZDK_ERR_CRYPTO
        }
        acl = a
    }

    let sk: SecureEnclave.P256.Signing.PrivateKey
    let ak: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        if let acl {
            sk = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl)
            ak = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
        } else {
            sk = try SecureEnclave.P256.Signing.PrivateKey()
            ak = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        }
    } catch {
        return TZDK_ERR_CRYPTO
    }
    let r1 = storeBlob(sk.dataRepresentation, signURL(d))
    if r1 != TZDK_OK { return r1 }
    let r2 = storeBlob(ak.dataRepresentation, agreeURL(d))
    if r2 != TZDK_OK {
        // Do not leave a half-created identity behind.
        try? fm.removeItem(at: signURL(d))
        return r2
    }
    return TZDK_OK
}

/// Round-trips both keys to prove the enclave really answers. The daemon calls
/// this at startup: an unsanctioned path must fail loudly, never degrade quietly.
@_cdecl("tzdk_selftest")
public func tzdk_selftest(_ dir: UnsafePointer<CChar>) -> Int32 {
    let d = keyDir(dir)
    guard case .success(let sk) = openSigning(d) else { return TZDK_ERR_NOT_FOUND }
    guard case .success(let ak) = openAgreement(d) else { return TZDK_ERR_NOT_FOUND }
    guard let digest = RawSHA256Digest(Array(SHA256.hash(data: Data("tzdk-selftest".utf8)))),
          let sig = try? sk.signature(for: digest) else { return TZDK_ERR_CRYPTO }
    guard sk.publicKey.isValidSignature(sig, for: digest) else { return TZDK_ERR_CRYPTO }
    let eph = P256.KeyAgreement.PrivateKey()
    guard (try? eph.sharedSecretFromKeyAgreement(with: ak.publicKey)) != nil else {
        return TZDK_ERR_CRYPTO
    }
    return TZDK_OK
}

/// Raw x‖y of the SIGNING key — this is the device's public identity.
@_cdecl("tzdk_public_key")
public func tzdk_public_key(_ dir: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    switch openSigning(keyDir(dir)) {
    case .failure(let e): return e.code
    case .success(let k):
        let raw = k.publicKey.rawRepresentation
        guard raw.count == 64 else { return TZDK_ERR_CRYPTO }
        raw.copyBytes(to: out, count: 64)
        return TZDK_OK
    }
}

/// Raw x‖y of the AGREEMENT key. Callers that wrap a secret without holding the
/// key — i.e. from the public half alone — need this one, not the signing key.
@_cdecl("tzdk_agreement_public_key")
public func tzdk_agreement_public_key(_ dir: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    switch openAgreement(keyDir(dir)) {
    case .failure(let e): return e.code
    case .success(let k):
        let raw = k.publicKey.rawRepresentation
        guard raw.count == 64 else { return TZDK_ERR_CRYPTO }
        raw.copyBytes(to: out, count: 64)
        return TZDK_OK
    }
}

// The device is backed by two hardware keys, so something has to say which one
// speaks for it. Settled practice (MLS RFC 9420 LeafNode, Signal X3DH) is: the
// SIGNING key is the identity, and the agreement key is a subordinate credential
// bound to it by a signature. A peer must verify this binding before it ECDHs to
// the agreement key, otherwise an attacker could advertise its own agreement key
// against someone else's identity.
//
// Domain-separated so a binding can never be replayed as some other signature
// this key also produces.
let TZDK_BINDING_CONTEXT = Data("tenzro/device-binding/v1".utf8)

/// Writes signing_pub(64) ‖ agreement_pub(64) ‖ signature(64).
/// The signature is over SHA256(CONTEXT ‖ agreement_pub), by the signing key.
@_cdecl("tzdk_identity")
public func tzdk_identity(_ dir: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    let d = keyDir(dir)
    guard case .success(let sk) = openSigning(d) else { return TZDK_ERR_NOT_FOUND }
    guard case .success(let ak) = openAgreement(d) else { return TZDK_ERR_NOT_FOUND }

    let signPub = sk.publicKey.rawRepresentation
    let agreePub = ak.publicKey.rawRepresentation
    guard signPub.count == 64, agreePub.count == 64 else { return TZDK_ERR_CRYPTO }

    var tbs = Data()
    tbs.append(TZDK_BINDING_CONTEXT)
    tbs.append(agreePub)
    guard let digest = RawSHA256Digest(Array(SHA256.hash(data: tbs))),
          let sig = try? sk.signature(for: digest) else { return TZDK_ERR_CRYPTO }
    let raw = sig.rawRepresentation
    guard raw.count == 64 else { return TZDK_ERR_CRYPTO }

    (signPub + agreePub + raw).copyBytes(to: out, count: 192)
    return TZDK_OK
}

/// Sign a 32-byte prehash. Writes raw r‖s (64 bytes).
@_cdecl("tzdk_sign_prehash")
public func tzdk_sign_prehash(_ dir: UnsafePointer<CChar>,
                              _ hash: UnsafePointer<UInt8>,
                              _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    guard let digest = RawSHA256Digest(Array(UnsafeBufferPointer(start: hash, count: 32))) else {
        return TZDK_ERR_BADARG
    }
    switch openSigning(keyDir(dir)) {
    case .failure(let e): return e.code
    case .success(let k):
        guard let sig = try? k.signature(for: digest) else { return TZDK_ERR_CRYPTO }
        let raw = sig.rawRepresentation
        guard raw.count == 64 else { return TZDK_ERR_CRYPTO }
        raw.copyBytes(to: out, count: 64)
        return TZDK_OK
    }
}

// Wire format: ephemeral_pub(64) ‖ AES-GCM combined(nonce 12 ‖ ct ‖ tag 16).
// Deliberately OUR format, not Apple's ECIES: the enclave-side primitive is
// CryptoKit ECDH, and pretending to be `kSecKeyAlgorithmECIES…` while not being
// byte-compatible with it would be worse than owning the difference.
let TZDK_WRAP_SALT = Data("tenzro-device-key/v1".utf8)

@_cdecl("tzdk_wrap_secret")
public func tzdk_wrap_secret(_ dir: UnsafePointer<CChar>,
                             _ secret: UnsafePointer<UInt8>, _ secretLen: Int,
                             _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int,
                             _ outLen: UnsafeMutablePointer<Int>) -> Int32 {
    guard secretLen > 0 else { return TZDK_ERR_BADARG }
    switch openAgreement(keyDir(dir)) {
    case .failure(let e): return e.code
    case .success(let k):
        let eph = P256.KeyAgreement.PrivateKey()
        guard let ss = try? eph.sharedSecretFromKeyAgreement(with: k.publicKey) else {
            return TZDK_ERR_CRYPTO
        }
        let sym = ss.hkdfDerivedSymmetricKey(using: SHA256.self, salt: TZDK_WRAP_SALT,
                                             sharedInfo: Data(), outputByteCount: 32)
        let plaintext = Data(UnsafeBufferPointer(start: secret, count: secretLen))
        guard let sealed = try? AES.GCM.seal(plaintext, using: sym),
              let combined = sealed.combined else { return TZDK_ERR_CRYPTO }
        let blob = eph.publicKey.rawRepresentation + combined
        outLen.pointee = blob.count
        guard blob.count <= outCap else { return TZDK_ERR_BUFFER }
        blob.copyBytes(to: out, count: blob.count)
        return TZDK_OK
    }
}

@_cdecl("tzdk_unwrap_secret")
public func tzdk_unwrap_secret(_ dir: UnsafePointer<CChar>,
                               _ ct: UnsafePointer<UInt8>, _ ctLen: Int,
                               _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int,
                               _ outLen: UnsafeMutablePointer<Int>) -> Int32 {
    // 64 ephemeral pub + 12 nonce + 16 tag is the floor; anything shorter cannot
    // be one of ours and must not reach AES.GCM.
    guard ctLen > 64 + 12 + 16 else { return TZDK_ERR_BADARG }
    switch openAgreement(keyDir(dir)) {
    case .failure(let e): return e.code
    case .success(let k):
        let blob = Data(UnsafeBufferPointer(start: ct, count: ctLen))
        guard let ephPub = try? P256.KeyAgreement.PublicKey(rawRepresentation: blob.prefix(64)),
              let ss = try? k.sharedSecretFromKeyAgreement(with: ephPub) else {
            return TZDK_ERR_CRYPTO
        }
        let sym = ss.hkdfDerivedSymmetricKey(using: SHA256.self, salt: TZDK_WRAP_SALT,
                                             sharedInfo: Data(), outputByteCount: 32)
        guard let box = try? AES.GCM.SealedBox(combined: blob.dropFirst(64)),
              let plain = try? AES.GCM.open(box, using: sym) else {
            return TZDK_ERR_CRYPTO
        }
        outLen.pointee = plain.count
        guard plain.count <= outCap else { return TZDK_ERR_BUFFER }
        plain.copyBytes(to: out, count: plain.count)
        return TZDK_OK
    }
}

// MARK: - Raw ECDH, for HPKE DHKEM decapsulation
//
// RFC 9180 §4.1: Decap(enc, skR) = ExtractAndExpand(DH(skR, enc), kem_context).
// The ONLY private-key operation is DH(); everything after it is a KDF over
// public inputs. So an enclave that exposes nothing but ECDH is sufficient to
// be an HPKE recipient — confirmed by Apple's own swift-crypto, whose DHKEM
// `decapsulate` requires only `sharedSecretFromKeyAgreement(with:)`.
//
// `peerEnc` is the 65-byte SEC1 uncompressed ephemeral public key (0x04||X||Y).
// Writes the 32-byte x-coordinate. Per §7.1.1 the P-256 shared secret IS the
// x-coordinate — do not pass the full point on.
@_cdecl("tzdk_ecdh")
public func tzdk_ecdh(_ dir: UnsafePointer<CChar>,
                      _ peerEnc: UnsafePointer<UInt8>, _ peerEncLen: Int,
                      _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    guard peerEncLen == 65 else { return TZDK_ERR_BADARG }
    let raw = Data(UnsafeBufferPointer(start: peerEnc, count: peerEncLen))
    guard raw.first == 0x04 else { return TZDK_ERR_BADARG }

    // CryptoKit's rawRepresentation is X||Y without the SEC1 prefix. Validation
    // (on-curve, not identity) happens inside this initialiser, so a malformed
    // ephemeral key is rejected here rather than reaching the enclave.
    guard let peer = try? P256.KeyAgreement.PublicKey(rawRepresentation: raw.dropFirst()) else {
        return TZDK_ERR_BADARG
    }
    switch openAgreement(keyDir(dir)) {
    case .failure(let e): return e.code
    case .success(let k):
        guard let ss = try? k.sharedSecretFromKeyAgreement(with: peer) else {
            return TZDK_ERR_CRYPTO
        }
        // SharedSecret is exactly Ndh = 32 bytes for P-256, already x-only.
        let n = ss.withUnsafeBytes { buf -> Int in
            guard buf.count == 32 else { return -1 }
            out.update(from: buf.bindMemory(to: UInt8.self).baseAddress!, count: 32)
            return 32
        }
        return n == 32 ? TZDK_OK : TZDK_ERR_CRYPTO
    }
}

/// SEC1 uncompressed (0x04||X||Y, 65 bytes) agreement public key — what HPKE
/// calls `pkRm` and puts in the KEM context. The 64-byte form elsewhere in this
/// crate is NOT interchangeable: dropping the prefix changes `kem_context` and
/// every peer's derived secret.
@_cdecl("tzdk_agreement_public_key_sec1")
public func tzdk_agreement_public_key_sec1(_ dir: UnsafePointer<CChar>,
                                           _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    switch openAgreement(keyDir(dir)) {
    case .failure(let e): return e.code
    case .success(let k):
        let raw = k.publicKey.rawRepresentation
        guard raw.count == 64 else { return TZDK_ERR_CRYPTO }
        (Data([0x04]) + raw).copyBytes(to: out, count: 65)
        return TZDK_OK
    }
}

@_cdecl("tzdk_delete")
public func tzdk_delete(_ dir: UnsafePointer<CChar>) -> Int32 {
    let d = keyDir(dir)
    let fm = FileManager.default
    // Idempotent: a missing file is a success, an undeletable one is not.
    for u in [signURL(d), agreeURL(d)] where fm.fileExists(atPath: u.path) {
        guard (try? fm.removeItem(at: u)) != nil else { return TZDK_ERR_IO }
    }
    return TZDK_OK
}
