import Crypto
import Foundation

/// The composite signature format Tenzro accounts sign with: ML-DSA-65
/// paired with ECDSA over P-256 (draft-ietf-lamps-pq-composite-sigs). Both
/// legs sign the message representative
/// `M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)`, where `ctx` names
/// the protocol the signature is for; the P-256 leg is ECDSA over
/// `SHA-256(M')`.
public enum Composite {
    static let prefix = Data("CompositeAlgorithmSignatures2025".utf8)
    static let label = Data("COMPSIG-MLDSA65-ECDSA-P256-SHA512".utf8)

    /// The message representative `M'` of `message` under `context`.
    public static func messageRepresentative(context: String, message: Data) throws -> Data {
        let ctx = Data(context.utf8)
        guard ctx.count <= 255 else { throw TenzroError.invalidArgument("a context is at most 255 bytes") }
        var m = prefix + label
        m.append(UInt8(ctx.count))
        m.append(ctx)
        m.append(contentsOf: SHA512.hash(data: message))
        return m
    }

    /// The account address of a P-256 key `x || y`, `0x`-prefixed hex:
    /// `SHA-256("tenzro/account" || 0x02 || 0x40 || x || y)[..20]`.
    public static func accountAddress(p256XY: Data) throws -> String {
        guard p256XY.count == 64 else { throw TenzroError.invalidArgument("a P-256 key is 64 bytes, x || y") }
        var pre = Data("tenzro/account".utf8)
        pre.append(contentsOf: [0x02, 0x40])
        pre.append(p256XY)
        return "0x" + SHA256.hash(data: pre).prefix(20).map { String(format: "%02x", $0) }.joined()
    }

    /// The order of the P-256 group, big-endian.
    static let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ]

    /// `a - b` for 32-byte big-endian numbers with `a >= b`.
    static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            let d = Int(a[i]) - Int(b[i]) - borrow
            out[i] = UInt8((d + 256) % 256)
            borrow = d < 0 ? 1 : 0
        }
        return out
    }

    /// `signature` (`r || s`) with `s` in the lower half of the group order: one
    /// canonical form of the same signature (the node accepts either).
    public static func lowS(_ signature: Data) -> Data {
        guard signature.count == 64 else { return signature }
        let s = [UInt8](signature.suffix(32))
        // s is high when s > n - s, that is when n - s sorts before s.
        let other = subtract(order, s)
        guard other.lexicographicallyPrecedes(s) else { return signature }
        return signature.prefix(32) + Data(other)
    }

    /// Whether `signature` (`r || s`) is the P-256 leg of the key `x || y`
    /// over `message` under `context`.
    public static func verifyClassical(p256XY: Data, context: String, message: Data, signature: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(rawRepresentation: p256XY),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              let m = try? messageRepresentative(context: context, message: message)
        else { return false }
        return key.isValidSignature(sig, for: m)
    }
}

/// A composite signature: the P-256 leg and, when the signer holds one, the
/// ML-DSA-65 leg.
public struct CompositeSignature: Sendable, Equatable {
    /// ECDSA P-256 over `SHA-256(M')`, `r || s` (64 bytes).
    public let classical: Data
    /// The ML-DSA-65 leg over `M'`, or nil when the signer holds no ML-DSA-65 key.
    public let mlDsa: Data?
}

/// A key that signs for a Tenzro account in the composite format.
public protocol TenzroSigner: Sendable {
    /// The account's P-256 public key, `x || y` (64 bytes).
    var publicKeyXY: Data { get }
    /// Signs `message` for `context`. May prompt the user (biometrics).
    func sign(context: String, message: Data) async throws -> CompositeSignature
}

extension TenzroSigner {
    /// The account address the key derives.
    public func address() throws -> String { try Composite.accountAddress(p256XY: publicKeyXY) }
}

/// A key that makes the ML-DSA-65 leg of an account's composite signature.
/// The key is the account's enrolled one, held where its owner keeps it (a
/// TPM-derived key, a node the owner runs); this type only asks it to sign.
public protocol MlDsaSigner: Sendable {
    /// The ML-DSA-65 public key (1952 bytes).
    var publicKey: Data { get }
    /// Signs `message`, the composite message representative `M'`, with
    /// `context` as its FIPS 204 context string: the composite label.
    func sign(context: String, message: Data) async throws -> Data
}

/// An account's whole composite signature: the P-256 leg from `p256` and the
/// ML-DSA-65 leg from `mlDsa`, both over the same `M'`.
public struct HybridSigner: TenzroSigner {
    /// The size of an ML-DSA-65 signature.
    public static let mlDsaSignatureSize = 3309

    let p256: any TenzroSigner
    let mlDsa: any MlDsaSigner

    /// A signer whose P-256 leg is `p256`'s and whose ML-DSA-65 leg is `mlDsa`'s.
    public init(p256: any TenzroSigner, mlDsa: any MlDsaSigner) {
        self.p256 = p256
        self.mlDsa = mlDsa
    }

    public var publicKeyXY: Data { p256.publicKeyXY }

    public func sign(context: String, message: Data) async throws -> CompositeSignature {
        let classical = try await p256.sign(context: context, message: message).classical
        let m = try Composite.messageRepresentative(context: context, message: message)
        let leg = try await mlDsa.sign(context: String(decoding: Composite.label, as: UTF8.self), message: m)
        guard leg.count == Self.mlDsaSignatureSize else {
            throw TenzroError.invalidArgument("an ML-DSA-65 signature is \(Self.mlDsaSignatureSize) bytes")
        }
        return CompositeSignature(classical: classical, mlDsa: leg)
    }
}

/// The P-256 leg of an account key held in software. For tests and for keys
/// a caller already keeps safe; on Apple devices use `SecureEnclaveSigner`.
public struct SoftwareP256Signer: TenzroSigner {
    let key: P256.Signing.PrivateKey

    /// A signer over `key`.
    public init(key: P256.Signing.PrivateKey) { self.key = key }

    public var publicKeyXY: Data { key.publicKey.rawRepresentation }

    public func sign(context: String, message: Data) async throws -> CompositeSignature {
        let m = try Composite.messageRepresentative(context: context, message: message)
        return CompositeSignature(classical: Composite.lowS(try key.signature(for: m).rawRepresentation), mlDsa: nil)
    }
}

#if canImport(CryptoKit) && (os(iOS) || os(macOS) || os(visionOS))
// Crypto is CryptoKit on Apple platforms; SecAccessControl comes from Security.
import Security

/// The P-256 leg of an account key held in the Secure Enclave, which never
/// lets the private key leave it. Keep `dataRepresentation` (an encrypted
/// handle only this device's enclave can use) to reopen the key.
///
/// It holds no ML-DSA-65 key, so its signatures carry only the P-256 leg; an
/// account that has enrolled an ML-DSA-65 key, and every transaction and
/// payment authorization the ledger admits, need both legs: wrap it in a `HybridSigner` with the account's ML-DSA-65 key.
public struct SecureEnclaveSigner: TenzroSigner {
    let key: SecureEnclave.P256.Signing.PrivateKey

    /// A new key in the Secure Enclave.
    public init(accessControl: SecAccessControl? = nil) throws {
        key = try accessControl.map { try SecureEnclave.P256.Signing.PrivateKey(accessControl: $0) }
            ?? SecureEnclave.P256.Signing.PrivateKey()
    }

    /// The key whose handle `dataRepresentation` is.
    public init(dataRepresentation: Data) throws {
        key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
    }

    /// The encrypted handle to keep; useless on any other device.
    public var dataRepresentation: Data { key.dataRepresentation }

    public var publicKeyXY: Data { key.publicKey.rawRepresentation }

    public func sign(context: String, message: Data) async throws -> CompositeSignature {
        let m = try Composite.messageRepresentative(context: context, message: message)
        return CompositeSignature(classical: Composite.lowS(try key.signature(for: m).rawRepresentation), mlDsa: nil)
    }
}
#endif
