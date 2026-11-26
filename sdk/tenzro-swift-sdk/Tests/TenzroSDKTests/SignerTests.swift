import Crypto
import Foundation
import Testing
@testable import TenzroSDK

/// The composite format and the software signer, held to the shared
/// hardware-signing vectors, `sdk/fixtures/hwsign/vectors.json`.
@Suite struct SignerTests {
    struct Vectors: Decodable {
        struct Case: Decodable {
            let context: String
            let message_hex: String
            let m_prime_hex: String
            let raw_signature_hex: String
        }
        let p256_public_key_xy_hex: String
        let account_address_hex: String
        let cases: [Case]
    }

    static let vectors: Vectors = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../../fixtures/hwsign/vectors.json")
        return try! JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }()

    static func hex(_ s: String) -> Data {
        var out = Data()
        var it = s.makeIterator()
        while let a = it.next(), let b = it.next() { out.append(UInt8(String([a, b]), radix: 16)!) }
        return out
    }

    @Test func theRepresentativeMatchesEveryVector() throws {
        for c in Self.vectors.cases {
            #expect(try Composite.messageRepresentative(context: c.context, message: Self.hex(c.message_hex))
                == Self.hex(c.m_prime_hex))
        }
    }

    @Test func theAccountAddressMatchesTheVector() throws {
        #expect(try Composite.accountAddress(p256XY: Self.hex(Self.vectors.p256_public_key_xy_hex))
            == "0x" + Self.vectors.account_address_hex)
    }

    @Test func aVectorSignatureVerifiesOnlyUnderItsOwnContext() {
        let xy = Self.hex(Self.vectors.p256_public_key_xy_hex)
        for c in Self.vectors.cases {
            let m = Self.hex(c.message_hex), sig = Self.hex(c.raw_signature_hex)
            #expect(Composite.verifyClassical(p256XY: xy, context: c.context, message: m, signature: sig))
            #expect(!Composite.verifyClassical(p256XY: xy, context: c.context + "/other", message: m, signature: sig))
        }
    }

    @Test func aHighSSignatureIsNormalisedToLowS() {
        let xy = Self.hex(Self.vectors.p256_public_key_xy_hex)
        for c in Self.vectors.cases {
            let sig = Self.hex(c.raw_signature_hex)
            let s = [UInt8](sig.suffix(32))
            let flipped = sig.prefix(32) + Data(Composite.subtract(Composite.order, s))
            for form in [sig, flipped] {
                let low = Composite.lowS(form)
                let ls = [UInt8](low.suffix(32))
                #expect(!Composite.subtract(Composite.order, ls).lexicographicallyPrecedes(ls))
                #expect(Composite.verifyClassical(p256XY: xy, context: c.context, message: Self.hex(c.message_hex), signature: low))
            }
        }
    }

    @Test func theSoftwareSignerMakesTheP256LegOfItsAccount() async throws {
        let signer = SoftwareP256Signer(key: try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32)))
        #expect(signer.publicKeyXY == Self.hex(Self.vectors.p256_public_key_xy_hex))
        #expect(try signer.address() == "0x" + Self.vectors.account_address_hex)
        let m = Data([1, 2, 3])
        let sig = try await signer.sign(context: "tenzro/signed-message", message: m)
        #expect(sig.mlDsa == nil)
        #expect(Composite.verifyClassical(p256XY: signer.publicKeyXY, context: "tenzro/signed-message", message: m, signature: sig.classical))
        #expect(!Composite.verifyClassical(p256XY: signer.publicKeyXY, context: "tenzro/tx", message: m, signature: sig.classical))
    }

    /// An ML-DSA-65 key that records what it is asked to sign.
    final class RecordingMlDsa: MlDsaSigner, @unchecked Sendable {
        let publicKey = Data(repeating: 9, count: 1952)
        let size: Int
        var asked: (context: String, message: Data)?
        init(size: Int = HybridSigner.mlDsaSignatureSize) { self.size = size }
        func sign(context: String, message: Data) async throws -> Data {
            asked = (context, message)
            return Data(repeating: 5, count: size)
        }
    }

    @Test func theHybridSignerAsksTheMlDsaKeyToSignTheSameRepresentativeUnderTheLabel() async throws {
        let p256 = SoftwareP256Signer(key: try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32)))
        let mlDsa = RecordingMlDsa()
        let signer = HybridSigner(p256: p256, mlDsa: mlDsa)
        #expect(signer.publicKeyXY == p256.publicKeyXY)
        let m = Data([1, 2, 3])
        let sig = try await signer.sign(context: "tenzro/tx", message: m)
        #expect(Composite.verifyClassical(p256XY: p256.publicKeyXY, context: "tenzro/tx", message: m, signature: sig.classical))
        #expect(sig.mlDsa == Data(repeating: 5, count: HybridSigner.mlDsaSignatureSize))
        #expect(mlDsa.asked?.context == "COMPSIG-MLDSA65-ECDSA-P256-SHA512")
        #expect(mlDsa.asked?.message == (try Composite.messageRepresentative(context: "tenzro/tx", message: m)))
    }

    @Test func anMlDsaSignatureOfTheWrongSizeIsRefused() async throws {
        let p256 = SoftwareP256Signer(key: try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32)))
        let signer = HybridSigner(p256: p256, mlDsa: RecordingMlDsa(size: 64))
        await #expect(throws: TenzroError.self) { try await signer.sign(context: "tenzro/tx", message: Data([1])) }
    }
}
