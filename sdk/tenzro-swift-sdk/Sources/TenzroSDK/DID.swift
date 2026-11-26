import Foundation

/// A parsed `did:tenzro:` identifier.
///
/// Forms (from the node's identity crate docs):
/// - `did:tenzro:human:{uuid}`
/// - `did:tenzro:machine:{uuid}` (autonomous agent)
/// - `did:tenzro:machine:{controller}:{uuid}` (delegated agent)
///
/// This is syntactic parsing only. It does not resolve the DID or verify
/// anything; resolution is the `tenzro_resolveDidDocument` RPC.
public struct TenzroDID: Sendable, Equatable, CustomStringConvertible {
    public enum Kind: String, Sendable { case human, machine }

    public let kind: Kind
    /// Everything after `did:tenzro:<kind>:`; for delegated agents this is
    /// `controller:uuid`.
    public let identifier: String

    public init(kind: Kind, identifier: String) {
        self.kind = kind
        self.identifier = identifier
    }

    public init(parsing s: String) throws {
        let parts = s.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, parts[0] == "did", parts[1] == "tenzro",
              let kind = Kind(rawValue: parts[2]),
              !parts[3...].contains(where: \.isEmpty) else {
            throw TenzroError.invalidDID(s)
        }
        self.kind = kind
        self.identifier = parts[3...].joined(separator: ":")
    }

    public var description: String { "did:tenzro:\(kind.rawValue):\(identifier)" }

    /// For a delegated agent, the controller portion (the part before the final UUID).
    public var controller: String? {
        guard kind == .machine else { return nil }
        let p = identifier.split(separator: ":")
        guard p.count >= 2 else { return nil }
        return p.dropLast().joined(separator: ":")
    }
}
