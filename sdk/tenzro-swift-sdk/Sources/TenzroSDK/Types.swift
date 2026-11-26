import Foundation

/// The node's own report (`tenzro_getNodeStatus`). Only fields observed on a
/// dev node are modeled; every field is optional so additions or removals on
/// the node do not break decoding.
public struct NodeStatus: Codable, Sendable, Equatable {
    public let state: String?
    public let roles: [String]?
    public let healthStatus: String?
    public let uptimeSecs: UInt64?
    public let blockHeight: UInt64?
    public let peerCount: UInt64?
    public let teeCapable: Bool?
    public let irohEnabled: Bool?

    enum CodingKeys: String, CodingKey {
        case state, roles
        case healthStatus = "health_status"
        case uptimeSecs = "uptime_secs"
        case blockHeight = "block_height"
        case peerCount = "peer_count"
        case teeCapable = "tee_capable"
        case irohEnabled = "iroh_enabled"
    }
}

/// An account balance. `raw` is the node's hex quantity; `decimal` is the same
/// value in base 10 (arbitrary size).
public struct Balance: Sendable, Equatable {
    public let raw: String
    public let decimal: String
}
