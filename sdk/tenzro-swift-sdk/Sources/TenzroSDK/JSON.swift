import Foundation

/// A loosely-typed JSON value, for responses whose schema the SDK does not model.
public enum JSONValue: Codable, Sendable, Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }

    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }
    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var doubleValue: Double? { if case .number(let n) = self { return n }; return nil }
}

/// JSON-RPC 2.0 request envelope.
struct RPCRequest<P: Encodable & Sendable>: Encodable, Sendable {
    let jsonrpc = "2.0"
    let id: Int
    let method: String
    let params: P
}

/// JSON-RPC 2.0 response envelope.
struct RPCResponse<R: Decodable & Sendable>: Decodable, Sendable {
    let result: R?
    let error: RPCErrorObject?
}

/// Parse an Ethereum-style hex quantity (`0x3444`) into a `UInt64`.
public func parseHexUInt64(_ s: String) throws -> UInt64 {
    guard s.hasPrefix("0x") || s.hasPrefix("0X"), let v = UInt64(s.dropFirst(2), radix: 16) else {
        throw TenzroError.invalidHex(s)
    }
    return v
}

/// Parse a hex quantity into a decimal string. Balances can exceed `UInt64`
/// (wei-style 18-decimals), and Swift has no built-in big integer, so this
/// does the base conversion on digit arrays.
public func hexQuantityToDecimalString(_ s: String) throws -> String {
    guard s.hasPrefix("0x") || s.hasPrefix("0X") else { throw TenzroError.invalidHex(s) }
    var digits: [UInt8] = [0] // little-endian base-10 digits
    let hex = s.dropFirst(2)
    if hex.isEmpty { throw TenzroError.invalidHex(s) }
    for ch in hex {
        guard let nib = ch.hexDigitValue else { throw TenzroError.invalidHex(s) }
        var carry = nib
        for i in 0..<digits.count {
            let v = Int(digits[i]) * 16 + carry
            digits[i] = UInt8(v % 10)
            carry = v / 10
        }
        while carry > 0 { digits.append(UInt8(carry % 10)); carry /= 10 }
    }
    return String(digits.reversed().map { Character(String($0)) })
}
