import Foundation

/// A JSON-RPC 2.0 error object returned by the node.
public struct RPCErrorObject: Codable, Sendable, Equatable {
    public let code: Int
    public let message: String
}

/// A payment challenge surfaced from an HTTP 402 response (x402 / MPP).
///
/// This is typed surfacing only. The SDK does not build, sign or submit a
/// payment; the caller decides what to do with the challenge.
public struct PaymentChallenge: Sendable, Equatable {
    /// Value of the `PAYMENT-REQUIRED` header (x402), if present. Usually
    /// base64-encoded JSON.
    public let paymentRequiredHeader: String?
    /// Value of the `WWW-Authenticate` header (MPP `Payment` challenge), if present.
    public let wwwAuthenticate: String?
    /// Raw response body.
    public let body: Data
    /// Best-effort JSON decode of the x402 requirements (header first, then body).
    /// `nil` when neither parses as JSON. The schema is not validated.
    public var requirements: JSONValue? {
        if let h = paymentRequiredHeader {
            if let d = Data(base64Encoded: h), let v = try? JSONDecoder().decode(JSONValue.self, from: d) { return v }
            if let v = try? JSONDecoder().decode(JSONValue.self, from: Data(h.utf8)) { return v }
        }
        return try? JSONDecoder().decode(JSONValue.self, from: body)
    }
}

public enum TenzroError: Error, Sendable {
    case invalidURL(String)
    case transport(String)
    case http(status: Int, body: Data)
    /// HTTP 402: the endpoint wants payment.
    case paymentRequired(PaymentChallenge)
    case rpc(RPCErrorObject)
    case decoding(String)
    case invalidHex(String)
    case invalidDID(String)
    case invalidArgument(String)
}

extension TenzroError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidURL(let s): "invalid URL: \(s)"
        case .transport(let s): "transport error: \(s)"
        case .http(let st, _): "HTTP \(st)"
        case .paymentRequired: "HTTP 402 payment required"
        case .rpc(let e): "RPC error \(e.code): \(e.message)"
        case .decoding(let s): "decoding error: \(s)"
        case .invalidHex(let s): "invalid hex quantity: \(s)"
        case .invalidDID(let s): "invalid DID: \(s)"
        case .invalidArgument(let s): "invalid argument: \(s)"
        }
    }
}
