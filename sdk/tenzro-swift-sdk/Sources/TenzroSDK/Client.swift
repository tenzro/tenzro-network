import Foundation

/// Minimal read-only Tenzro JSON-RPC client.
///
/// Method names follow the TypeScript SDK (`getChainId`, `getBalance`,
/// `getBlockNumber`, `getStatus`, ...). Only methods in the node's open
/// (no-auth) set are used.
public final class TenzroClient: Sendable {
    public static let mainnetRPC = URL(string: "https://rpc.tenzro.com")!
    /// Chain id 13380 (`0x3444`).
    public static let chainID: UInt64 = 13380

    private let endpoint: URL
    private let session: URLSession
    private let ids = IDCounter()

    public init(endpoint: URL = TenzroClient.mainnetRPC, session: URLSession = .shared) {
        self.endpoint = endpoint
        self.session = session
    }

    public convenience init(endpoint: String) throws {
        guard let u = URL(string: endpoint), u.scheme != nil else { throw TenzroError.invalidURL(endpoint) }
        self.init(endpoint: u)
    }

    // MARK: Reads

    public func getChainId() async throws -> UInt64 {
        try parseHexUInt64(try await call("eth_chainId"))
    }

    public func getBlockNumber() async throws -> UInt64 {
        try parseHexUInt64(try await call("eth_blockNumber"))
    }

    public func getBalance(_ address: String) async throws -> Balance {
        let raw: String = try await call("tenzro_getBalance", [address])
        return Balance(raw: raw, decimal: try hexQuantityToDecimalString(raw))
    }

    public func getNonce(_ address: String) async throws -> UInt64 {
        try parseHexUInt64(try await call("tenzro_getNonce", [address]))
    }

    /// The node's own status report (`tenzro_getNodeStatus`).
    public func getStatus() async throws -> NodeStatus {
        try await call("tenzro_getNodeStatus")
    }

    public func isConnected() async -> Bool {
        (try? await getChainId()) != nil
    }

    /// Resolve a DID document via `tenzro_resolveDidDocument`. The response
    /// schema is not modeled; it is returned as loosely-typed JSON.
    public func resolveDidDocument(_ did: TenzroDID) async throws -> JSONValue {
        try await call("tenzro_resolveDidDocument", [did.description])
    }

    // MARK: Generic call

    /// Call any JSON-RPC method. `P` and `R` are your own `Codable` shapes.
    public func call<R: Decodable & Sendable, P: Encodable & Sendable>(_ method: String, _ params: P) async throws -> R {
        let id = ids.next()
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONEncoder().encode(RPCRequest(id: id, method: method, params: params))
        let (data, http) = try await send(req)
        try Self.checkStatus(http, data)
        let env: RPCResponse<R>
        do { env = try JSONDecoder().decode(RPCResponse<R>.self, from: data) }
        catch { throw TenzroError.decoding(String(describing: error)) }
        if let e = env.error { throw TenzroError.rpc(e) }
        guard let r = env.result else { throw TenzroError.decoding("response has neither result nor error") }
        return r
    }

    public func call<R: Decodable & Sendable>(_ method: String) async throws -> R {
        try await call(method, [String]())
    }

    // MARK: Payment-gated HTTP (x402 / MPP): typed surfacing of 402 only

    /// GET a URL. If the server answers HTTP 402 this throws
    /// `TenzroError.paymentRequired` carrying the challenge. No payment is
    /// made or retried.
    public func get(_ url: URL, headers: [String: String] = [:]) async throws -> (Data, HTTPURLResponse) {
        var req = URLRequest(url: url)
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let (data, http) = try await send(req)
        try Self.checkStatus(http, data)
        return (data, http)
    }

    // MARK: Internals

    private func send(_ req: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else { throw TenzroError.transport("non-HTTP response") }
            return (data, http)
        } catch let e as TenzroError {
            throw e
        } catch {
            throw TenzroError.transport(error.localizedDescription)
        }
    }

    static func checkStatus(_ http: HTTPURLResponse, _ data: Data) throws {
        if http.statusCode == 402 {
            throw TenzroError.paymentRequired(PaymentChallenge(
                paymentRequiredHeader: http.value(forHTTPHeaderField: "PAYMENT-REQUIRED"),
                wwwAuthenticate: http.value(forHTTPHeaderField: "WWW-Authenticate"),
                body: data))
        }
        guard (200..<300).contains(http.statusCode) else {
            throw TenzroError.http(status: http.statusCode, body: data)
        }
    }
}

private final class IDCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func next() -> Int { lock.lock(); defer { lock.unlock() }; n += 1; return n }
}
