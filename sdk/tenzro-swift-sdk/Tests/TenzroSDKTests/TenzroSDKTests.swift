import Testing
import Foundation
@testable import TenzroSDK

// Offline tests always run. Live tests run only when TENZRO_RPC_URL is set,
// e.g. TENZRO_RPC_URL=http://127.0.0.1:28545 swift test

@Suite struct OfflineTests {
    @Test func hexParsing() throws {
        #expect(try parseHexUInt64("0x3444") == 13380)
        #expect(throws: TenzroError.self) { try parseHexUInt64("3444") }
    }

    @Test func hexToDecimal() throws {
        #expect(try hexQuantityToDecimalString("0x0") == "0")
        #expect(try hexQuantityToDecimalString("0xff") == "255")
        // 2^64 = 18446744073709551616
        #expect(try hexQuantityToDecimalString("0x10000000000000000") == "18446744073709551616")
        // 1e18 = 0xde0b6b3a7640000
        #expect(try hexQuantityToDecimalString("0xde0b6b3a7640000") == "1000000000000000000")
    }

    @Test func didParsing() throws {
        let h = try TenzroDID(parsing: "did:tenzro:human:abc-123")
        #expect(h.kind == .human)
        #expect(h.description == "did:tenzro:human:abc-123")
        let d = try TenzroDID(parsing: "did:tenzro:machine:ctrl:uuid1")
        #expect(d.controller == "ctrl")
        #expect(throws: TenzroError.self) { try TenzroDID(parsing: "did:web:example.com") }
        #expect(throws: TenzroError.self) { try TenzroDID(parsing: "did:tenzro:human:") }
    }

    @Test func paymentChallengeSurfacing() throws {
        let url = URL(string: "https://example.com/x")!
        let json = #"{"x402Version":2}"#
        let resp = HTTPURLResponse(url: url, statusCode: 402, httpVersion: nil,
                                   headerFields: ["PAYMENT-REQUIRED": Data(json.utf8).base64EncodedString()])!
        do {
            try TenzroClient.checkStatus(resp, Data())
            Issue.record("expected throw")
        } catch TenzroError.paymentRequired(let c) {
            #expect(c.requirements?["x402Version"]?.doubleValue == 2)
        }
    }

    @Test func nodeStatusDecodesWithMissingFields() throws {
        let s = try JSONDecoder().decode(NodeStatus.self, from: Data(#"{"state":"Running","block_height":5}"#.utf8))
        #expect(s.blockHeight == 5)
        #expect(s.peerCount == nil)
    }
}

private let liveURL = ProcessInfo.processInfo.environment["TENZRO_RPC_URL"]

@Suite(.enabled(if: liveURL != nil, "set TENZRO_RPC_URL to run live tests"))
struct LiveTests {
    let client = TenzroClient(endpoint: URL(string: liveURL ?? "http://127.0.0.1:1")!)

    @Test func chainId() async throws {
        #expect(try await client.getChainId() == 13380)
    }

    @Test func blockNumberAndStatus() async throws {
        _ = try await client.getBlockNumber()
        let s = try await client.getStatus()
        #expect(s.state != nil)
    }

    @Test func balanceOfUnfundedAddress() async throws {
        let b = try await client.getBalance("0x0000000000000000000000000000000000000001")
        #expect(!b.decimal.isEmpty)
    }

    @Test func unknownMethodSurfacesRPCError() async throws {
        await #expect(throws: TenzroError.self) {
            let _: String = try await client.call("tenzro_doesNotExist")
        }
    }
}
