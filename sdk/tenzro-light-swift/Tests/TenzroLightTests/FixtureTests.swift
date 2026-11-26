import Foundation
import XCTest

@testable import TenzroLight

/// Replays the shared fixture: the node's replies the Rust core recorded.
final class Replay: Transport, @unchecked Sendable {
    let calls: [[String: Any]]

    init(_ calls: [[String: Any]]) { self.calls = calls }

    func call(method: String, paramsJson: String) throws -> String {
        for c in calls where c["method"] as? String == method && c["params"] as? String == paramsJson {
            return c["result"] as! String
        }
        throw TransportError.Failed(reason: "no recorded reply to \(method) \(paramsJson)")
    }
}

final class Down: Transport, @unchecked Sendable {
    func call(method: String, paramsJson: String) throws -> String {
        throw TransportError.Failed(reason: "connection refused")
    }
}

final class FixtureTests: XCTestCase {
    var fixture: [String: Any] = [:]
    var expect: [String: Any] { fixture["expect"] as! [String: Any] }
    var transport: Replay { Replay(fixture["calls"] as! [[String: Any]]) }
    var clock: Clock {
        let c = fixture["clock"] as! [String: Any]
        return Clock(
            nowMs: (c["now_ms"] as! NSNumber).uint64Value,
            maxAgeMs: (c["max_age_ms"] as! NSNumber).uint64Value,
            maxAheadMs: (c["max_ahead_ms"] as! NSNumber).uint64Value
        )
    }
    var chainId: UInt64 { (fixture["chain_id"] as! NSNumber).uint64Value }
    var genesis: String { fixture["genesis_hash"] as! String }

    override func setUpWithError() throws {
        let path = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../../fixtures/light-client/fixture.json")
        let data = try Data(contentsOf: path)
        fixture = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func client() throws -> LightClient {
        try LightClient(
            chainId: chainId,
            genesisHash: genesis,
            epoch: (fixture["epoch"] as! NSNumber).uint64Value,
            committeeRoot: fixture["committee_root"] as! String,
            committeeReplyJson: fixture["committee_reply"] as! String
        )
    }

    func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func testSyncsAndProvesAnIdentitysKeys() throws {
        let lc = try client()
        let cp = try lc.sync(transport: transport, clock: clock)
        let want = expect["checkpoint"] as! [String: Any]
        XCTAssertEqual(cp.index, (want["index"] as! NSNumber).uint64Value)
        XCTAssertEqual(hex(cp.stateRoot), want["state_root"] as! String)

        let id = expect["identity"] as! [String: Any]
        let proven = try XCTUnwrap(lc.resolveIdentity(transport: transport, did: id["did"] as! String, clock: clock))
        XCTAssertEqual(hex(proven.controllerKey), id["controller_key"] as! String)
        XCTAssertEqual(hex(proven.mlDsaKey), id["ml_dsa_key"] as! String)
        XCTAssertEqual(hex(proven.keyDigest), id["key_digest"] as! String)
        XCTAssertEqual(proven.revoked, id["revoked"] as! Bool)

        XCTAssertNil(try lc.resolveIdentity(transport: transport, did: expect["absent_did"] as! String, clock: clock))
    }

    func testProvesAnIdentitysKeyHistory() throws {
        let lc = try client()
        let cp = try lc.sync(transport: transport, clock: clock)
        let want = expect["key_history"] as! [String: Any]
        let did = (expect["identity"] as! [String: Any])["did"] as! String
        let history = try lc.keyHistory(transport: transport, did: did, clock: clock)
        XCTAssertEqual(history.epochs().count, (want["keys"] as! NSNumber).intValue)
        XCTAssertEqual(history.sequence(), (want["sequence"] as! NSNumber).uint64Value)
        XCTAssertEqual(hex(history.head()), want["head"] as! String)
        let key = try XCTUnwrap(history.keyAt(timeMs: cp.timestampMs))
        XCTAssertEqual(key.version, (want["version"] as! NSNumber).uint64Value)
        XCTAssertEqual(hex(key.ed25519), want["ed25519"] as! String)
        XCTAssertNil(history.keyAt(timeMs: key.effectiveFromMs - 1))
    }

    func testSavedStateRestoresAndRefusesARollback() throws {
        let lc = try client()
        let index = try lc.sync(transport: transport, clock: clock).index
        let saved = lc.save()
        let back = try LightClient.restore(saved: saved, chainId: chainId, genesisHash: genesis, atLeastIndex: index)
        XCTAssertEqual(back.latest()?.index, index)
        XCTAssertThrowsError(
            try LightClient.restore(saved: saved, chainId: chainId, genesisHash: genesis, atLeastIndex: index + 1)
        )
    }

    func testNothingIsReadBeforeACheckpointIsCertified() throws {
        let id = expect["identity"] as! [String: Any]
        XCTAssertThrowsError(try client().resolveIdentity(transport: transport, did: id["did"] as! String, clock: clock))
    }

    func testATransportFailureIsReported() throws {
        XCTAssertThrowsError(try client().sync(transport: Down(), clock: clock))
    }
}
