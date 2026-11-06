// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test, VmLog} from "cheats/Cheats.sol";
import {TenzroSettlementLock} from "../src/TenzroSettlementLock.sol";
import {ITenzroFinality} from "agent-account/TenzroAgentAccount.sol";

/// Serves the state root of the shared vectors.
contract FinalityStub is ITenzroFinality {
    mapping(uint64 => bytes32) public roots;

    function set(uint64 index, bytes32 root) external {
        roots[index] = root;
    }

    function checkpoints(uint64 index) external view returns (bytes32, bytes32, uint64, uint64, uint64) {
        return (bytes32(0), roots[index], 0, 0, 0);
    }
}

contract Token {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function approve(address spender, uint256 v) external returns (bool) {
        allowance[msg.sender][spender] = v;
        return true;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }

    function transferFrom(address from, address to, uint256 v) external returns (bool) {
        allowance[from][msg.sender] -= v;
        balanceOf[from] -= v;
        balanceOf[to] += v;
        return true;
    }
}

contract SettlementLockTest is Test {
    string constant VECTORS = "../../../sdk/fixtures/settlement_lock/vectors.json";
    uint64 constant HORIZON = 14 days;
    address constant PAYER = address(0xA11CE);
    address constant RECIPIENT = address(0xB0B);

    string json;
    FinalityStub stub;
    TenzroSettlementLock lock;
    Token token;

    function setUp() public {
        json = vm.readFile(VECTORS);
        stub = new FinalityStub();
        stub.set(1, vm.parseJsonBytes32(json, ".root"));
        lock = new TenzroSettlementLock(stub, HORIZON);
        token = new Token();
        token.mint(PAYER, 1_000);
        vm.prank(PAYER);
        token.approve(address(lock), type(uint256).max);
        vm.deal(PAYER, 10 ether);
    }

    function _plan(string memory which) internal view returns (bytes32) {
        return vm.parseJsonBytes32(json, string.concat(".", which, ".plan_id"));
    }

    function _decision(string memory which) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".", which, ".decision"));
    }

    function _proof(string memory which) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".", which, ".proof"));
    }

    function test_ids_and_tree_keys_match_tenzro() public view {
        bytes32 plan = _plan("committed");
        assertEq(lock.legId(plan, 1), vm.parseJsonBytes32(json, ".committed.leg_ids[1]"));
        assertEq(lock.decisionTreeKey(plan), vm.parseJsonBytes32(json, ".committed.tree_key"));
    }

    /// The Locked log Tenzro decodes (sdk/fixtures/settlement_lock/locked_event.json).
    function test_the_locked_event_matches_the_shared_vector() public {
        string memory ev = vm.readFile("../../../sdk/fixtures/settlement_lock/locked_event.json");
        vm.warp(vm.parseJsonUint(ev, ".timestamp"));
        bytes32 planId = vm.parseJsonBytes32(ev, ".plan_id");
        vm.recordLogs();
        vm.prank(PAYER);
        lock.lock{value: 700}(planId, 1, address(0), 700, RECIPIENT);
        VmLog[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("Locked(bytes32,bytes32,uint8,address,address,address,uint256,uint64)"));
        assertEq(logs[0].topics[1], planId);
        assertEq(logs[0].topics[2], vm.parseJsonBytes32(ev, ".leg_id"));
        assertEq(keccak256(logs[0].data), keccak256(vm.parseJsonBytes(ev, ".data")));
    }

    /// Locks, releases and refunds fold into the running hash Tenzro
    /// reconciles (sdk/fixtures/settlement_lock/recon.json), and `checkpoint`
    /// emits it with its count.
    function test_the_reconciliation_hash_matches_the_shared_vector() public {
        string memory rv = vm.readFile("../../../sdk/fixtures/settlement_lock/recon.json");
        bytes32 c = _plan("committed");
        bytes32 a = _plan("aborted");
        bytes32 u = _plan("undecided");
        vm.prank(PAYER);
        lock.lock(c, 0, address(token), 400, RECIPIENT);
        assertEq(lock.reconAcc(), vm.parseJsonBytes32(rv, ".entries[0].acc"));
        vm.prank(PAYER);
        lock.lock{value: 1 ether}(a, 2, address(0), 1 ether, RECIPIENT);
        lock.settle(c, 0, 1, _decision("committed"), _proof("committed"));
        lock.settle(a, 2, 1, _decision("aborted"), _proof("aborted"));
        vm.prank(PAYER);
        lock.lock(u, 1, address(token), 250, RECIPIENT);
        vm.warp(block.timestamp + HORIZON);
        lock.escape(u, 1);
        assertEq(lock.reconCount(), vm.parseJsonUint(rv, ".count"));
        bytes32 acc = vm.parseJsonBytes32(rv, ".acc");
        assertEq(lock.reconAcc(), acc);
        vm.recordLogs();
        lock.checkpoint();
        VmLog[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("Accumulator(uint64,bytes32)"));
        assertEq(keccak256(logs[0].data), keccak256(abi.encode(uint64(6), acc)));
    }

    function test_a_proven_commit_pays_the_recipient_once() public {
        bytes32 plan = _plan("committed");
        vm.prank(PAYER);
        lock.lock(plan, 0, address(token), 400, RECIPIENT);
        assertEq(token.balanceOf(address(lock)), 400);
        lock.settle(plan, 0, 1, _decision("committed"), _proof("committed"));
        assertEq(token.balanceOf(RECIPIENT), 400);
        // Replaying the proof settles nothing more.
        vm.expectRevert(TenzroSettlementLock.NotLocked.selector);
        lock.settle(plan, 0, 1, _decision("committed"), _proof("committed"));
    }

    function test_a_proven_abort_refunds_the_payer_in_the_native_coin() public {
        bytes32 plan = _plan("aborted");
        vm.prank(PAYER);
        lock.lock{value: 1 ether}(plan, 2, address(0), 1 ether, RECIPIENT);
        lock.settle(plan, 2, 1, _decision("aborted"), _proof("aborted"));
        assertEq(PAYER.balance, 10 ether);
        assertEq(RECIPIENT.balance, 0);
    }

    function test_another_plans_decision_or_a_forged_one_is_refused() public {
        bytes32 plan = _plan("undecided");
        vm.prank(PAYER);
        lock.lock(plan, 0, address(token), 100, RECIPIENT);
        // The committed plan's proven decision names another plan.
        vm.expectRevert(TenzroSettlementLock.BadDecision.selector);
        lock.settle(plan, 0, 1, _decision("committed"), _proof("committed"));
        // A commitment for this plan that Tenzro never wrote has no proof.
        bytes memory forged = _decision("committed");
        for (uint256 i = 0; i < 32; i++) {
            forged[10 + i] = plan[i];
        }
        vm.expectRevert(TenzroSettlementLock.BadStateProof.selector);
        lock.settle(plan, 0, 1, forged, _proof("committed"));
        // Nor does an unknown checkpoint.
        vm.expectRevert(TenzroSettlementLock.UnknownCheckpoint.selector);
        lock.settle(plan, 0, 9, _decision("committed"), _proof("committed"));
    }

    function test_no_refund_without_a_proven_abort_before_the_escape_horizon() public {
        bytes32 plan = _plan("undecided");
        vm.prank(PAYER);
        lock.lock(plan, 1, address(token), 250, RECIPIENT);
        vm.expectRevert(TenzroSettlementLock.TooEarly.selector);
        lock.escape(plan, 1);
        vm.warp(block.timestamp + HORIZON);
        lock.escape(plan, 1);
        assertEq(token.balanceOf(PAYER), 1_000);
        vm.expectRevert(TenzroSettlementLock.NotLocked.selector);
        lock.escape(plan, 1);
    }

    function test_a_leg_locks_once() public {
        bytes32 plan = _plan("committed");
        vm.prank(PAYER);
        lock.lock(plan, 0, address(token), 1, RECIPIENT);
        vm.prank(PAYER);
        vm.expectRevert(TenzroSettlementLock.AlreadyLocked.selector);
        lock.lock(plan, 0, address(token), 1, RECIPIENT);
    }

    function _receipts() internal returns (string memory r) {
        r = vm.readFile("../../../sdk/fixtures/settlement_lock/leg_receipts.json");
        stub.set(2, vm.parseJsonBytes32(r, ".root"));
    }

    function _provenReceipt(string memory r, string memory which)
        internal
        view
        returns (TenzroSettlementLock.LegReceipt memory)
    {
        return lock.provenLegReceipt(
            2,
            vm.parseJsonBytes32(r, string.concat(".", which, ".leg_id")),
            vm.parseJsonBytes(r, string.concat(".", which, ".receipt")),
            vm.parseJsonBytes(r, string.concat(".", which, ".proof"))
        );
    }

    function test_a_leg_receipt_proves_its_outcome_and_repaid_network_fee() public {
        string memory r = _receipts();
        assertEq(
            lock.legReceiptTreeKey(vm.parseJsonBytes32(r, ".committed.leg_id")),
            vm.parseJsonBytes32(r, ".committed.tree_key")
        );
        TenzroSettlementLock.LegReceipt memory got = _provenReceipt(r, "committed");
        assertEq(got.planId, vm.parseJsonBytes32(r, ".plan_id"));
        assertEq(uint256(got.index), 1);
        assertEq(got.committed ? 1 : 0, 1);
        assertEq(uint256(got.class), 2);
        assertEq(uint256(got.networkFee), vm.parseJsonUint(r, ".committed.network_fee"));
        assertEq(uint256(got.amount), vm.parseJsonUint(r, ".committed.amount"));
        assertEq(got.relayer, vm.parseJsonBytes32(r, ".committed.relayer"));
        got = _provenReceipt(r, "aborted");
        assertEq(got.committed ? 1 : 0, 0);
        assertEq(uint256(got.compensation), 3);
        assertEq(got.relayer, bytes32(0));
    }

    function test_another_legs_or_an_altered_receipt_proves_nothing() public {
        string memory r = _receipts();
        bytes32 leg = vm.parseJsonBytes32(r, ".committed.leg_id");
        bytes memory receipt = vm.parseJsonBytes(r, ".committed.receipt");
        bytes memory proof = vm.parseJsonBytes(r, ".committed.proof");
        vm.expectRevert(TenzroSettlementLock.BadReceipt.selector);
        lock.provenLegReceipt(2, vm.parseJsonBytes32(r, ".absent.leg_id"), receipt, proof);
        vm.expectRevert(TenzroSettlementLock.UnknownCheckpoint.selector);
        lock.provenLegReceipt(9, leg, receipt, proof);
        receipt[108] = bytes1(uint8(receipt[108]) ^ 1);
        vm.expectRevert(TenzroSettlementLock.BadStateProof.selector);
        lock.provenLegReceipt(2, leg, receipt, proof);
    }
}
