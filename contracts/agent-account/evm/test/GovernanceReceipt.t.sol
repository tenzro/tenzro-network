// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "./Cheats.sol";
import {
    TenzroGovernanceReceiptVerifier,
    ITenzroFinalityCheckpoints
} from "finality/TenzroGovernanceReceiptVerifier.sol";

/// Serves the state root of the shared governance receipt vectors as final
/// checkpoint 1.
contract CheckpointStub is ITenzroFinalityCheckpoints {
    bytes32 public root;

    constructor(bytes32 root_) {
        root = root_;
    }

    function checkpoints(uint64 index) external view returns (bytes32, bytes32, uint64, uint64, uint64) {
        return (bytes32(0), index == 1 ? root : bytes32(0), 1, 1, 0);
    }
}

contract GovernanceReceiptTest is Test {
    string constant VECTORS = "../../../sdk/fixtures/governance_receipt/vectors.json";

    string json;
    TenzroGovernanceReceiptVerifier verifier;
    bytes32 id;
    bytes32 recordHash;
    uint64 height;

    function setUp() public {
        json = vm.readFile(VECTORS);
        verifier = new TenzroGovernanceReceiptVerifier(new CheckpointStub(vm.parseJsonBytes32(json, ".state_root")));
        id = vm.parseJsonBytes32(json, ".proposal_id");
        recordHash = vm.parseJsonBytes32(json, ".proposal_record_hash");
        height = uint64(vm.parseJsonUint(json, ".executed_height"));
    }

    function test_the_tree_key_is_where_tenzro_stores_the_decision() public view {
        assertEq(verifier.decisionTreeKey(id), vm.parseJsonBytes32(json, ".decision_tree_key"));
    }

    function test_a_real_decision_verifies_and_binds_its_proposal_record() public view {
        bytes memory proof = vm.parseJsonBytes(json, ".decision_proof");
        assertEq(sha256(vm.parseJsonBytes(json, ".proposal_record")), recordHash);
        require(verifier.verifyDecision(1, id, recordHash, height, proof), "the decision verifies");
        require(!verifier.verifyDecision(1, id, recordHash, height + 1, proof), "another height does not");
        require(!verifier.verifyDecision(1, id, bytes32(uint256(recordHash) ^ 1), height, proof), "another record does not");
        require(
            !verifier.verifyDecision(1, vm.parseJsonBytes32(json, ".absent_proposal_id"), recordHash, height, proof),
            "another proposal does not"
        );
    }

    function test_an_undecided_proposal_is_proven_absent() public view {
        bytes32 other = vm.parseJsonBytes32(json, ".absent_proposal_id");
        require(verifier.verifyUndecided(1, other, vm.parseJsonBytes(json, ".absent_decision_proof")), "absent");
        require(!verifier.verifyUndecided(1, id, vm.parseJsonBytes(json, ".decision_proof")), "a decided one is not");
    }

    function test_an_unknown_checkpoint_is_refused() public view {
        bytes memory proof = vm.parseJsonBytes(json, ".decision_proof");
        try verifier.verifyDecision(2, id, recordHash, height, proof) returns (bool) {
            revert("an unknown checkpoint must revert");
        } catch (bytes memory reason) {
            require(bytes4(reason) == TenzroGovernanceReceiptVerifier.UnknownCheckpoint.selector, "UnknownCheckpoint");
        }
    }
}
