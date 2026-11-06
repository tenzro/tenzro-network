// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {TenzroStateProof} from "../agent-account/evm/src/TenzroStateProof.sol";

/// @notice The final checkpoints a Tenzro finality client holds.
interface ITenzroFinalityCheckpoints {
    function checkpoints(uint64 index)
        external
        view
        returns (bytes32 digest, bytes32 stateRoot, uint64 stateHeight, uint64 lastHeight, uint64 timestampMs);
}

/// @title Tenzro governance decisions, checked on an EVM chain.
/// @notice When Tenzro governance enacts a proposal, consensus state records
///         `governance_decision:<id>` as the SHA-256 of the executed
///         proposal record followed by the enacting height (big-endian
///         u64). A contract here accepts a decision by checking that record
///         with a state proof under the state root of a final checkpoint its
///         finality client holds. There is no key to compromise: the proof
///         is the authority.
contract TenzroGovernanceReceiptVerifier {
    /// @notice The finality client whose checkpoints decisions are proven under.
    ITenzroFinalityCheckpoints public immutable finality;

    error UnknownCheckpoint(uint64 index);

    constructor(ITenzroFinalityCheckpoints finality_) {
        finality = finality_;
    }

    /// @notice Where proposal `proposalId`'s decision record sits in the state tree.
    function decisionTreeKey(bytes32 proposalId) public pure returns (bytes32) {
        bytes memory slot = bytes.concat("governance_decision:", _hex(abi.encodePacked(proposalId)));
        return sha256(
            bytes.concat(
                "tenzro.state-trie.key",
                hex"0500",
                "state",
                "storage:ffffffffffffffffffffffffffffffffffffffff:",
                _hex(slot)
            )
        );
    }

    /// @notice Whether, at final checkpoint `index`, Tenzro governance had
    ///         enacted proposal `proposalId` at `executedHeight`, its executed
    ///         record hashing to `proposalRecordHash`, by the state `proof`.
    function verifyDecision(
        uint64 index,
        bytes32 proposalId,
        bytes32 proposalRecordHash,
        uint64 executedHeight,
        bytes calldata proof
    ) public view returns (bool) {
        (, bytes32 root,,,) = finality.checkpoints(index);
        if (root == bytes32(0)) revert UnknownCheckpoint(index);
        return TenzroStateProof.verifyAt(
            root, decisionTreeKey(proposalId), true, abi.encodePacked(proposalRecordHash, executedHeight), proof
        );
    }

    /// @notice Whether, at final checkpoint `index`, proposal `proposalId`
    ///         had no decision: it was not enacted, by the state `proof`.
    function verifyUndecided(uint64 index, bytes32 proposalId, bytes calldata proof) external view returns (bool) {
        (, bytes32 root,,,) = finality.checkpoints(index);
        if (root == bytes32(0)) revert UnknownCheckpoint(index);
        return TenzroStateProof.verifyAt(root, decisionTreeKey(proposalId), false, "", proof);
    }

    function _hex(bytes memory b) private pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(b.length * 2);
        for (uint256 i = 0; i < b.length; i++) {
            out[2 * i] = digits[uint8(b[i]) >> 4];
            out[2 * i + 1] = digits[uint8(b[i]) & 0x0f];
        }
    }
}
