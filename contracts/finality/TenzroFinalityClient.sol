// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IRiscZeroVerifier} from "./vendor/risc0-ethereum/IRiscZeroVerifier.sol";

/// @title Tenzro finality on an EVM chain.
/// @notice Holds the root of each Tenzro epoch's committee, starting from the
///         genesis committee, and accepts a Tenzro checkpoint when a Groth16
///         proof shows that the finality program verified the checkpoint's
///         certificate under the committee whose root it holds for that
///         epoch. A checkpoint that ends an epoch commits the next committee's
///         root, which this contract then holds for the next epoch. Anyone may
///         submit; a proof is accepted only on its own verification.
contract TenzroFinalityClient {
    /// @notice The statement the finality program commits, in the order its
    ///         journal encodes it.
    struct Journal {
        uint64 chainId;
        bytes32 genesisHash;
        uint64 epoch;
        bytes32 committeeRoot;
        uint64 index;
        bytes32 checkpointDigest;
        uint64 lastHeight;
        uint64 stateHeight;
        bytes32 stateRoot;
        bytes32 blocksRoot;
        bytes32 statementRoot;
        bytes32 nextCommitteeRoot;
        uint64 timestampMs;
    }

    /// @notice What is kept of a final checkpoint.
    struct Checkpoint {
        bytes32 digest;
        bytes32 stateRoot;
        uint64 stateHeight;
        uint64 lastHeight;
        uint64 timestampMs;
    }

    /// @notice Bytes of an encoded journal: thirteen words.
    uint256 public constant JOURNAL_LEN = 13 * 32;

    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    uint64 public immutable chainId;
    bytes32 public immutable genesisHash;

    /// @notice Committee root by epoch.
    mapping(uint64 => bytes32) public committeeRoot;
    /// @notice Final checkpoints by index.
    mapping(uint64 => Checkpoint) public checkpoints;
    /// @notice Highest final checkpoint index.
    uint64 public latestIndex;

    event CheckpointFinalized(uint64 indexed index, uint64 indexed epoch, bytes32 digest, bytes32 stateRoot, uint64 stateHeight);
    event CommitteeHandedOver(uint64 indexed epoch, bytes32 root);

    error MalformedJournal();
    error WrongChain();
    error UnknownCommittee(uint64 epoch);
    error AlreadyFinal(uint64 index);

    /// @param verifier_ The Groth16 receipt verifier.
    /// @param imageId_ The finality program's image id.
    /// @param chainId_ The Tenzro chain id.
    /// @param genesisHash_ The Tenzro genesis block hash.
    /// @param genesisCommitteeRoot The root of the genesis committee, from the
    ///        genesis file.
    constructor(
        IRiscZeroVerifier verifier_,
        bytes32 imageId_,
        uint64 chainId_,
        bytes32 genesisHash_,
        bytes32 genesisCommitteeRoot
    ) {
        verifier = verifier_;
        imageId = imageId_;
        chainId = chainId_;
        genesisHash = genesisHash_;
        committeeRoot[0] = genesisCommitteeRoot;
    }

    /// @notice Accept the checkpoint `journal` states, proven by `seal`.
    function submit(bytes calldata journal, bytes calldata seal) external {
        if (journal.length != JOURNAL_LEN) revert MalformedJournal();
        verifier.verify(seal, imageId, sha256(journal));
        Journal memory j = abi.decode(journal, (Journal));
        if (j.chainId != chainId || j.genesisHash != genesisHash) revert WrongChain();
        bytes32 root = committeeRoot[j.epoch];
        if (root == bytes32(0) || root != j.committeeRoot) revert UnknownCommittee(j.epoch);
        if (checkpoints[j.index].digest != bytes32(0)) revert AlreadyFinal(j.index);
        checkpoints[j.index] = Checkpoint(j.checkpointDigest, j.stateRoot, j.stateHeight, j.lastHeight, j.timestampMs);
        if (j.index > latestIndex) latestIndex = j.index;
        emit CheckpointFinalized(j.index, j.epoch, j.checkpointDigest, j.stateRoot, j.stateHeight);
        if (j.nextCommitteeRoot != bytes32(0) && committeeRoot[j.epoch + 1] == bytes32(0)) {
            committeeRoot[j.epoch + 1] = j.nextCommitteeRoot;
            emit CommitteeHandedOver(j.epoch + 1, j.nextCommitteeRoot);
        }
    }
}
