// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {TenzroStateProof} from "agent-account/TenzroStateProof.sol";
import {ITenzroFinality} from "agent-account/TenzroAgentAccount.sol";

/// @notice The ERC-20 calls the lock makes.
interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Tenzro settlement lock
/// @notice Holds one leg of a Tenzro settlement plan on this chain until
/// Tenzro decides the plan. The holder locks the leg's value here; anyone
/// may then present a state proof, under a final checkpoint of Tenzro's
/// finality client, of the plan's decision commitment at
/// `decision:<plan_id>`: a commit pays the leg's recipient, an abort refunds
/// its payer. Without a proven decision the payer can reclaim the leg only
/// after the escape horizon, so a refund cannot race a commit while Tenzro
/// is live. No key holds any authority here.
contract TenzroSettlementLock {
    /// Decision commitment: version (1) || outcome (1) || decided_at_ms (8) || plan_id (32).
    uint256 private constant DECISION_LEN = 42;
    uint8 private constant DECISION_VERSION = 1;
    uint8 private constant COMMIT = 1;
    uint8 private constant ABORT = 2;

    uint8 private constant LOCKED = 1;
    uint8 private constant RELEASED = 2;
    uint8 private constant REFUNDED = 3;
    /// Leg receipt at `plr:<legId>`: version (1) || outcome (1) || index (1) || class (1) || flags (1) ||
    /// decided_at_ms (8) || plan_id (32) || leg_id (32) || amount (16) || network_fee (16) || compensation (16) ||
    /// proof_digest (32) || relayer (32), integers big endian.
    uint256 private constant LEG_RECEIPT_LEN = 189;
    uint8 private constant LEG_RECEIPT_VERSION = 1;

    /// @notice One leg's outcome as Tenzro recorded it.
    struct LegReceipt {
        bytes32 planId;
        uint8 index;
        bool committed;
        /// 0 none, 1 native, 2 proven, 3 attested.
        uint8 class;
        uint64 decidedAtMs;
        uint128 amount;
        /// The network fee the commit repaid the leg's relayer, wei.
        uint128 networkFee;
        /// A rail leg's compensation, wei; zero when none was paid.
        uint128 compensation;
        /// Digest of the evidence that proved the leg; zero when none.
        bytes32 proofDigest;
        /// The relayer's Tenzro account; zero when no relayer carried a proof.
        bytes32 relayer;
    }

    struct Lock {
        address payer;
        address recipient;
        address token;
        uint64 escapeAt;
        uint8 state;
        uint256 amount;
    }

    /// @notice Tenzro's finality client on this chain.
    ITenzroFinality public immutable finality;
    /// @notice Seconds after locking before a payer may reclaim an undecided leg.
    uint64 public immutable escapeHorizon;

    /// @notice Locks by leg id.
    mapping(bytes32 => Lock) public locks;
    /// @notice Running hash over every lock, release and refund in order, for
    /// Tenzro to reconcile against its plans.
    bytes32 public reconAcc;
    /// @notice How many entries `reconAcc` folds.
    uint64 public reconCount;

    event Locked(
        bytes32 indexed planId,
        bytes32 indexed legId,
        uint8 index,
        address payer,
        address recipient,
        address token,
        uint256 amount,
        uint64 escapeAt
    );
    event Released(bytes32 indexed planId, bytes32 indexed legId, address to, uint256 amount);
    event Refunded(bytes32 indexed planId, bytes32 indexed legId, address to, uint256 amount, bool escaped);
    event Accumulator(uint64 count, bytes32 acc);

    error AlreadyLocked();
    error NotLocked();
    error BadAmount();
    error UnknownCheckpoint();
    error BadDecision();
    error BadReceipt();
    error BadStateProof();
    error TooEarly();
    error TransferFailed();

    constructor(ITenzroFinality finality_, uint64 escapeHorizon_) {
        finality = finality_;
        escapeHorizon = escapeHorizon_;
    }

    /// @notice The id Tenzro gives leg `index` of plan `planId`.
    function legId(bytes32 planId, uint8 index) public pure returns (bytes32) {
        return sha256(abi.encodePacked("tenzro/plan/leg/v1", planId, index));
    }

    /// @notice Lock `amount` of `token` (the zero address for the native coin)
    /// as leg `index` of plan `planId`, payable to `recipient` on a commit.
    function lock(bytes32 planId, uint8 index, address token, uint256 amount, address recipient) external payable {
        bytes32 id = legId(planId, index);
        if (locks[id].state != 0) revert AlreadyLocked();
        if (amount == 0) revert BadAmount();
        if (token == address(0)) {
            if (msg.value != amount) revert BadAmount();
        } else {
            if (msg.value != 0) revert BadAmount();
            if (!IERC20Transfer(token).transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        }
        uint64 escapeAt = uint64(block.timestamp) + escapeHorizon;
        locks[id] = Lock(msg.sender, recipient, token, escapeAt, LOCKED, amount);
        _record(planId, id, LOCKED, amount);
        emit Locked(planId, id, index, msg.sender, recipient, token, amount, escapeAt);
    }

    /// @notice Emit the running reconciliation hash and its count, for Tenzro
    /// to prove like a `Locked` event. Anyone may send it.
    function checkpoint() external {
        emit Accumulator(reconCount, reconAcc);
    }

    /// @notice Settle leg `index` of `planId` on the proven decision: `decision`
    /// is the commitment at `decision:<planId>` and `proof` its state proof
    /// under the state root of final checkpoint `tenzroCheckpoint`. Anyone may send it.
    function settle(bytes32 planId, uint8 index, uint64 tenzroCheckpoint, bytes calldata decision, bytes calldata proof)
        external
    {
        bytes32 id = legId(planId, index);
        Lock storage l = locks[id];
        if (l.state != LOCKED) revert NotLocked();
        (, bytes32 root,,,) = finality.checkpoints(tenzroCheckpoint);
        if (root == bytes32(0)) revert UnknownCheckpoint();
        if (decision.length != DECISION_LEN || uint8(decision[0]) != DECISION_VERSION) revert BadDecision();
        if (bytes32(decision[10:42]) != planId) revert BadDecision();
        uint8 outcome = uint8(decision[1]);
        if (outcome != COMMIT && outcome != ABORT) revert BadDecision();
        if (!TenzroStateProof.verifyAt(root, decisionTreeKey(planId), true, decision, proof)) revert BadStateProof();
        if (outcome == COMMIT) {
            l.state = RELEASED;
            _record(planId, id, RELEASED, l.amount);
            _pay(l.token, l.recipient, l.amount);
            emit Released(planId, id, l.recipient, l.amount);
        } else {
            l.state = REFUNDED;
            _record(planId, id, REFUNDED, l.amount);
            _pay(l.token, l.payer, l.amount);
            emit Refunded(planId, id, l.payer, l.amount, false);
        }
    }

    /// @notice Leg `legId`'s receipt, once `receipt` (the record at `plr:<legId>`) is proven by `proof` under the
    /// state root of final checkpoint `tenzroCheckpoint`. Reverts otherwise.
    function provenLegReceipt(uint64 tenzroCheckpoint, bytes32 legId_, bytes calldata receipt, bytes calldata proof)
        external
        view
        returns (LegReceipt memory)
    {
        _checkLegReceipt(legId_, receipt);
        (, bytes32 root,,,) = finality.checkpoints(tenzroCheckpoint);
        if (root == bytes32(0)) revert UnknownCheckpoint();
        if (!TenzroStateProof.verifyAt(root, legReceiptTreeKey(legId_), true, receipt, proof)) revert BadStateProof();
        return _decodeLegReceipt(receipt);
    }

    function _checkLegReceipt(bytes32 legId_, bytes calldata receipt) private pure {
        if (receipt.length != LEG_RECEIPT_LEN || uint8(receipt[0]) != LEG_RECEIPT_VERSION) revert BadReceipt();
        if (bytes32(receipt[45:77]) != legId_) revert BadReceipt();
        if (legId(bytes32(receipt[13:45]), uint8(receipt[2])) != legId_) revert BadReceipt();
        uint8 outcome = uint8(receipt[1]);
        if (outcome != COMMIT && outcome != ABORT) revert BadReceipt();
        if (uint8(receipt[3]) > 3 || uint8(receipt[4]) > 7) revert BadReceipt();
    }

    function _decodeLegReceipt(bytes calldata receipt) private pure returns (LegReceipt memory r) {
        r.planId = bytes32(receipt[13:45]);
        r.index = uint8(receipt[2]);
        r.committed = uint8(receipt[1]) == COMMIT;
        r.class = uint8(receipt[3]);
        r.decidedAtMs = uint64(bytes8(receipt[5:13]));
        r.amount = uint128(bytes16(receipt[77:93]));
        r.networkFee = uint128(bytes16(receipt[93:109]));
        r.compensation = uint128(bytes16(receipt[109:125]));
        r.proofDigest = bytes32(receipt[125:157]);
        r.relayer = bytes32(receipt[157:189]);
    }

    /// @notice Reclaim an undecided leg once its escape horizon has passed.
    function escape(bytes32 planId, uint8 index) external {
        bytes32 id = legId(planId, index);
        Lock storage l = locks[id];
        if (l.state != LOCKED) revert NotLocked();
        if (block.timestamp < l.escapeAt) revert TooEarly();
        l.state = REFUNDED;
        _record(planId, id, REFUNDED, l.amount);
        _pay(l.token, l.payer, l.amount);
        emit Refunded(planId, id, l.payer, l.amount, true);
    }

    /// @notice The state tree key of `decision:<planId>`.
    function decisionTreeKey(bytes32 planId) public pure returns (bytes32) {
        return _systemSlotTreeKey("decision:", planId);
    }

    /// @notice The state tree key of `plr:<legId>`.
    function legReceiptTreeKey(bytes32 legId_) public pure returns (bytes32) {
        return _systemSlotTreeKey("plr:", legId_);
    }

    /// The state tree key of the record `<prefix><hex id>` in VM system
    /// storage, keyed by the hex of the record key.
    function _systemSlotTreeKey(bytes memory prefix, bytes32 planId) private pure returns (bytes32) {
        bytes16 digits = "0123456789abcdef";
        bytes memory idHex = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            idHex[2 * i] = digits[uint8(planId[i]) >> 4];
            idHex[2 * i + 1] = digits[uint8(planId[i]) & 0x0f];
        }
        bytes memory key = bytes.concat(prefix, idHex);
        bytes memory hexKey = new bytes(key.length * 2);
        for (uint256 i = 0; i < key.length; i++) {
            hexKey[2 * i] = digits[uint8(key[i]) >> 4];
            hexKey[2 * i + 1] = digits[uint8(key[i]) & 0x0f];
        }
        return sha256(
            bytes.concat(
                "tenzro.state-trie.key",
                hex"0500",
                "state",
                "storage:ffffffffffffffffffffffffffffffffffffffff:",
                hexKey
            )
        );
    }

    /// Fold one entry (kind 1 locked, 2 released, 3 refunded) into the
    /// running reconciliation hash.
    function _record(bytes32 planId, bytes32 id, uint8 kind, uint256 amount) private {
        reconAcc = sha256(abi.encodePacked("tenzro/settlement/recon/v1", reconAcc, planId, id, kind, amount));
        reconCount += 1;
    }

    function _pay(address token, address to, uint256 amount) private {
        if (token == address(0)) {
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else if (!IERC20Transfer(token).transfer(to, amount)) {
            revert TransferFailed();
        }
    }
}
