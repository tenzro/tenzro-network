// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {TenzroStateProof} from "./TenzroStateProof.sol";
import {HashVoucher} from "./HashVoucher.sol";

/// @notice What the account reads of Tenzro's finality client.
interface ITenzroFinality {
    function checkpoints(uint64 index)
        external
        view
        returns (bytes32 digest, bytes32 stateRoot, uint64 stateHeight, uint64 lastHeight, uint64 timestampMs);
}

/// @notice ERC-4337 packed user operation (EntryPoint v0.9).
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice An ERC-20 balance read.
interface IERC20Balance {
    function balanceOf(address who) external view returns (uint256);
}

/// @notice A Tenzro agent's account on an EVM chain.
///
/// The account holds no key. Its authority is the grant Tenzro issued for the
/// agent on this chain, installed by anyone with `sync`: the grant bytes and
/// their state proof under the state root of a checkpoint Tenzro's finality
/// client accepted. An action runs with `act` when serving nodes of the agent
/// signed its digest with P-256 keys in the grant's key root (two of distinct
/// operators above the grant's cosign threshold), within the grant's budget,
/// per-action limit, time window and targets. An exact grant carries one
/// action, run once with `actExact`. A void grant stops every action.
contract TenzroAgentAccount {
    struct Action {
        address target;
        bytes selector;
        uint128 amount;
        uint128 relayRefund;
        bytes data;
    }

    struct Sig {
        bytes32 x;
        bytes32 y;
        string operatorDid;
        bytes32[] keyProof;
        bytes32 r;
        bytes32 s;
    }

    struct Grant {
        bytes32 chain;
        bytes32 account;
        bytes32 agent;
        uint64 termsVersion;
        uint64 seq;
        uint64 notBeforeMs;
        uint64 notAfterMs;
        bytes32 asset;
        uint128 budget;
        uint128 perActionMax;
        uint128 cosignAbove;
        bytes32 keysRoot;
        bytes32 targetsRoot;
        bytes32 payloadHash;
        uint128 relayFeeMax;
        bool isVoid;
    }

    uint256 private constant GRANT_LEN = 322;
    uint256 private constant P256_HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
    address private constant P256_VERIFY = address(0x100);
    /// @notice The ERC-4337 v0.9 EntryPoint, at one address on every chain.
    address public constant ENTRY_POINT = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;
    bytes private constant ACT_DOMAIN = "tenzro/agent-act/v1";

    ITenzroFinality public immutable finality;

    bool public initialized;
    bytes32 public agent;
    bytes32 public chainHash;
    bytes32 public treeKey;
    Grant internal grant;
    bool public installed;
    uint128 public spent;
    uint64 public nonce;
    bool public exactUsed;
    address public assetToken;
    bool public assetNative;

    /// A payment channel the account funds for one payee, claimed with
    /// cumulative vouchers a serving node signs.
    struct Channel {
        address payee;
        address token;
        bool native;
        uint128 deposit;
        uint128 claimed;
        uint64 expiresMs;
        bytes32 keysRoot;
    }

    bytes private constant CHANNEL_DOMAIN = "tenzro/agent-channel/v1";
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    uint8 private constant REPORT_PAID = 4;

    /// @notice Grant sequence (plus one) under which each hash was approved
    /// as the account's ERC-1271 signature.
    mapping(bytes32 => uint64) public approvedSeq;
    /// @notice Channels by id.
    mapping(uint256 => Channel) public channels;

    /// The one-time hash-based keys a channel committed to when it opened:
    /// the seed every hash of the channel is tweaked with, the root of the
    /// tree of 2^height keys, and the lowest key not yet spent here.
    struct VoucherKeys {
        bytes32 publicSeed;
        bytes32 root;
        uint8 height;
        uint32 nextLeaf;
    }

    /// @notice Hash-based voucher keys by channel id; a zero root means the
    /// channel takes P-256 vouchers.
    mapping(uint256 => VoucherKeys) public voucherKeys;
    uint256 public channelCount;
    /// @notice What open channels hold, per asset (the zero address for the
    /// native coin). No action may spend it.
    mapping(address => uint256) public reserved;

    event Synced(uint64 indexed seq, bool isVoid, bytes32 payee);
    /// @notice An account report Tenzro records through the chain's report
    /// route, in the layout Tenzro decodes.
    event Reported(bytes report);
    event Paid(bytes32 indexed payee, uint64 indexed seq, uint64 indexed nonce, address to, uint128 amount);
    event HashApproved(bytes32 indexed hash, uint64 indexed seq);
    event ChannelOpened(uint256 indexed id, address payee, uint128 deposit, uint64 expiresMs);
    event ChannelClaimed(uint256 indexed id, uint128 cumulative, uint128 paid);
    event ChannelClosed(uint256 indexed id, uint128 returned);
    event VoucherKeysCommitted(uint256 indexed id, bytes32 publicSeed, uint8 height, bytes32 root);
    event GrantClosed(uint64 indexed seq, uint128 spent);
    event Acted(uint64 indexed seq, uint64 indexed nonce, bytes32 digest, uint128 amount);

    error AlreadyInitialized();
    error NotInitialized();
    error P256Unavailable();
    error UnknownCheckpoint();
    error BadStateProof();
    error MalformedGrant();
    error NotThisAccount();
    error StaleGrant();
    error AssetMismatch();
    error NoLiveGrant();
    error GrantVoid();
    error OutsideWindow();
    error ExactGrant();
    error NotExact();
    error ExactUsed();
    error PayloadMismatch();
    error HighS();
    error BadSignature();
    error KeyNotInRoot();
    error CosignRequired();
    error TargetNotAllowed();
    error OverPerAction();
    error OverBudget();
    error RelayOverCap();
    error CallFailed();
    error ApproveFailed();
    error OutflowAboveAmount();
    error NotEntryPoint();
    error OnlySelf();
    error TransferFailed();
    error UnknownChannel();
    error ChannelExpired();
    error ChannelLive();
    error BadVoucher();
    error BadVoucherKeys();
    error HashVoucherRequired();
    error LeafSpent();
    error ReservedFunds();

    constructor(ITenzroFinality finality_) {
        finality = finality_;
        initialized = true;
    }

    /// @notice Bind the account to its agent on this chain. The factory calls
    /// it in the transaction that deploys the account.
    function initialize(string calldata did) external {
        if (initialized) revert AlreadyInitialized();
        _requireP256();
        initialized = true;
        string memory caip2 = string.concat("eip155:", _decimal(block.chainid));
        agent = sha256(bytes(did));
        chainHash = sha256(bytes(caip2));
        treeKey = _grantTreeKey(bytes(did), bytes(caip2));
    }

    /// @notice Install grant `grantBytes`, proven by `proof` under the state
    /// root of final checkpoint `index`: a later grant, or the void of the
    /// current one. `caip19` names the grant's asset; `payee` is the Tenzro
    /// account a relay task pays for installing a void.
    function sync(uint64 index, bytes calldata grantBytes, bytes calldata proof, string calldata caip19, bytes32 payee)
        external
    {
        if (!initialized) revert NotInitialized();
        (, bytes32 root,,,) = finality.checkpoints(index);
        if (root == bytes32(0)) revert UnknownCheckpoint();
        if (!TenzroStateProof.verifyAt(root, treeKey, true, grantBytes, proof)) revert BadStateProof();
        Grant memory g = _decode(grantBytes);
        if (g.chain != chainHash || g.agent != agent || g.account != bytes32(uint256(uint160(address(this))))) {
            revert NotThisAccount();
        }
        if (installed) {
            Grant storage cur = grant;
            bool later = g.seq > cur.seq;
            bool voids = g.seq == cur.seq && g.isVoid && !cur.isVoid;
            if (!later && !voids) revert StaleGrant();
            if (later) emit GrantClosed(cur.seq, spent);
        }
        if (sha256(bytes(caip19)) != g.asset) revert AssetMismatch();
        (assetToken, assetNative) = _asset(bytes(caip19));
        if (!installed || g.seq != grant.seq) {
            spent = 0;
            exactUsed = false;
        }
        grant = g;
        installed = true;
        emit Synced(g.seq, g.isVoid, payee);
    }

    /// @notice Run `a` under the live open grant, signed by serving nodes.
    function act(Action calldata a, Sig[] calldata sigs, bytes32[] calldata targetProof) external {
        bytes32 digest = _check(a, sigs, targetProof);
        if (msg.sender == ENTRY_POINT && a.relayRefund != 0) revert RelayOverCap();
        uint64 n = nonce;
        nonce = n + 1;
        spent += a.amount;
        _execute(a);
        if (a.relayRefund != 0) payable(msg.sender).transfer(a.relayRefund);
        emit Acted(grant.seq, n, digest, a.amount);
    }

    /// @notice Run the one action an exact grant carries, once.
    function actExact(Action calldata a) external {
        Grant storage g = grant;
        _live(g);
        if (!_isExact(g)) revert NotExact();
        if (exactUsed) revert ExactUsed();
        bytes32 h = sha256(_encode(a));
        if (h != g.payloadHash) revert PayloadMismatch();
        if (a.relayRefund > g.relayFeeMax) revert RelayOverCap();
        exactUsed = true;
        uint64 n = nonce;
        nonce = n + 1;
        spent += a.amount;
        _execute(a);
        if (a.relayRefund != 0) payable(msg.sender).transfer(a.relayRefund);
        emit Acted(g.seq, n, h, a.amount);
    }

    /// @notice ERC-4337 validation: an operation may only call `act` with
    /// signatures that pass every check `act` makes. The account holds no
    /// key, so the operation's own signature field is unused.
    function validateUserOp(PackedUserOperation calldata op, bytes32, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint();
        validationData = 1;
        if (op.callData.length >= 4 && bytes4(op.callData[:4]) == this.act.selector) {
            (Action memory a, Sig[] memory sigs, bytes32[] memory proof) =
                abi.decode(op.callData[4:], (Action, Sig[], bytes32[]));
            try this.checkAction(a, sigs, proof) {
                validationData = 0;
            } catch {}
        }
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            ok;
        }
    }

    /// @notice Every check `act` makes, without acting. Returns the digest.
    function checkAction(Action calldata a, Sig[] calldata sigs, bytes32[] calldata targetProof)
        external
        view
        returns (bytes32)
    {
        return _check(a, sigs, targetProof);
    }

    /// @notice The live grant.
    function liveGrant() external view returns (Grant memory) {
        return grant;
    }

    /// @notice The digest serving nodes sign for `a` as the next action.
    function actionDigest(Action calldata a) external view returns (bytes32) {
        return sha256(abi.encodePacked(ACT_DOMAIN, chainHash, bytes32(uint256(uint160(address(this)))), grant.seq, nonce, _encode(a)));
    }

    receive() external payable {}

    // ----- Payment module: every entry below runs as an action under the
    // live grant (target this account), so the grant's signatures, budget,
    // per-action limit, window and targets apply to it.

    /// @notice Pay `amount` of the grant's asset to `to` for the Tenzro
    /// account `payee`, bound to the request and quote it bought, and report
    /// it so Tenzro records the payment as this agent's.
    function pay(address to, uint128 amount, bytes32 payee, bytes32 requestDigest, bytes32 quoteDigest, uint64 usdE6)
        external
        payable
    {
        if (msg.sender != address(this)) revert OnlySelf();
        _transferOut(assetToken, assetNative, to, amount);
        uint64 n = nonce - 1;
        uint64 seq = grant.seq;
        emit Paid(payee, seq, n, to, amount);
        emit Reported(
            abi.encodePacked(
                REPORT_PAID,
                chainHash,
                bytes32(uint256(uint160(address(this)))),
                agent,
                seq,
                n,
                payee,
                requestDigest,
                quoteDigest,
                usdE6,
                amount
            )
        );
    }

    /// @notice Approve `hash` as this account's signature (ERC-1271) under the
    /// live grant, for a transfer the token pulls itself (EIP-3009): the
    /// action's amount counts against the grant when the hash is approved.
    function approveHash(bytes32 hash) external payable {
        if (msg.sender != address(this)) revert OnlySelf();
        approvedSeq[hash] = grant.seq + 1;
        emit HashApproved(hash, grant.seq);
    }

    /// @notice ERC-1271: a hash is signed while the grant it was approved
    /// under is the live one.
    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        Grant storage g = grant;
        uint256 nowMs = block.timestamp * 1000;
        if (
            !installed || g.isVoid || nowMs < g.notBeforeMs || nowMs > g.notAfterMs
                || approvedSeq[hash] != g.seq + 1
        ) {
            return 0xffffffff;
        }
        return ERC1271_MAGIC;
    }

    /// @notice Open a channel to `payee` holding the action's amount of the
    /// grant's asset until `expiresMs`, no later than the grant ends.
    function openChannel(address payee, uint128 deposit, uint64 expiresMs) external payable returns (uint256 id) {
        if (msg.sender != address(this)) revert OnlySelf();
        id = _openChannel(payee, deposit, expiresMs);
    }

    /// @notice Open a channel as `openChannel` does, paid only with vouchers
    /// signed by the one-time hash-based keys under `root`: 2^`height` keys,
    /// each tweaked with `publicSeed`, which the serving node gives for this
    /// channel. Those vouchers hold when ECDSA does not.
    function openHashChannel(
        address payee,
        uint128 deposit,
        uint64 expiresMs,
        bytes32 publicSeed,
        uint8 height,
        bytes32 root
    ) external payable returns (uint256 id) {
        if (msg.sender != address(this)) revert OnlySelf();
        if (root == bytes32(0) || height > HashVoucher.MAX_HEIGHT) revert BadVoucherKeys();
        id = _openChannel(payee, deposit, expiresMs);
        voucherKeys[id] = VoucherKeys(publicSeed, root, height, 0);
        emit VoucherKeysCommitted(id, publicSeed, height, root);
    }

    function _openChannel(address payee, uint128 deposit, uint64 expiresMs) internal returns (uint256 id) {
        Grant storage g = grant;
        if (expiresMs > g.notAfterMs) revert OutsideWindow();
        address key = assetNative ? address(0) : assetToken;
        reserved[key] += deposit;
        if (_assetBalance() < reserved[key]) revert ReservedFunds();
        id = ++channelCount;
        channels[id] = Channel(payee, assetToken, assetNative, deposit, 0, expiresMs, g.keysRoot);
        emit ChannelOpened(id, payee, deposit, expiresMs);
    }

    /// @notice Pay a channel's payee up to `cumulative`, signed by a serving
    /// node whose key was in the grant the channel opened under. Anyone may
    /// submit it; the money only goes to the payee. A void grant stops it.
    function claimChannel(uint256 id, uint128 cumulative, Sig calldata s) external {
        Channel storage c = channels[id];
        if (c.payee == address(0)) revert UnknownChannel();
        if (grant.isVoid) revert GrantVoid();
        if (block.timestamp * 1000 > c.expiresMs) revert ChannelExpired();
        if (cumulative <= c.claimed || cumulative > c.deposit) revert BadVoucher();
        if (voucherKeys[id].root != bytes32(0)) revert HashVoucherRequired();
        if (uint256(s.s) > P256_HALF_N) revert HighS();
        if (!_p256(channelDigest(id, cumulative), s.r, s.s, s.x, s.y)) revert BadSignature();
        bytes32 leaf = sha256(abi.encodePacked(bytes1(0x00), bytes1(0x04), s.x, s.y, bytes(s.operatorDid)));
        if (!_merkle(c.keysRoot, leaf, s.keyProof)) revert KeyNotInRoot();
        _pay(id, c, cumulative);
    }

    /// @notice Pay a hash-based channel's payee up to `cumulative`, signed
    /// by one of the one-time keys the channel committed to. Each key pays
    /// once: a voucher must spend a key above every key already spent here.
    function claimChannelHashed(uint256 id, uint128 cumulative, bytes calldata signature) external {
        Channel storage c = channels[id];
        if (c.payee == address(0)) revert UnknownChannel();
        if (grant.isVoid) revert GrantVoid();
        if (block.timestamp * 1000 > c.expiresMs) revert ChannelExpired();
        if (cumulative <= c.claimed || cumulative > c.deposit) revert BadVoucher();
        VoucherKeys storage k = voucherKeys[id];
        if (k.root == bytes32(0)) revert BadVoucherKeys();
        if (signature.length != HashVoucher.signatureLength(k.height)) revert BadSignature();
        uint32 leaf = HashVoucher.leafOf(signature);
        if (leaf < k.nextLeaf) revert LeafSpent();
        if (!HashVoucher.verify(k.publicSeed, k.height, k.root, channelDigest(id, cumulative), signature)) {
            revert BadSignature();
        }
        k.nextLeaf = leaf + 1;
        _pay(id, c, cumulative);
    }

    /// @notice Whether `signature` is a hash-based voucher for `cumulative`
    /// on channel `id` under the keys the channel committed to. It does not
    /// say whether the voucher can still be claimed.
    function hashVoucherValid(uint256 id, uint128 cumulative, bytes calldata signature) external view returns (bool) {
        VoucherKeys storage k = voucherKeys[id];
        if (k.root == bytes32(0)) return false;
        return HashVoucher.verify(k.publicSeed, k.height, k.root, channelDigest(id, cumulative), signature);
    }

    function _pay(uint256 id, Channel storage c, uint128 cumulative) internal {
        uint128 owed = cumulative - c.claimed;
        c.claimed = cumulative;
        reserved[c.native ? address(0) : c.token] -= owed;
        _transferOut(c.token, c.native, c.payee, owed);
        emit ChannelClaimed(id, cumulative, owed);
    }

    /// @notice After a channel expires, release what its payee did not
    /// claim back to the account. Anyone may send it.
    function closeChannel(uint256 id) external {
        Channel storage c = channels[id];
        if (c.payee == address(0)) revert UnknownChannel();
        if (block.timestamp * 1000 <= c.expiresMs) revert ChannelLive();
        uint128 returned = c.deposit - c.claimed;
        reserved[c.native ? address(0) : c.token] -= returned;
        delete channels[id];
        delete voucherKeys[id];
        emit ChannelClosed(id, returned);
    }

    /// @notice The digest a serving node signs for a channel voucher.
    function channelDigest(uint256 id, uint128 cumulative) public view returns (bytes32) {
        return sha256(
            abi.encodePacked(CHANNEL_DOMAIN, chainHash, bytes32(uint256(uint160(address(this)))), uint64(id), cumulative)
        );
    }

    function _transferOut(address token, bool native, address to, uint128 amount) internal {
        bool ok;
        bytes memory ret;
        if (native) {
            (ok,) = payable(to).call{value: amount}("");
        } else {
            (ok, ret) = token.call(abi.encodeWithSelector(0xa9059cbb, to, uint256(amount)));
            ok = ok && (ret.length == 0 || abi.decode(ret, (bool)));
        }
        if (!ok) revert TransferFailed();
    }

    function _check(Action calldata a, Sig[] calldata sigs, bytes32[] calldata targetProof)
        internal
        view
        returns (bytes32 digest)
    {
        Grant storage g = grant;
        _live(g);
        if (_isExact(g)) revert ExactGrant();
        if (a.amount > g.perActionMax) revert OverPerAction();
        if (spent + a.amount > g.budget) revert OverBudget();
        if (a.relayRefund > g.relayFeeMax) revert RelayOverCap();
        if (g.targetsRoot != bytes32(0)) {
            bytes32 leaf = sha256(
                abi.encodePacked(bytes1(0x00), uint16(20), a.target, uint16(a.selector.length), a.selector)
            );
            if (!_merkle(g.targetsRoot, leaf, targetProof)) revert TargetNotAllowed();
        }
        digest = sha256(
            abi.encodePacked(ACT_DOMAIN, chainHash, bytes32(uint256(uint160(address(this)))), g.seq, nonce, _encode(a))
        );
        uint256 need = a.amount > g.cosignAbove ? 2 : 1;
        if (sigs.length < need) revert CosignRequired();
        bytes32 firstOperator;
        for (uint256 i = 0; i < need; i++) {
            Sig calldata s = sigs[i];
            if (uint256(s.s) > P256_HALF_N) revert HighS();
            if (!_p256(digest, s.r, s.s, s.x, s.y)) revert BadSignature();
            bytes32 leaf = sha256(abi.encodePacked(bytes1(0x00), bytes1(0x04), s.x, s.y, bytes(s.operatorDid)));
            if (!_merkle(g.keysRoot, leaf, s.keyProof)) revert KeyNotInRoot();
            bytes32 op = keccak256(bytes(s.operatorDid));
            if (i == 0) firstOperator = op;
            else if (op == firstOperator) revert CosignRequired();
        }
    }

    function _live(Grant storage g) internal view {
        if (!installed) revert NoLiveGrant();
        if (g.isVoid) revert GrantVoid();
        uint256 nowMs = block.timestamp * 1000;
        if (nowMs < g.notBeforeMs || nowMs > g.notAfterMs) revert OutsideWindow();
    }

    function _isExact(Grant storage g) internal view returns (bool) {
        return g.payloadHash != bytes32(0);
    }

    /// @dev For a token asset the target may pull exactly `a.amount` during
    /// the call (a settlement lock's `lock`, a payment contract), and no
    /// allowance outlives it.
    function _execute(Action calldata a) internal {
        uint256 before = _assetBalance();
        bool pulls = !assetNative && assetToken != address(0) && a.target != assetToken && a.amount > 0;
        if (pulls) _approve(a.target, a.amount);
        (bool ok,) = a.target.call{value: assetNative ? a.amount : 0}(bytes.concat(a.selector, a.data));
        if (!ok) revert CallFailed();
        if (pulls) _approve(a.target, 0);
        uint256 afterBalance = _assetBalance();
        if (afterBalance < before && before - afterBalance > a.amount) revert OutflowAboveAmount();
        if (afterBalance < reserved[assetNative ? address(0) : assetToken]) revert ReservedFunds();
    }

    /// @dev ERC-20 approve, accepting tokens that return nothing.
    function _approve(address spender, uint256 amount) internal {
        (bool ok, bytes memory ret) = assetToken.call(abi.encodeWithSelector(0x095ea7b3, spender, amount));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert ApproveFailed();
    }

    function _assetBalance() internal view returns (uint256) {
        if (assetNative) return address(this).balance;
        if (assetToken == address(0)) return 0;
        return IERC20Balance(assetToken).balanceOf(address(this));
    }

    function _encode(Action calldata a) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint16(20),
            a.target,
            uint16(a.selector.length),
            a.selector,
            a.amount,
            a.relayRefund,
            uint32(a.data.length),
            a.data
        );
    }

    function _merkle(bytes32 root, bytes32 leaf, bytes32[] calldata proof) internal pure returns (bool) {
        bytes32 acc = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 s = proof[i];
            acc = acc <= s
                ? sha256(abi.encodePacked(bytes1(0x01), acc, s))
                : sha256(abi.encodePacked(bytes1(0x01), s, acc));
        }
        return acc == root;
    }

    function _p256(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
        (bool ok, bytes memory out) = P256_VERIFY.staticcall(abi.encode(h, r, s, x, y));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    /// The chain must verify P-256 natively: a known signature must pass.
    function _requireP256() internal view {
        bytes32 h = 0xca39fc8e1aa5905ee376a18dce5c2ed75b6d4830a6303091fd8c2d394c2583dd;
        bytes32 r = 0x10e817b589e060ed04d162ecd1098dbdde356bd14ad7b581863bc4b23539c6a3;
        bytes32 s = 0x44554cfd80ff12661094d6f4d043b5d47dc7b32df5cb2af43b72a0050490b17e;
        bytes32 x = 0x0217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed;
        bytes32 y = 0x194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794;
        if (!_p256(h, r, s, x, y)) revert P256Unavailable();
    }

    function _decode(bytes calldata b) internal pure returns (Grant memory g) {
        if (b.length != GRANT_LEN || b[0] != 0x01) revert MalformedGrant();
        uint8 v = uint8(b[321]);
        if (v > 1) revert MalformedGrant();
        g.chain = bytes32(b[1:33]);
        g.account = bytes32(b[33:65]);
        g.agent = bytes32(b[65:97]);
        g.termsVersion = uint64(bytes8(b[97:105]));
        g.seq = uint64(bytes8(b[105:113]));
        g.notBeforeMs = uint64(bytes8(b[113:121]));
        g.notAfterMs = uint64(bytes8(b[121:129]));
        g.asset = bytes32(b[129:161]);
        g.budget = uint128(bytes16(b[161:177]));
        g.perActionMax = uint128(bytes16(b[177:193]));
        g.cosignAbove = uint128(bytes16(b[193:209]));
        g.keysRoot = bytes32(b[209:241]);
        g.targetsRoot = bytes32(b[241:273]);
        g.payloadHash = bytes32(b[273:305]);
        g.relayFeeMax = uint128(bytes16(b[305:321]));
        g.isVoid = v == 1;
    }

    /// The state tree key of the grant of `did` on `caip2`: VM system storage,
    /// keyed by the hex of `agent_grant:<did>:<caip2>`.
    function _grantTreeKey(bytes memory did, bytes memory caip2) internal pure returns (bytes32) {
        bytes memory key = bytes.concat("agent_grant:", did, ":", caip2);
        bytes memory hexKey = new bytes(key.length * 2);
        bytes16 digits = "0123456789abcdef";
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

    /// The asset a CAIP-19 id names: native for `slip44:60`, else an ERC-20.
    function _asset(bytes memory caip19) internal pure returns (address token, bool native) {
        bytes memory nativeTail = "/slip44:60";
        if (_endsWith(caip19, nativeTail)) return (address(0), true);
        bytes memory marker = "/erc20:0x";
        uint256 at = _find(caip19, marker);
        if (at == type(uint256).max || caip19.length != at + marker.length + 40) revert AssetMismatch();
        uint160 v;
        for (uint256 i = at + marker.length; i < caip19.length; i++) {
            uint8 c = uint8(caip19[i]);
            uint8 d;
            if (c >= 48 && c <= 57) d = c - 48;
            else if (c >= 97 && c <= 102) d = c - 87;
            else if (c >= 65 && c <= 70) d = c - 55;
            else revert AssetMismatch();
            v = (v << 4) | d;
        }
        return (address(v), false);
    }

    function _endsWith(bytes memory s, bytes memory tail) internal pure returns (bool) {
        if (s.length < tail.length) return false;
        for (uint256 i = 0; i < tail.length; i++) {
            if (s[s.length - tail.length + i] != tail[i]) return false;
        }
        return true;
    }

    function _find(bytes memory s, bytes memory needle) internal pure returns (uint256) {
        if (s.length < needle.length) return type(uint256).max;
        for (uint256 i = 0; i + needle.length <= s.length; i++) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (s[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) return i;
        }
        return type(uint256).max;
    }

    function _decimal(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 len;
        for (uint256 t = v; t != 0; t /= 10) len++;
        bytes memory out = new bytes(len);
        for (; v != 0; v /= 10) out[--len] = bytes1(uint8(48 + v % 10));
        return string(out);
    }
}
