// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {HashVoucherSigner} from "./HashVoucherSigner.sol";
import {Test, VmLog} from "./Cheats.sol";
import {TenzroAgentAccount, ITenzroFinality, PackedUserOperation} from "../src/TenzroAgentAccount.sol";
import {TenzroAgentAccountFactory} from "../src/TenzroAgentAccountFactory.sol";
import {TenzroFinalityClient} from "finality/TenzroFinalityClient.sol";
import {IRiscZeroVerifier} from "finality/vendor/risc0-ethereum/IRiscZeroVerifier.sol";
import {RiscZeroGroth16Verifier} from "finality/vendor/risc0-ethereum/groth16/RiscZeroGroth16Verifier.sol";

/// A finality client standing in for proofs that only a GPU prover makes:
/// it serves the state roots of the shared vectors.
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

    function mint(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }

    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 v) external returns (bool) {
        allowance[msg.sender][spender] = v;
        return true;
    }

    function transferFrom(address from, address to, uint256 v) external returns (bool) {
        allowance[from][msg.sender] -= v;
        balanceOf[from] -= v;
        balanceOf[to] += v;
        return true;
    }
}

/// Pulls a token from its caller, as a settlement lock's `lock` does.
contract Puller {
    function pull(address token, uint256 v) external {
        Token(token).transferFrom(msg.sender, address(this), v);
    }
}

/// The ERC-8004 identity registry's `setAgentWallet` consent check, as the
/// reference registry runs it: an ECDSA signature by the new wallet over the
/// EIP-712 digest, else the wallet's ERC-1271 answer for that digest.
contract WalletConsentRegistry {
    error Expired();
    error InvalidWalletSig();

    mapping(uint256 => address) public agentWallet;

    function digest(uint256 chainId, address registry, uint256 agentId, address newWallet, address owner, uint256 deadline)
        public
        pure
        returns (bytes32)
    {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ERC8004IdentityRegistry"),
                keccak256("1"),
                chainId,
                registry
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)"),
                agentId,
                newWallet,
                owner,
                deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes calldata signature) external {
        if (block.timestamp > deadline || deadline > block.timestamp + 5 minutes) revert Expired();
        bytes32 d = digest(block.chainid, address(this), agentId, newWallet, msg.sender, deadline);
        bool ok;
        if (signature.length == 65) {
            (bytes32 r, bytes32 s) = abi.decode(signature[:64], (bytes32, bytes32));
            ok = ecrecover(d, uint8(signature[64]), r, s) == newWallet;
        }
        if (!ok) {
            (bool called, bytes memory res) =
                newWallet.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", d, signature));
            ok = called && res.length >= 32 && abi.decode(res, (bytes4)) == bytes4(0x1626ba7e);
        }
        if (!ok) revert InvalidWalletSig();
        agentWallet[agentId] = newWallet;
    }
}

contract AgentAccountTest is Test {
    string constant VECTORS = "../../../sdk/fixtures/remote_grant/vectors.json";
    string constant STATE = "../../../sdk/fixtures/state_proof/vectors.json";
    string constant C = ".chains[0]";
    bytes32 constant CONSENT_VECTOR = 0xb8ebe0d450f7d61b52c90b1f8407cdc0b8638bfbe0b9b03888748a0a7ee61d29;
    uint256 constant N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

    string json;
    string state;
    FinalityStub stub;
    TenzroAgentAccount account;
    string did;
    string caip19;

    function setUp() public {
        json = vm.readFile(VECTORS);
        state = vm.readFile(STATE);
        did = vm.parseJsonString(json, ".did");
        caip19 = vm.parseJsonString(json, string.concat(C, ".asset"));
        vm.chainId(8453);
        stub = new FinalityStub();
        stub.set(1, vm.parseJsonBytes32(state, ".root_v1"));
        stub.set(2, vm.parseJsonBytes32(state, ".root_v2"));
        TenzroAgentAccount impl = new TenzroAgentAccount(stub);
        address at = vm.parseJsonAddress(json, string.concat(C, ".account"));
        vm.etch(
            at,
            abi.encodePacked(hex"363d3d373d3d3d363d73", address(impl), hex"5af43d82803e903d91602b57fd5bf3")
        );
        account = TenzroAgentAccount(payable(at));
        account.initialize(did);
        vm.deal(at, 10 ether);
        Token t = new Token();
        vm.etch(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, address(t).code);
        Token(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913).mint(at, 1_000_000);
        vm.warp(vm.parseJsonUint(json, ".now_ms") / 1000);
    }

    function _sync(uint64 index, string memory version) internal {
        string memory g = keccak256(bytes(version)) == keccak256("v1") ? ".grant.bytes" : ".void_grant.bytes";
        account.sync(
            index,
            vm.parseJsonBytes(json, string.concat(C, g)),
            vm.parseJsonBytes(json, string.concat(C, ".proof_", version)),
            caip19,
            bytes32(uint256(0x77))
        );
    }

    function _action(string memory key) internal view returns (TenzroAgentAccount.Action memory a) {
        string memory p = string.concat(C, ".", key);
        a.target = address(bytes20(vm.parseJsonBytes(json, string.concat(p, ".target"))));
        a.selector = vm.parseJsonBytes(json, string.concat(p, ".selector"));
        a.amount = uint128(vm.parseJsonUint(json, string.concat(p, ".amount")));
        a.relayRefund = uint128(vm.parseJsonUint(json, string.concat(p, ".relay_refund")));
        a.data = vm.parseJsonBytes(json, string.concat(p, ".data"));
    }

    function _key(uint256 i) internal view returns (bytes32 x, bytes32 y, string memory op, bytes32[] memory proof) {
        string memory p = string.concat(".keys[", vm.toString(i), "]");
        bytes memory pk = vm.parseJsonBytes(json, string.concat(p, ".public_key"));
        assembly ("memory-safe") {
            x := mload(add(pk, 33))
            y := mload(add(pk, 65))
        }
        op = vm.parseJsonString(json, string.concat(p, ".operator_did"));
        proof = vm.parseJsonBytes32Array(json, string.concat(p, ".proof"));
    }

    function _sigFromHex(uint256 key, bytes memory rs) internal view returns (TenzroAgentAccount.Sig memory s) {
        (s.x, s.y, s.operatorDid, s.keyProof) = _key(key);
        bytes32 r;
        bytes32 sv;
        assembly ("memory-safe") {
            r := mload(add(rs, 32))
            sv := mload(add(rs, 64))
        }
        s.r = r;
        s.s = sv;
    }

    /// A low-S signature by test key `key` (scalars 0x11.., 0x22.., 0x33..).
    function _sign(uint256 key, bytes32 digest) internal view returns (TenzroAgentAccount.Sig memory s) {
        uint256 pk = uint256(0x1111111111111111111111111111111111111111111111111111111111111111) * (key + 1);
        (bytes32 r, bytes32 sv) = vm.signP256(pk, digest);
        if (uint256(sv) > N / 2) sv = bytes32(N - uint256(sv));
        (s.x, s.y, s.operatorDid, s.keyProof) = _key(key);
        s.r = r;
        s.s = sv;
    }

    function _one(TenzroAgentAccount.Sig memory s) internal pure returns (TenzroAgentAccount.Sig[] memory out) {
        out = new TenzroAgentAccount.Sig[](1);
        out[0] = s;
    }

    function _two(TenzroAgentAccount.Sig memory a, TenzroAgentAccount.Sig memory b)
        internal
        pure
        returns (TenzroAgentAccount.Sig[] memory out)
    {
        out = new TenzroAgentAccount.Sig[](2);
        out[0] = a;
        out[1] = b;
    }

    function _targetProof() internal view returns (bytes32[] memory) {
        return vm.parseJsonBytes32Array(json, string.concat(C, ".targets[0].proof"));
    }

    function test_the_account_is_where_tenzro_derives_it() public view {
        bytes32 salt = vm.parseJsonBytes32(json, string.concat(C, ".salt"));
        assertEq(salt, sha256(abi.encodePacked("tenzro/omni-account/v1", did)));
        address derived = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), bytes20(hex"4242424242424242424242424242424242424242"), salt, bytes32(hex"2424242424242424242424242424242424242424242424242424242424242424")))))
        );
        assertEq(derived, address(account));
        assertEq(account.treeKey(), vm.parseJsonBytes32(json, string.concat(C, ".tree_key")));
    }

    function test_the_factory_deploys_at_the_derived_address_once() public {
        TenzroAgentAccount impl = new TenzroAgentAccount(stub);
        TenzroAgentAccountFactory f = new TenzroAgentAccountFactory(address(impl));
        address a = f.accountOf(did);
        assertEq(f.createAccount(did), a);
        assertEq(f.createAccount(did), a);
        assertEq(TenzroAgentAccount(payable(a)).treeKey(), account.treeKey());
        bytes32 salt = sha256(abi.encodePacked("tenzro/omni-account/v1", did));
        assertEq(a, address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(f), salt, f.initCodeHash()))))));
        vm.expectRevert(TenzroAgentAccount.AlreadyInitialized.selector);
        TenzroAgentAccount(payable(a)).initialize("did:tenzro:machine:someone:else");
    }

    function test_a_signed_action_runs_under_a_synced_grant() public {
        bytes memory gb = vm.parseJsonBytes(json, string.concat(C, ".grant.bytes"));
        bytes memory pb = vm.parseJsonBytes(json, string.concat(C, ".proof_v1"));
        uint256 g0 = gasleft();
        account.sync(1, gb, pb, caip19, bytes32(uint256(0x77)));
        logGas("sync gas", g0 - gasleft());
        TenzroAgentAccount.Action memory a = _action("action");
        bytes32 digest = vm.parseJsonBytes32(json, string.concat(C, ".action_digest"));
        assertEq(account.actionDigest(a), digest);
        TenzroAgentAccount.Sig memory s = _sigFromHex(0, vm.parseJsonBytes(json, string.concat(C, ".action_signature")));
        uint256 before = address(this).balance;
        TenzroAgentAccount.Sig[] memory one = _one(s);
        bytes32[] memory tp = _targetProof();
        g0 = gasleft();
        account.act(a, one, tp);
        logGas("act gas", g0 - gasleft());
        assertEq(account.nonce(), 1);
        assertEq(account.spent(), 100);
        assertEq(address(this).balance - before, 5);
    }

    receive() external payable {}

    function test_a_stranger_or_a_wrong_key_is_refused() public {
        _sync(1, "v1");
        TenzroAgentAccount.Action memory a = _action("action");
        TenzroAgentAccount.Sig memory s = _sigFromHex(0, vm.parseJsonBytes(json, string.concat(C, ".stranger_signature")));
        vm.expectRevert(TenzroAgentAccount.BadSignature.selector);
        account.act(a, _one(s), _targetProof());
        bytes memory spk = vm.parseJsonBytes(json, string.concat(C, ".stranger_public_key"));
        bytes32 x;
        bytes32 y;
        assembly ("memory-safe") {
            x := mload(add(spk, 33))
            y := mload(add(spk, 65))
        }
        s.x = x;
        s.y = y;
        vm.expectRevert(TenzroAgentAccount.KeyNotInRoot.selector);
        account.act(a, _one(s), _targetProof());
    }

    function test_a_high_s_signature_is_refused() public {
        _sync(1, "v1");
        TenzroAgentAccount.Sig memory s = _sigFromHex(0, vm.parseJsonBytes(json, string.concat(C, ".action_signature_high_s")));
        vm.expectRevert(TenzroAgentAccount.HighS.selector);
        account.act(_action("action"), _one(s), _targetProof());
    }

    function test_a_replayed_action_is_refused() public {
        _sync(1, "v1");
        TenzroAgentAccount.Sig memory s = _sigFromHex(0, vm.parseJsonBytes(json, string.concat(C, ".action_signature")));
        account.act(_action("action"), _one(s), _targetProof());
        vm.expectRevert(TenzroAgentAccount.BadSignature.selector);
        account.act(_action("action"), _one(s), _targetProof());
    }

    function test_a_grant_of_another_chain_is_refused() public {
        vm.chainId(1);
        TenzroAgentAccount impl = new TenzroAgentAccount(stub);
        address other = address(0xBEEF);
        vm.etch(other, abi.encodePacked(hex"363d3d373d3d3d363d73", address(impl), hex"5af43d82803e903d91602b57fd5bf3"));
        TenzroAgentAccount(payable(other)).initialize(did);
        // Its tree key is the grant on eip155:1: the base grant's proof fails.
        vm.expectRevert(TenzroAgentAccount.BadStateProof.selector);
        TenzroAgentAccount(payable(other)).sync(
            1,
            vm.parseJsonBytes(json, string.concat(C, ".grant.bytes")),
            vm.parseJsonBytes(json, string.concat(C, ".proof_v1")),
            caip19,
            bytes32(0)
        );
    }

    function test_a_stale_grant_is_refused_and_a_void_stops_every_action() public {
        _sync(1, "v1");
        _sync(2, "v2");
        assertEq(account.nonce(), 0);
        vm.expectRevert(TenzroAgentAccount.StaleGrant.selector);
        _sync(1, "v1");
        TenzroAgentAccount.Sig memory s = _sigFromHex(0, vm.parseJsonBytes(json, string.concat(C, ".action_signature")));
        vm.expectRevert(TenzroAgentAccount.GrantVoid.selector);
        account.act(_action("action"), _one(s), _targetProof());
    }

    function test_a_forged_grant_or_proof_is_refused() public {
        bytes memory g = vm.parseJsonBytes(json, string.concat(C, ".grant.bytes"));
        g[200] = bytes1(uint8(g[200]) ^ 1);
        vm.expectRevert(TenzroAgentAccount.BadStateProof.selector);
        account.sync(1, g, vm.parseJsonBytes(json, string.concat(C, ".proof_v1")), caip19, bytes32(0));
        vm.expectRevert(TenzroAgentAccount.UnknownCheckpoint.selector);
        _sync(9, "v1");
    }

    function test_an_expired_grant_acts_no_more() public {
        _sync(1, "v1");
        vm.warp(vm.parseJsonUint(json, string.concat(C, ".grant.not_after_ms")) / 1000 + 1);
        TenzroAgentAccount.Sig memory s = _sigFromHex(0, vm.parseJsonBytes(json, string.concat(C, ".action_signature")));
        vm.expectRevert(TenzroAgentAccount.OutsideWindow.selector);
        account.act(_action("action"), _one(s), _targetProof());
    }

    function test_limits_cosigns_targets_and_refunds_are_enforced() public {
        _sync(1, "v1");
        TenzroAgentAccount.Action memory a = _action("action");
        a.amount = 401;
        TenzroAgentAccount.Sig[] memory pre272 = _one(_sign(0, account.actionDigest(a)));
        vm.expectRevert(TenzroAgentAccount.OverPerAction.selector);
        account.act(a, pre272, _targetProof());
        a.amount = 100;
        a.relayRefund = 11;
        TenzroAgentAccount.Sig[] memory pre276 = _one(_sign(0, account.actionDigest(a)));
        vm.expectRevert(TenzroAgentAccount.RelayOverCap.selector);
        account.act(a, pre276, _targetProof());
        a.relayRefund = 0;
        a.target = address(0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC);
        TenzroAgentAccount.Sig[] memory pre280 = _one(_sign(0, account.actionDigest(a)));
        vm.expectRevert(TenzroAgentAccount.TargetNotAllowed.selector);
        account.act(a, pre280, _targetProof());
        TenzroAgentAccount.Action memory big = _action("big_action");
        bytes32 d = account.actionDigest(big);
        vm.expectRevert(TenzroAgentAccount.CosignRequired.selector);
        account.act(big, _one(_sign(0, d)), _targetProof());
        // Two nodes of one operator are not a cosign.
        vm.expectRevert(TenzroAgentAccount.CosignRequired.selector);
        account.act(big, _two(_sign(0, d), _sign(2, d)), _targetProof());
        account.act(big, _two(_sign(0, d), _sign(1, d)), _targetProof());
        d = account.actionDigest(big);
        account.act(big, _two(_sign(0, d), _sign(1, d)), _targetProof());
        d = account.actionDigest(big);
        vm.expectRevert(TenzroAgentAccount.OverBudget.selector);
        account.act(big, _two(_sign(0, d), _sign(1, d)), _targetProof());
        assertEq(account.spent(), 700);
    }

    /// A grant of this test's own, as the only entry of a state tree.
    function _install(uint64 index, bytes memory g) internal {
        bytes32 tk = account.treeKey();
        bytes32 slots = sha256(abi.encodePacked(bytes1(0x00), g));
        uint256 slot = uint8(tk[31]);
        for (uint256 i = 0; i < 8; i++) {
            slots = (slot >> i) & 1 == 0
                ? sha256(abi.encodePacked(bytes1(0x03), slots, bytes32(0)))
                : sha256(abi.encodePacked(bytes1(0x03), bytes32(0), slots));
        }
        stub.set(index, sha256(abi.encodePacked(bytes1(0x02), bytes31(tk), slots)));
        account.sync(index, g, abi.encodePacked(hex"000002", new bytes(256)), _custom_asset, bytes32(0));
    }

    string _custom_asset;

    function _grant(uint64 seq, string memory asset, bytes32 payload, bytes32 targetsRoot) internal returns (bytes memory) {
        _custom_asset = asset;
        uint64 t = uint64(vm.parseJsonUint(json, ".now_ms"));
        return abi.encodePacked(
            uint8(1),
            sha256("eip155:8453"),
            bytes32(uint256(uint160(address(account)))),
            sha256(bytes(did)),
            uint64(1),
            seq,
            t - 1000,
            t + 600_000,
            sha256(bytes(asset)),
            uint128(1000),
            uint128(400),
            uint128(300),
            vm.parseJsonBytes32(json, ".keys_root"),
            targetsRoot,
            payload,
            uint128(10),
            uint8(0)
        );
    }

    function _encode(TenzroAgentAccount.Action memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint16(20), a.target, uint16(a.selector.length), a.selector, a.amount, a.relayRefund, uint32(a.data.length), a.data
        );
    }

    function test_an_outflow_above_the_stated_amount_is_refused() public {
        address token = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
        _install(5, _grant(5, caip19, bytes32(0), bytes32(0)));
        TenzroAgentAccount.Action memory a;
        a.target = token;
        a.selector = hex"a9059cbb";
        a.data = abi.encode(address(0x1234), uint256(500));
        a.amount = 100;
        bytes32[] memory none = new bytes32[](0);
        TenzroAgentAccount.Sig[] memory pre353 = _one(_sign(0, account.actionDigest(a)));
        vm.expectRevert(TenzroAgentAccount.OutflowAboveAmount.selector);
        account.act(a, pre353, none);
        a.data = abi.encode(address(0x1234), uint256(100));
        account.act(a, _one(_sign(0, account.actionDigest(a))), none);
        assertEq(Token(token).balanceOf(address(0x1234)), 100);
    }

    function test_a_target_pulls_exactly_the_stated_amount_and_keeps_no_allowance() public {
        address token = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
        Puller puller = new Puller();
        _install(5, _grant(5, caip19, bytes32(0), bytes32(0)));
        TenzroAgentAccount.Action memory a;
        a.target = address(puller);
        a.selector = abi.encodeWithSelector(Puller.pull.selector);
        a.data = abi.encode(token, uint256(101));
        a.amount = 100;
        bytes32[] memory none = new bytes32[](0);
        TenzroAgentAccount.Sig[] memory over = _one(_sign(0, account.actionDigest(a)));
        vm.expectRevert(TenzroAgentAccount.CallFailed.selector);
        account.act(a, over, none);
        a.data = abi.encode(token, uint256(100));
        account.act(a, _one(_sign(0, account.actionDigest(a))), none);
        assertEq(Token(token).balanceOf(address(puller)), 100);
        assertEq(Token(token).allowance(address(account), address(puller)), 0);
    }

    function test_an_exact_grant_runs_its_one_action_once() public {
        TenzroAgentAccount.Action memory a;
        a.target = address(0xBEEF);
        a.amount = 1 ether;
        _install(6, _grant(6, "eip155:8453/slip44:60", sha256(_encode(a)), bytes32(0)));
        bytes32[] memory none = new bytes32[](0);
        TenzroAgentAccount.Sig[] memory pre366 = _one(_sign(0, account.actionDigest(a)));
        vm.expectRevert(TenzroAgentAccount.ExactGrant.selector);
        account.act(a, pre366, none);
        TenzroAgentAccount.Action memory other;
        other.target = a.target;
        other.amount = 2 ether;
        vm.expectRevert(TenzroAgentAccount.PayloadMismatch.selector);
        account.actExact(other);
        account.actExact(a);
        assertEq(address(0xBEEF).balance, 1 ether);
        vm.expectRevert(TenzroAgentAccount.ExactUsed.selector);
        account.actExact(a);
    }

    function test_an_entry_point_operation_validates_only_a_signed_action() public {
        _sync(1, "v1");
        TenzroAgentAccount.Action memory a = _action("action");
        a.relayRefund = 0;
        TenzroAgentAccount.Sig[] memory sigs = _one(_sign(0, account.actionDigest(a)));
        PackedUserOperation memory op;
        op.sender = address(account);
        op.callData = abi.encodeCall(TenzroAgentAccount.act, (a, sigs, _targetProof()));
        address ep = account.ENTRY_POINT();
        vm.prank(ep);
        assertEq(account.validateUserOp(op, bytes32(0), 0), 0);
        sigs[0].s = bytes32(uint256(sigs[0].s) ^ 1);
        op.callData = abi.encodeCall(TenzroAgentAccount.act, (a, sigs, _targetProof()));
        vm.prank(ep);
        assertEq(account.validateUserOp(op, bytes32(0), 0), 1);
        op.callData = abi.encodeCall(TenzroAgentAccount.actExact, (a));
        vm.prank(ep);
        assertEq(account.validateUserOp(op, bytes32(0), 0), 1);
        vm.expectRevert(TenzroAgentAccount.NotEntryPoint.selector);
        account.validateUserOp(op, bytes32(0), 0);
    }

    /// The real finality client accepts a real recorded Groth16 seal and
    /// serves its state root.
    function test_the_finality_client_accepts_a_real_recorded_proof() public {
        string memory p = vm.readFile("../../../crates/tenzro-vm/tests/fixtures/finality_proof.json");
        RiscZeroGroth16Verifier v = new RiscZeroGroth16Verifier(
            0xa54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56,
            0x04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0
        );
        TenzroFinalityClient client = new TenzroFinalityClient(
            IRiscZeroVerifier(address(v)),
            vm.parseJsonBytes32(p, ".image_id"),
            1337,
            bytes32(hex"6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e"),
            0xf17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481
        );
        bytes memory journal = vm.parseJsonBytes(p, ".journal");
        bytes memory seal = vm.parseJsonBytes(p, ".evm_seal");
        uint256 g0 = gasleft();
        client.submit(journal, seal);
        logGas("checkpoint submit gas", g0 - gasleft());
        (, bytes32 root,,,) = client.checkpoints(7);
        assertEq(root, bytes32(hex"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"));
    }

    // ----- Payment module

    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function _selfAction(bytes4 selector, bytes memory args, uint128 amount)
        internal
        view
        returns (TenzroAgentAccount.Action memory a)
    {
        a.target = address(account);
        a.selector = abi.encodePacked(selector);
        a.data = args;
        a.amount = amount;
    }

    function _act(TenzroAgentAccount.Action memory a) internal {
        account.act(a, _one(_sign(0, account.actionDigest(a))), new bytes32[](0));
    }

    function test_a_payment_moves_the_asset_and_reports_it_for_tenzro() public {
        _install(7, _grant(7, caip19, bytes32(0), bytes32(0)));
        bytes32 payee = bytes32(uint256(0x55));
        TenzroAgentAccount.Action memory a = _selfAction(
            TenzroAgentAccount.pay.selector,
            abi.encode(address(0x1234), uint128(100), payee, bytes32(uint256(1)), bytes32(uint256(2)), uint64(30)),
            100
        );
        vm.recordLogs();
        _act(a);
        assertEq(Token(USDC).balanceOf(address(0x1234)), 100);
        assertEq(account.spent(), 100);
        VmLog[] memory logs = vm.getRecordedLogs();
        bytes memory expected = abi.encodePacked(
            uint8(4),
            sha256("eip155:8453"),
            bytes32(uint256(uint160(address(account)))),
            sha256(bytes(did)),
            uint64(7),
            uint64(0),
            payee,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            uint64(30),
            uint128(100)
        );
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == TenzroAgentAccount.Reported.selector) {
                assertEq(keccak256(abi.decode(logs[i].data, (bytes))), keccak256(expected));
                found = true;
            }
        }
        require(found, "no report");

        // Paying more than the action states is refused, as is a direct call.
        TenzroAgentAccount.Action memory over = _selfAction(
            TenzroAgentAccount.pay.selector,
            abi.encode(address(0x1234), uint128(150), payee, bytes32(0), bytes32(0), uint64(0)),
            100
        );
        TenzroAgentAccount.Sig[] memory sigs = _one(_sign(0, account.actionDigest(over)));
        vm.expectRevert(TenzroAgentAccount.OutflowAboveAmount.selector);
        account.act(over, sigs, new bytes32[](0));
        vm.expectRevert(TenzroAgentAccount.OnlySelf.selector);
        account.pay(address(this), 1, payee, bytes32(0), bytes32(0), 0);
    }

    function test_an_approved_hash_is_the_accounts_signature_only_under_its_grant() public {
        _install(8, _grant(8, caip19, bytes32(0), bytes32(0)));
        bytes32 h = keccak256("an EIP-3009 authorization");
        assertEq(uint256(uint32(account.isValidSignature(h, ""))), uint256(0xffffffff));
        _act(_selfAction(TenzroAgentAccount.approveHash.selector, abi.encode(h), 200));
        assertEq(uint256(uint32(account.isValidSignature(h, ""))), uint256(0x1626ba7e));
        assertEq(account.spent(), 200);
        vm.expectRevert(TenzroAgentAccount.OnlySelf.selector);
        account.approveHash(keccak256("other"));
        // A later grant ends every approval of the old one.
        _install(9, _grant(9, caip19, bytes32(0), bytes32(0)));
        assertEq(uint256(uint32(account.isValidSignature(h, ""))), uint256(0xffffffff));
    }

    function test_an_agent_account_consents_to_be_its_erc8004_agent_wallet() public {
        WalletConsentRegistry registry = new WalletConsentRegistry();
        // The digest Tenzro computes (tenzro-identity erc8004::consent).
        assertEq(
            registry.digest(
                8453, 0x8004A818BFB912233c491871b3d84c89A494BD9e, 7, address(0x1111111111111111111111111111111111111111),
                address(0x2222222222222222222222222222222222222222), 1_800_000_000
            ),
            CONSENT_VECTOR
        );
        _install(11, _grant(11, caip19, bytes32(0), bytes32(0)));
        uint256 deadline = block.timestamp + 300;
        bytes32 d = registry.digest(block.chainid, address(registry), 7, address(account), address(this), deadline);
        vm.expectRevert(WalletConsentRegistry.InvalidWalletSig.selector);
        registry.setAgentWallet(7, address(account), deadline, "");
        _act(_selfAction(TenzroAgentAccount.approveHash.selector, abi.encode(d), 0));
        registry.setAgentWallet(7, address(account), deadline, "");
        assertEq(registry.agentWallet(7), address(account));
        // The consent names its owner: another owner cannot use it.
        vm.prank(address(0xbeef));
        vm.expectRevert(WalletConsentRegistry.InvalidWalletSig.selector);
        registry.setAgentWallet(7, address(account), deadline, "");
        // A later grant ends the consent.
        _install(12, _grant(12, caip19, bytes32(0), bytes32(0)));
        vm.expectRevert(WalletConsentRegistry.InvalidWalletSig.selector);
        registry.setAgentWallet(7, address(account), deadline, "");
    }

    function test_a_channel_reserves_its_deposit_and_pays_signed_vouchers() public {
        _install(10, _grant(10, caip19, bytes32(0), bytes32(0)));
        uint256 balance = Token(USDC).balanceOf(address(account));
        vm.prank(address(account));
        Token(USDC).transfer(address(0xdead), balance - 300);
        uint64 expires = uint64(vm.parseJsonUint(json, ".now_ms")) + 60_000;
        _act(_selfAction(TenzroAgentAccount.openChannel.selector, abi.encode(address(0xCAFE), uint128(250), expires), 250));
        uint256 id = account.channelCount();
        assertEq(account.reserved(USDC), 250);

        // No action may spend what the channel holds.
        TenzroAgentAccount.Action memory drain;
        drain.target = USDC;
        drain.selector = hex"a9059cbb";
        drain.data = abi.encode(address(0x1234), uint256(100));
        drain.amount = 100;
        TenzroAgentAccount.Sig[] memory dsig = _one(_sign(0, account.actionDigest(drain)));
        vm.expectRevert(TenzroAgentAccount.ReservedFunds.selector);
        account.act(drain, dsig, new bytes32[](0));

        TenzroAgentAccount.Sig memory v = _sign(0, account.channelDigest(id, 100));
        account.claimChannel(id, 100, v);
        assertEq(Token(USDC).balanceOf(address(0xCAFE)), 100);
        vm.expectRevert(TenzroAgentAccount.BadVoucher.selector);
        account.claimChannel(id, 100, v);
        TenzroAgentAccount.Sig memory big = _sign(0, account.channelDigest(id, 251));
        vm.expectRevert(TenzroAgentAccount.BadVoucher.selector);
        account.claimChannel(id, 251, big);
        TenzroAgentAccount.Sig memory forged = _sign(0, account.channelDigest(id, 200));
        vm.expectRevert(TenzroAgentAccount.BadSignature.selector);
        account.claimChannel(id, 180, forged);
        account.claimChannel(id, 200, forged);
        assertEq(Token(USDC).balanceOf(address(0xCAFE)), 200);

        vm.expectRevert(TenzroAgentAccount.ChannelLive.selector);
        account.closeChannel(id);
        TenzroAgentAccount.Sig memory late = _sign(0, account.channelDigest(id, 250));
        vm.warp(expires / 1000 + 1);
        vm.expectRevert(TenzroAgentAccount.ChannelExpired.selector);
        account.claimChannel(id, 250, late);
        account.closeChannel(id);
        assertEq(account.reserved(USDC), 0);
    }

    /// A channel opened with hash-based keys pays only vouchers those keys
    /// signed, each key once and in rising order; a P-256 voucher, a
    /// voucher for another amount, a spent key or another channel's keys
    /// are refused.
    function test_a_hash_channel_pays_only_its_one_time_key_vouchers() public {
        _install(10, _grant(10, caip19, bytes32(0), bytes32(0)));
        uint256 balance = Token(USDC).balanceOf(address(account));
        vm.prank(address(account));
        Token(USDC).transfer(address(0xdead), balance - 300);
        uint64 expires = uint64(vm.parseJsonUint(json, ".now_ms")) + 60_000;
        bytes32 seed = bytes32(uint256(0x42));
        bytes32 ps = HashVoucherSigner.publicSeed(seed);
        bytes32[][] memory tree = HashVoucherSigner.levels(seed, 2);
        bytes32 root = tree[2][0];
        _act(
            _selfAction(
                TenzroAgentAccount.openHashChannel.selector,
                abi.encode(address(0xCAFE), uint128(250), expires, ps, uint8(2), root),
                250
            )
        );
        uint256 id = account.channelCount();
        assertEq(account.reserved(USDC), 250);
        (bytes32 kps, bytes32 kroot, uint8 kh, uint32 next) = account.voucherKeys(id);
        assertEq(kps, ps);
        assertEq(kroot, root);
        assertEq(kh, 2);
        assertEq(next, 0);

        // A P-256 voucher from a key of the grant does not pay this channel.
        TenzroAgentAccount.Sig memory p256 = _sign(0, account.channelDigest(id, 100));
        vm.expectRevert(TenzroAgentAccount.HashVoucherRequired.selector);
        account.claimChannel(id, 100, p256);

        bytes memory v100 = HashVoucherSigner.sign(seed, tree, 0, account.channelDigest(id, 100));
        assertTrue(account.hashVoucherValid(id, 100, v100), "the voucher is valid");
        assertFalse(account.hashVoucherValid(id, 101, v100), "not for another amount");
        vm.expectRevert(TenzroAgentAccount.BadSignature.selector);
        account.claimChannelHashed(id, 101, v100);
        account.claimChannelHashed(id, 100, v100);
        assertEq(Token(USDC).balanceOf(address(0xCAFE)), 100);
        vm.expectRevert(TenzroAgentAccount.BadVoucher.selector);
        account.claimChannelHashed(id, 100, v100);

        // Key 0 is spent: a second voucher signed with it is refused even
        // though it verifies.
        bytes memory again = HashVoucherSigner.sign(seed, tree, 0, account.channelDigest(id, 150));
        assertTrue(account.hashVoucherValid(id, 150, again), "it verifies");
        vm.expectRevert(TenzroAgentAccount.LeafSpent.selector);
        account.claimChannelHashed(id, 150, again);

        // Keys may be skipped (a node that crashed lost one), not reused.
        bytes memory v200 = HashVoucherSigner.sign(seed, tree, 2, account.channelDigest(id, 200));
        account.claimChannelHashed(id, 200, v200);
        assertEq(Token(USDC).balanceOf(address(0xCAFE)), 200);
        (,,, next) = account.voucherKeys(id);
        assertEq(next, 3);
        bytes memory v1 = HashVoucherSigner.sign(seed, tree, 1, account.channelDigest(id, 220));
        vm.expectRevert(TenzroAgentAccount.LeafSpent.selector);
        account.claimChannelHashed(id, 220, v1);

        // Another channel's keys sign nothing here.
        bytes32 other = bytes32(uint256(0x43));
        bytes memory foreign =
            HashVoucherSigner.sign(other, HashVoucherSigner.levels(other, 2), 3, account.channelDigest(id, 230));
        vm.expectRevert(TenzroAgentAccount.BadSignature.selector);
        account.claimChannelHashed(id, 230, foreign);
        bytes memory truncated = new bytes(v200.length - 32);
        vm.expectRevert(TenzroAgentAccount.BadSignature.selector);
        account.claimChannelHashed(id, 230, truncated);

        vm.warp(expires / 1000 + 1);
        account.closeChannel(id);
        assertEq(account.reserved(USDC), 0);
        (, kroot,,) = account.voucherKeys(id);
        assertEq(kroot, bytes32(0));
    }

    /// A P-256 channel takes no hash-based voucher, and a hash channel
    /// cannot be opened without a root or with a tree above the limit.
    function test_hash_vouchers_need_committed_keys() public {
        _install(10, _grant(10, caip19, bytes32(0), bytes32(0)));
        uint64 expires = uint64(vm.parseJsonUint(json, ".now_ms")) + 60_000;
        _act(_selfAction(TenzroAgentAccount.openChannel.selector, abi.encode(address(0xCAFE), uint128(10), expires), 10));
        uint256 id = account.channelCount();
        bytes32 seed = bytes32(uint256(0x42));
        bytes32[][] memory tree = HashVoucherSigner.levels(seed, 2);
        bytes memory v = HashVoucherSigner.sign(seed, tree, 0, account.channelDigest(id, 5));
        assertFalse(account.hashVoucherValid(id, 5, v), "no keys committed");
        vm.expectRevert(TenzroAgentAccount.BadVoucherKeys.selector);
        account.claimChannelHashed(id, 5, v);

        vm.prank(address(account));
        vm.expectRevert(TenzroAgentAccount.BadVoucherKeys.selector);
        account.openHashChannel(address(0xCAFE), 1, expires, bytes32(0), 2, bytes32(0));
        vm.prank(address(account));
        vm.expectRevert(TenzroAgentAccount.BadVoucherKeys.selector);
        account.openHashChannel(address(0xCAFE), 1, expires, bytes32(0), 21, bytes32(uint256(1)));
        vm.expectRevert(TenzroAgentAccount.OnlySelf.selector);
        account.openHashChannel(address(0xCAFE), 1, expires, bytes32(0), 2, bytes32(uint256(1)));
    }
}
