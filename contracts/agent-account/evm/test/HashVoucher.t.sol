// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "./Cheats.sol";
import {HashVoucher} from "../src/HashVoucher.sol";
import {HashVoucherSigner} from "./HashVoucherSigner.sol";

contract VoucherCheck {
    function verify(bytes32 publicSeed, uint256 height, bytes32 root, bytes32 digest, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return HashVoucher.verify(publicSeed, height, root, digest, signature);
    }
}

/// The contract's verifier against the vectors the Rust signer writes
/// (`sdk/fixtures/hash_voucher`), and a separate Solidity signer against
/// the same vectors.
contract HashVoucherTest is Test {
    string constant VECTORS = "../../../sdk/fixtures/hash_voucher/vectors.json";

    string json;
    VoucherCheck check;

    function setUp() public {
        json = vm.readFile(VECTORS);
        check = new VoucherCheck();
    }

    function _t(uint256 t, string memory field) internal pure returns (string memory) {
        return string.concat(".trees[", vm.toString(t), "].", field);
    }

    function _v(uint256 t, uint256 v, string memory field) internal pure returns (string memory) {
        return string.concat(".trees[", vm.toString(t), "].vouchers[", vm.toString(v), "].", field);
    }

    function _count(uint256 t) internal pure returns (uint256) {
        return t == 2 ? 3 : 4;
    }

    function _flip(bytes memory b, uint256 at) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        c[at] = c[at] ^ 0x01;
    }

    /// Every voucher the Rust signer signed verifies under its channel's
    /// keys, and nothing else does: another digest, root, seed or height,
    /// a changed leaf number, chain value or path value, or a truncated
    /// signature.
    function test_the_rust_signer_vouchers_verify_and_nothing_else_does() public view {
        for (uint256 t = 0; t < 3; t++) {
            bytes32 ps = vm.parseJsonBytes32(json, _t(t, "public_seed"));
            bytes32 root = vm.parseJsonBytes32(json, _t(t, "root"));
            uint256 height = vm.parseJsonUint(json, _t(t, "height"));
            for (uint256 v = 0; v < _count(t); v++) {
                bytes32 digest = vm.parseJsonBytes32(json, _v(t, v, "digest"));
                bytes memory sig = vm.parseJsonBytes(json, _v(t, v, "signature"));
                assertEq(sig.length, HashVoucher.signatureLength(height));
                assertTrue(check.verify(ps, height, root, digest, sig), "a signed voucher verifies");

                assertFalse(check.verify(ps, height, root, digest ^ bytes32(uint256(1)), sig), "another digest");
                assertFalse(check.verify(ps, height, root ^ bytes32(uint256(1)), digest, sig), "another root");
                assertFalse(check.verify(ps ^ bytes32(uint256(1)), height, root, digest, sig), "another seed");
                assertFalse(check.verify(ps, height + 1, root, digest, sig), "another height");
                assertFalse(check.verify(ps, height, root, digest, _flip(sig, 3)), "another leaf");
                assertFalse(check.verify(ps, height, root, digest, _flip(sig, 4 + 32 * 5)), "a changed chain");
                assertFalse(
                    check.verify(ps, height, root, digest, _flip(sig, 4 + 32 * 66 + 31)), "a changed checksum chain"
                );
                assertFalse(check.verify(ps, height, root, digest, _flip(sig, sig.length - 1)), "a changed path");
                bytes memory short = new bytes(sig.length - 1);
                for (uint256 i = 0; i < short.length; i++) {
                    short[i] = sig[i];
                }
                assertFalse(check.verify(ps, height, root, digest, short), "a truncated signature");
            }
        }
    }

    /// A voucher of one channel does not verify under another channel's keys.
    function test_a_voucher_does_not_verify_under_another_channel() public view {
        bytes32 digest = vm.parseJsonBytes32(json, _v(0, 1, "digest"));
        bytes memory sig = vm.parseJsonBytes(json, _v(0, 1, "signature"));
        bytes32 otherPs = vm.parseJsonBytes32(json, _t(1, "public_seed"));
        bytes32 otherRoot = vm.parseJsonBytes32(json, _t(1, "root"));
        assertFalse(check.verify(otherPs, 2, otherRoot, digest, sig), "another channel");
    }

    /// A tree above the tallest a channel may commit to is refused outright.
    function test_a_tree_above_the_limit_is_refused() public view {
        bytes memory sig = new bytes(HashVoucher.signatureLength(21));
        assertFalse(check.verify(bytes32(0), 21, bytes32(uint256(1)), bytes32(0), sig), "a tree above the limit");
    }

    /// A Solidity statement of the signer derives the same keys and the same
    /// signatures, byte for byte, as the Rust signer.
    function test_a_separate_signer_reproduces_the_rust_vectors() public view {
        string memory j = json;
        for (uint256 t = 0; t < 2; t++) {
            bytes32 seed = vm.parseJsonBytes32(j, _t(t, "seed"));
            uint8 height = uint8(vm.parseJsonUint(j, _t(t, "height")));
            assertEq(HashVoucherSigner.publicSeed(seed), vm.parseJsonBytes32(j, _t(t, "public_seed")));
            bytes32[][] memory tree = HashVoucherSigner.levels(seed, height);
            assertEq(tree[height][0], vm.parseJsonBytes32(j, _t(t, "root")));
            for (uint256 v = 0; v < _count(t); v++) {
                uint32 leaf = uint32(vm.parseJsonUint(j, _v(t, v, "leaf")));
                bytes32 digest = vm.parseJsonBytes32(j, _v(t, v, "digest"));
                assertEq(HashVoucherSigner.sign(seed, tree, leaf, digest), vm.parseJsonBytes(j, _v(t, v, "signature")));
            }
        }
    }

    /// Verifying a voucher of a channel of 1024 keys stays within a claim's
    /// gas.
    function test_verifying_a_voucher_of_1024_keys_costs_under_400k_gas() public view {
        bytes32 ps = vm.parseJsonBytes32(json, _t(2, "public_seed"));
        bytes32 root = vm.parseJsonBytes32(json, _t(2, "root"));
        bytes32 digest = vm.parseJsonBytes32(json, _v(2, 1, "digest"));
        bytes memory sig = vm.parseJsonBytes(json, _v(2, 1, "signature"));
        uint256 before = gasleft();
        assertTrue(check.verify(ps, 10, root, digest, sig), "it verifies");
        assertLt(before - gasleft(), 400_000);
    }
}
