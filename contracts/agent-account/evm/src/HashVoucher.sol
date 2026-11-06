// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Verifies a one-time hash-based voucher signature under the Merkle
/// root of the 2^height keys a channel commits to when it opens: WOTS+ with
/// Winternitz parameter 16 over SHA-256, the scheme of Tenzro's
/// `hash_voucher` signer byte for byte. It costs SHA-256 evaluations only,
/// no elliptic-curve arithmetic.
///
/// A signature is `leaf (4 bytes, big-endian) || 67 chain values || height
/// sibling hashes`, 32 bytes each. Every hash is domain separated; chain
/// steps and the leaf hash are tweaked with the channel's public seed, the
/// leaf and the position in the chain.
library HashVoucher {
    uint256 internal constant CHAINS = 67;
    uint256 internal constant LEN1 = 64;
    uint256 internal constant W_MAX = 15;
    uint256 internal constant MAX_HEIGHT = 20;

    /// @notice The length of a signature for a tree of `height`.
    function signatureLength(uint256 height) internal pure returns (uint256) {
        return 4 + 32 * (CHAINS + height);
    }

    /// @notice The one-time key a well-formed signature spends.
    function leafOf(bytes calldata signature) internal pure returns (uint32) {
        return uint32(bytes4(signature[:4]));
    }

    /// @notice Whether `signature` signs `digest` with one of the 2^`height`
    /// keys under `root`, all tweaked with `publicSeed`.
    function verify(bytes32 publicSeed, uint256 height, bytes32 root, bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (height > MAX_HEIGHT || signature.length != signatureLength(height)) return false;
        uint256 leaf = uint32(bytes4(signature[:4]));
        if (leaf >> height != 0) return false;

        // LEAF_DOMAIN || public seed || leaf || the top of each chain.
        bytes memory tops = new bytes(37 + 32 * CHAINS);
        assembly ("memory-safe") {
            let p := add(tops, 32)
            mstore(add(p, 1), publicSeed)
            mstore(add(p, 33), shl(224, leaf))
            mstore8(p, 0x02)
        }
        uint256 checksum;
        for (uint256 c = 0; c < CHAINS; c++) {
            uint256 digit;
            if (c < LEN1) {
                uint256 b = uint8(digest[c >> 1]);
                digit = c & 1 == 0 ? b >> 4 : b & 0x0f;
                checksum += W_MAX - digit;
            } else {
                digit = (checksum >> (4 * (CHAINS - 1 - c))) & 0x0f;
            }
            bytes32 top = _walk(publicSeed, leaf, c, digit, bytes32(signature[4 + 32 * c:36 + 32 * c]));
            assembly ("memory-safe") {
                mstore(add(tops, add(69, mul(32, c))), top)
            }
        }

        bytes32 at = sha256(tops);
        uint256 index = leaf;
        uint256 path = 4 + 32 * CHAINS;
        for (uint256 i = 0; i < height; i++) {
            bytes32 sibling = bytes32(signature[path + 32 * i:path + 32 * i + 32]);
            at = index & 1 == 0
                ? sha256(abi.encodePacked(bytes1(0x03), at, sibling))
                : sha256(abi.encodePacked(bytes1(0x03), sibling, at));
            index >>= 1;
        }
        return at == root;
    }

    /// Walks chain `chain` of `leaf` from position `from` to the top: each
    /// step is SHA-256(CHAIN_DOMAIN || public seed || leaf || chain || step || x).
    function _walk(bytes32 publicSeed, uint256 leaf, uint256 chain, uint256 from, bytes32 x)
        private
        view
        returns (bytes32 out)
    {
        assembly ("memory-safe") {
            let buf := mload(0x40)
            mstore(add(buf, 1), publicSeed)
            mstore(add(buf, 33), shl(224, leaf))
            mstore8(buf, 0x01)
            mstore8(add(buf, 37), chain)
            for { let step := from } lt(step, 15) { step := add(step, 1) } {
                mstore8(add(buf, 38), step)
                mstore(add(buf, 39), x)
                if iszero(staticcall(gas(), 0x02, buf, 71, 0x00, 0x20)) { revert(0, 0) }
                x := mload(0x00)
            }
            out := x
        }
    }
}
