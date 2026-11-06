// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// A plain re-statement of Tenzro's hash-based voucher signer, for tests
/// only: it derives a channel's keys from a seed and signs with them. It
/// shares no code with the contract's verifier, and the tests check both
/// against the vectors the Rust signer writes.
library HashVoucherSigner {
    uint256 internal constant CHAINS = 67;

    function publicSeed(bytes32 seed) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x05), seed));
    }

    function _secret(bytes32 seed, uint32 leaf, uint8 chain) private pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x00), seed, leaf, chain));
    }

    function _walk(bytes32 ps, uint32 leaf, uint8 chain, uint8 from, uint8 to, bytes32 x)
        private
        pure
        returns (bytes32)
    {
        for (uint8 step = from; step < to; step++) {
            x = sha256(abi.encodePacked(bytes1(0x01), ps, leaf, chain, step, x));
        }
        return x;
    }

    function _digits(bytes32 digest) private pure returns (uint8[67] memory d) {
        uint256 checksum;
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(digest[i]);
            d[2 * i] = b >> 4;
            d[2 * i + 1] = b & 0x0f;
            checksum += (15 - (b >> 4)) + (15 - (b & 0x0f));
        }
        d[64] = uint8((checksum >> 8) & 0x0f);
        d[65] = uint8((checksum >> 4) & 0x0f);
        d[66] = uint8(checksum & 0x0f);
    }

    function _leafHash(bytes32 seed, bytes32 ps, uint32 leaf) private pure returns (bytes32) {
        bytes memory b = abi.encodePacked(bytes1(0x02), ps, leaf);
        for (uint8 c = 0; c < CHAINS; c++) {
            b = bytes.concat(b, _walk(ps, leaf, c, 0, 15, _secret(seed, leaf, c)));
        }
        return sha256(b);
    }

    /// Every level of the tree, leaves first.
    function levels(bytes32 seed, uint8 height) internal pure returns (bytes32[][] memory out) {
        bytes32 ps = publicSeed(seed);
        out = new bytes32[][](height + 1);
        out[0] = new bytes32[](1 << height);
        for (uint32 leaf = 0; leaf < (1 << height); leaf++) {
            out[0][leaf] = _leafHash(seed, ps, leaf);
        }
        for (uint256 l = 1; l <= height; l++) {
            bytes32[] memory below = out[l - 1];
            out[l] = new bytes32[](below.length / 2);
            for (uint256 i = 0; i < out[l].length; i++) {
                out[l][i] = sha256(abi.encodePacked(bytes1(0x03), below[2 * i], below[2 * i + 1]));
            }
        }
    }

    function sign(bytes32 seed, bytes32[][] memory tree, uint32 leaf, bytes32 digest)
        internal
        pure
        returns (bytes memory sig)
    {
        bytes32 ps = publicSeed(seed);
        uint8[67] memory d = _digits(digest);
        sig = abi.encodePacked(leaf);
        for (uint8 c = 0; c < CHAINS; c++) {
            sig = bytes.concat(sig, _walk(ps, leaf, c, 0, d[c], _secret(seed, leaf, c)));
        }
        uint256 index = leaf;
        for (uint256 l = 0; l + 1 < tree.length; l++) {
            sig = bytes.concat(sig, tree[l][index ^ 1]);
            index >>= 1;
        }
    }
}
