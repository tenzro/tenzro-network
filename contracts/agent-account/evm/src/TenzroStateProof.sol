// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Tenzro state proofs, checked under a state root: the rules of
/// Tenzro's state trie (SHA-256 throughout). An entry has a 32-byte tree key
/// whose first 31 bytes are its stem (a path of 248 bits) and whose last byte
/// selects one of 256 value slots. A proof is the path length (u16,
/// big-endian), the sibling hashes down the path, then the terminal: 0 for an
/// empty subtree, 1 and the other stem and its slots root, or 2 and the eight
/// slot siblings.
library TenzroStateProof {
    function _word(bytes memory b, uint256 at) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), at))
        }
    }

    function _bit(bytes32 stem, uint256 depth) private pure returns (uint256) {
        return (uint256(uint8(stem[depth / 8])) >> (7 - (depth % 8))) & 1;
    }

    function _pair(bytes32 l, bytes32 r) private pure returns (bytes32) {
        if (l == bytes32(0) && r == bytes32(0)) return bytes32(0);
        return sha256(abi.encodePacked(bytes1(0x03), l, r));
    }

    /// @notice Whether, under `root`, the entry with tree key `tk` holds
    /// `value` (`present`) or is absent, by the encoded `proof`.
    function verifyAt(bytes32 root, bytes32 tk, bool present, bytes memory value, bytes memory proof)
        internal
        pure
        returns (bool)
    {
        if (proof.length < 3) return false;
        uint256 depth = (uint256(uint8(proof[0])) << 8) | uint256(uint8(proof[1]));
        if (depth > 248) return false;
        uint256 t = 2 + 32 * depth;
        if (proof.length <= t) return false;
        uint8 tag = uint8(proof[t]);
        uint256 bodyLen = proof.length - t - 1;
        // The stem is the first 31 bytes; the last byte of the word is the slot.
        bytes32 stem = tk & bytes32(~uint256(0xff));
        bytes32 acc;
        if (tag == 0) {
            if (bodyLen != 0 || present) return false;
        } else if (tag == 1) {
            if (bodyLen != 63 || present) return false;
            bytes32 other = _word(proof, t + 1) & bytes32(~uint256(0xff));
            if (other == stem) return false;
            for (uint256 d = 0; d < depth; d++) {
                if (_bit(other, d) != _bit(stem, d)) return false;
            }
            acc = sha256(abi.encodePacked(bytes1(0x02), bytes31(other), _word(proof, t + 32)));
        } else if (tag == 2) {
            if (bodyLen != 256) return false;
            bytes32 s = present ? sha256(abi.encodePacked(bytes1(0x00), value)) : bytes32(0);
            uint256 index = uint8(tk[31]);
            for (uint256 i = 0; i < 8; i++) {
                bytes32 sib = _word(proof, t + 1 + 32 * i);
                s = (index & 1) == 0 ? _pair(s, sib) : _pair(sib, s);
                index >>= 1;
            }
            if (s == bytes32(0)) return false;
            acc = sha256(abi.encodePacked(bytes1(0x02), bytes31(stem), s));
        } else {
            return false;
        }
        for (uint256 d = depth; d > 0; d--) {
            bytes32 sib = _word(proof, 2 + 32 * (d - 1));
            acc = _bit(stem, d - 1) == 0
                ? sha256(abi.encodePacked(bytes1(0x01), acc, sib))
                : sha256(abi.encodePacked(bytes1(0x01), sib, acc));
        }
        return acc == root;
    }
}
