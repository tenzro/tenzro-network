// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// A log the runner recorded.
struct VmLog {
    bytes32[] topics;
    bytes data;
    address emitter;
}

/// The test runner's cheat codes these tests use.
interface Vm {
    function recordLogs() external;
    function getRecordedLogs() external returns (VmLog[] memory);
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonString(string calldata json, string calldata key) external pure returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonBytes32Array(string calldata json, string calldata key) external pure returns (bytes32[] memory);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function parseJsonAddress(string calldata json, string calldata key) external pure returns (address);
    function toString(uint256 v) external pure returns (string memory);
    function chainId(uint256 id) external;
    function etch(address target, bytes calldata code) external;
    function deal(address who, uint256 amount) external;
    function warp(uint256 timestamp) external;
    function signP256(uint256 privateKey, bytes32 digest) external pure returns (bytes32 r, bytes32 s);
    function expectRevert(bytes4 selector) external;
    function prank(address sender) external;
}

/// The base of every test here: the cheat codes, assertions and a gas log.
abstract contract Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    event log_named_uint(string key, uint256 val);

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "not equal");
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        require(a == b, "not equal");
    }

    function assertEq(address a, address b) internal pure {
        require(a == b, "not equal");
    }

    function assertEq(bytes memory a, bytes memory b) internal pure {
        require(keccak256(a) == keccak256(b), "not equal");
    }

    function assertTrue(bool v, string memory what) internal pure {
        require(v, what);
    }

    function assertFalse(bool v, string memory what) internal pure {
        require(!v, what);
    }

    function assertLt(uint256 a, uint256 b) internal pure {
        require(a < b, "not less");
    }

    function logGas(string memory what, uint256 gas) internal {
        emit log_named_uint(what, gas);
    }
}
