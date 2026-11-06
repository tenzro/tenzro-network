// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {TenzroAgentAccount} from "./TenzroAgentAccount.sol";

/// @notice Deploys Tenzro agent accounts at the address every Tenzro node
/// derives for an agent: CREATE2 from this factory with salt
/// `sha256("tenzro/omni-account/v1" || did)` over a minimal proxy of the
/// account implementation. The factory and the implementation are deployed
/// with the keyless deterministic deployer and chain-independent constructor
/// arguments, so an agent has the same account address on every EVM chain.
contract TenzroAgentAccountFactory {
    address public immutable implementation;

    event AccountCreated(address indexed account, bytes32 indexed agent);

    constructor(address implementation_) {
        implementation = implementation_;
    }

    /// @notice The account of `did`, deployed if it is not yet. Anyone may
    /// call it.
    function createAccount(string calldata did) external returns (address account) {
        account = accountOf(did);
        if (account.code.length != 0) return account;
        bytes memory code = _proxyInitCode();
        bytes32 salt = _salt(did);
        assembly {
            account := create2(0, add(code, 32), mload(code), salt)
        }
        require(account != address(0), "deploy failed");
        TenzroAgentAccount(payable(account)).initialize(did);
        emit AccountCreated(account, sha256(bytes(did)));
    }

    /// @notice Where the account of `did` is, deployed or not.
    function accountOf(string calldata did) public view returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), _salt(did), initCodeHash()))))
        );
    }

    /// @notice The hash of the proxy init code every account is deployed with.
    function initCodeHash() public view returns (bytes32) {
        return keccak256(_proxyInitCode());
    }

    function _salt(string calldata did) internal pure returns (bytes32) {
        return sha256(abi.encodePacked("tenzro/omni-account/v1", did));
    }

    /// The EIP-1167 minimal proxy of the implementation.
    function _proxyInitCode() internal view returns (bytes memory) {
        return abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            implementation,
            hex"5af43d82803e903d91602b57fd5bf3"
        );
    }
}
