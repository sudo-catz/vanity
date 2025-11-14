// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Create2Factory
/// @notice Minimal factory that deploys arbitrary bytecode deterministically via CREATE2.
contract Create2Factory {
    error EmptyBytecode();
    error DeploymentFailed();

    event Deployed(address indexed addr, bytes32 indexed salt);

    /// @notice Deploys `bytecode` using CREATE2 and returns the new contract address.
    /// @dev Reverts if bytecode is empty or CREATE2 returns address(0).
    function deploy(bytes32 salt, bytes memory bytecode) external returns (address addr) {
        if (bytecode.length == 0) {
            revert EmptyBytecode();
        }

        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }

        if (addr == address(0)) {
            revert DeploymentFailed();
        }

        emit Deployed(addr, salt);
    }

    /// @notice Computes the address that would be produced for `salt` & `bytecode`.
    function computeAddress(bytes32 salt, bytes32 bytecodeHash) external view returns (address) {
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, bytecodeHash)))
            )
        );
    }
}
