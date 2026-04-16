// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates an owner-changing function with no authorization guard.
contract DemoAccessControlMissingGuard {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerable: any caller can take ownership.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
