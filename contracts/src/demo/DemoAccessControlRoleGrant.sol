// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates an unguarded role grant on an admin mapping.
contract DemoAccessControlRoleGrant {
    address public owner;
    mapping(address => bool) public isAdmin;

    constructor() {
        owner = msg.sender;
        isAdmin[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Vulnerable: anyone can grant admin privileges.
    function grantRole(address account) external {
        isAdmin[account] = true;
    }

    // Safe contrast: role grant restricted to owner.
    function grantRoleSafely(address account) external onlyOwner {
        isAdmin[account] = true;
    }
}
