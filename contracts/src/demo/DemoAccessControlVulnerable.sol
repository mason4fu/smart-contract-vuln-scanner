// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Combined vulnerable access-control demo for class presentation.
contract DemoAccessControlVulnerable {
    address public owner;
    address public treasury;
    mapping(address => bool) public isAdmin;
    uint256 public totalWithdrawn;

    constructor() payable {
        owner = msg.sender;
        treasury = msg.sender;
        isAdmin[msg.sender] = true;
    }

    // Vulnerable: sensitive transfer is publicly callable with no guard.
    function withdraw(address payable to, uint256 amount) external {
        totalWithdrawn += amount;
        to.transfer(amount);
    }

    // Vulnerable: anyone can take ownership.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // Vulnerable: anyone can grant admin privileges.
    function grantAdmin(address account) external {
        isAdmin[account] = true;
    }

    // Vulnerable: anyone can redirect treasury configuration.
    function setTreasury(address newTreasury) external {
        treasury = newTreasury;
    }

    function treasuryAddress() external view returns (address) {
        return treasury;
    }
}
