// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Combined safe access-control demo for class presentation.
contract DemoAccessControlSafe {
    address public owner;
    address public treasury;
    mapping(address => bool) public isAdmin;
    uint256 public totalWithdrawn;

    constructor() payable {
        owner = msg.sender;
        treasury = msg.sender;
        isAdmin[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Safe: sensitive transfer is owner-gated.
    function withdraw(address payable to, uint256 amount) external onlyOwner {
        totalWithdrawn += amount;
        to.transfer(amount);
    }

    // Safe: ownership change is restricted.
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
        isAdmin[newOwner] = true;
    }

    // Safe: role grants are owner-gated.
    function grantAdmin(address account) external onlyOwner {
        isAdmin[account] = true;
    }

    // Safe: treasury changes are owner-gated.
    function setTreasury(address newTreasury) external onlyOwner {
        treasury = newTreasury;
    }

    function treasuryAddress() external view returns (address) {
        return treasury;
    }
}
