// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates a compact and safe owner-guarded admin surface.
contract DemoAccessControlSafe {
    address public owner;
    uint256 public feeBps;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Safe: ownership change is guarded by onlyOwner.
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // Safe: config update is also owner-gated.
    function setFeeBps(uint256 newFeeBps) external onlyOwner {
        feeBps = newFeeBps;
    }
}
