// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title NearMiss
/// @notice Sensitive function is guarded; tx.origin used only in a getter (not auth)
contract NearMiss {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // tx.origin here is just informational, not used for auth decisions
    function getOriginalSender() external view returns (address) {
        return tx.origin;
    }
}
