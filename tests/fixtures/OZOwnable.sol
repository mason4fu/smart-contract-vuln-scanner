// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Simulates a contract inheriting from OpenZeppelin's Ownable
// The onlyOwner modifier comes from the base — we only check the name
contract OZOwnable {
    address public owner;
    constructor() { owner = msg.sender; }

    // onlyOwner is a well-known modifier — scanner should recognize it
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function sensitiveOperation() external onlyOwner {
        owner = msg.sender; // intentional — this is guarded
    }
}
