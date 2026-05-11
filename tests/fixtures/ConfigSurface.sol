// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ConfigSurface {
    address public owner;
    address public treasury;
    uint256 public counter;

    constructor() {
        owner = msg.sender;
        treasury = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setTreasury(address newTreasury) external {
        treasury = newTreasury;
    }

    function setCounter(uint256 newCounter) external {
        counter = newCounter;
    }

    function setTreasurySafe(address newTreasury) external onlyOwner {
        treasury = newTreasury;
    }
}
