// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract CreatorPattern {
    address public creator;

    constructor() {
        creator = msg.sender;
    }

    function setCreator(address newCreator) external {
        creator = newCreator;
    }
}