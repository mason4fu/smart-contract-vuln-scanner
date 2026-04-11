// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title MissingAuthVuln
/// @notice Public sensitive function with no authorization guard
contract MissingAuthVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // No modifier, no require — anyone can call this
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }
}
