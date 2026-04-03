// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title InlineAuthCheck
/// @notice Uses inline require(msg.sender == owner) without a modifier - should NOT be flagged
contract InlineAuthCheck {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address newOwner) public {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
