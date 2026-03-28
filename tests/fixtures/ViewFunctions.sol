// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ViewFunctions
/// @notice Public view/pure functions with no auth - should NOT be flagged
contract ViewFunctions {
    uint256 public value;

    constructor(uint256 _value) {
        value = _value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }

    function double(uint256 x) public pure returns (uint256) {
        return x * 2;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
