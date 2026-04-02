// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract NestedAuthCheck {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function execute(address newOwner) external {
        _stepOne(newOwner);
    }

    function _stepOne(address newOwner) internal {
        _stepTwo(newOwner);
    }

    function _stepTwo(address newOwner) internal {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }
}
