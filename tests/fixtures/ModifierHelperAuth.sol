// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ModifierHelperAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwnerViaHelper() {
        _enforceOwner();
        _;
    }

    function _enforceOwner() internal view {
        require(msg.sender == owner, "not owner");
    }

    function setOwner(address newOwner) external onlyOwnerViaHelper {
        owner = newOwner;
    }
}
