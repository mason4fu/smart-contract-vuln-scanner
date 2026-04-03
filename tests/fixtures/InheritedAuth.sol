// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}

contract InheritedAuth is Ownable {
    uint256 public value;

    function setValue(uint256 _val) external onlyOwner {
        value = _val;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}
