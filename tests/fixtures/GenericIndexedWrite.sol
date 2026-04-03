// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract GenericIndexedWrite {
    mapping(uint256 => uint256) public raw;
    mapping(address => uint256) public owned;

    function setRaw(uint256 key, uint256 value) external {
        raw[key] = value;
    }

    function setOwned(uint256 value) external {
        owned[msg.sender] = value;
    }
}
