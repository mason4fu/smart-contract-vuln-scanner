// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract RoleGrantOverlap {
    address public owner;
    mapping(address => bool) public roles;

    constructor() {
        owner = msg.sender;
    }

    function promote(address who) external {
        roles[who] = true;
        owner = who;
    }
}
