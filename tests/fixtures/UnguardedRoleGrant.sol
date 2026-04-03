// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnguardedRoleGrant {
    mapping(address => bool) public admins;
    function grantAdmin(address who) public { admins[who] = true; }  // no guard!
}
