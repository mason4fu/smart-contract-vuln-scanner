// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DangerousRenounce {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }
    function renounceOwnership() external onlyOwner { owner = address(0); }
}
