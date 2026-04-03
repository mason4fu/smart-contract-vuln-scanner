// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract TxOriginTwice {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function sweep(address payable to) external {
        require(tx.origin == owner, "origin owner mismatch");
        require(tx.origin != address(0), "invalid origin");
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}
