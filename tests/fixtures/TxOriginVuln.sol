// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title TxOriginVuln
/// @notice Uses tx.origin for authorization - vulnerable (SWC-115)
contract TxOriginVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() external {
        require(tx.origin == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
