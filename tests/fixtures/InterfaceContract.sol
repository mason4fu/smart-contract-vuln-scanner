// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface InterfaceContract {
    function transfer(address to, uint256 amount) external;

    function setApprovalForAll(address operator, bool approved) external;
}