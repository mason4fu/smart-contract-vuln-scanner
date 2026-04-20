// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Class demo: default Solidity 0.8 checked arithmetic on state (negative control).
contract DemoArithmeticSafe08 {
    uint256 public count;

    function increment(uint256 amount) external {
        count += amount;
    }
}
