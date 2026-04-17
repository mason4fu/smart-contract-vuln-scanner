// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ArithmeticUnchecked08 {
    uint256 public count;

    function incrementUnchecked(uint256 amount) external {
        unchecked {
            count += amount;
        }
    }
}
