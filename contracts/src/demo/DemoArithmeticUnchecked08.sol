// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Class demo: explicit unchecked block restores wrap risk on state update.
contract DemoArithmeticUnchecked08 {
    uint256 public count;

    function incrementUnchecked(uint256 amount) external {
        unchecked {
            count += amount;
        }
    }
}
