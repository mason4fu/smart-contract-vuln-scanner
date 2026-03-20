// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Counter
/// @notice A second minimal fixture to verify multi-contract compilation.
contract Counter {
    uint256 public count;

    /// @notice Increment the counter by one.
    function increment() external {
        count += 1;
    }

    /// @notice Reset the counter to zero.
    function reset() external {
        count = 0;
    }
}
