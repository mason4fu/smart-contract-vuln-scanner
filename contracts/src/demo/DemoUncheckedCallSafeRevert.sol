// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates explicit revert when a low-level call fails.
contract DemoUncheckedCallSafeRevert {
    uint256 public processedCount;

    // Safe: manual failure branch prevents silent continuation.
    function notify(address target) external {
        (bool success,) = target.call("");
        if (!success) {
            revert("call failed");
        }
        processedCount += 1;
    }
}
