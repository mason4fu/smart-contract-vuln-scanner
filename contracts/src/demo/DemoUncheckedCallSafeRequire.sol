// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates require(success) as explicit failure gating.
contract DemoUncheckedCallSafeRequire {
    uint256 public notifyCount;

    // Safe: execution continues only when the low-level call succeeds.
    function notify(address target) external {
        (bool success,) = target.call("");
        require(success, "call failed");
        notifyCount += 1;
    }
}
