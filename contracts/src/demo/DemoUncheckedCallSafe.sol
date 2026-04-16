// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Combined safe unchecked-call demo for class presentation.
contract DemoUncheckedCallSafe {
    uint256 public notifyCount;

    // Safe: require(success) gates continuation.
    function notifyRequire(address target) external {
        (bool success,) = target.call("");
        require(success, "call failed");
        notifyCount += 1;
    }

    // Safe: explicit revert branch on failure.
    function notifyRevert(address target) external {
        (bool success,) = target.call("");
        if (!success) {
            revert("call failed");
        }
        notifyCount += 1;
    }
}
