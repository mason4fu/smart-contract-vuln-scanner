// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates capturing call results but never gating on success.
contract DemoUncheckedCallAssignedUnused {
    uint256 public attemptCount;

    // Vulnerable: success is assigned but not used to handle failure.
    function notify(address target) external {
        (bool success, bytes memory returnData) = target.call("");
        returnData;
        attemptCount += 1;
    }
}
