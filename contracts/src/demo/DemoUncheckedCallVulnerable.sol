// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Combined vulnerable unchecked-call demo for class presentation.
contract DemoUncheckedCallVulnerable {
    uint256 public notifyCount;

    // Vulnerable: low-level call result is ignored entirely.
    function notifyIgnored(address target) external {
        target.call("");
        notifyCount += 1;
    }

    // Vulnerable: success is assigned but never used as a failure gate.
    function notifyAssignedUnused(address target) external {
        (bool success, bytes memory returnData) = target.call("");
        returnData;
        notifyCount += 1;
    }
}
