// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates one unsafe pattern and one safe pattern side by side.
contract DemoUncheckedCallMixed {
    event CallOutcome(bool success);

    uint256 public count;

    // Vulnerable: success is only observed in an event and does not gate continuation.
    function notifyUnchecked(address target) external {
        (bool success,) = target.call("");
        emit CallOutcome(success);
        count += 1;
    }

    // Safe: explicit failure branch reverts before state changes.
    function notifyChecked(address target) external {
        (bool success,) = target.call("");
        if (!success) {
            revert("call failed");
        }
        count += 1;
    }
}
