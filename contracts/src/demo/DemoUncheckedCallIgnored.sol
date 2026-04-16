// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates a low-level call whose success result is fully ignored.
contract DemoUncheckedCallIgnored {
    uint256 public pingCount;

    // Vulnerable: the bool returned by .call is never checked.
    function ping(address target) external {
        target.call("");
        pingCount += 1;
    }
}
