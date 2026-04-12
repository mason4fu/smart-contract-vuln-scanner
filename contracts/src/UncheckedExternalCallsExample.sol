// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract UncheckedExternalCallsExample {
    uint256 public count;

    function unsafeNotify(address target) external {
        target.call("");
        count += 1;
    }

    function safeNotify(address target) external {
        (bool success,) = target.call("");
        require(success, "notify failed");
        count += 1;
    }
}
