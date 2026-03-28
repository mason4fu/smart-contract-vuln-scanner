// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SensitiveActions
/// @notice Mix of guarded and unguarded sensitive operations
contract SensitiveActions {
    address public owner;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // GUARDED - should not be flagged
    function pause() external onlyOwner {
        paused = true;
    }

    // UNGUARDED selfdestruct - should be flagged
    function destroy() external {
        selfdestruct(payable(owner));
    }

    // UNGUARDED owner change - should be flagged
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}
