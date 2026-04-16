// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Demonstrates unguarded vs guarded admin reassignment.
contract DemoAccessControlAdminChange {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    // Vulnerable: public admin reassignment without an auth check.
    function setAdmin(address newAdmin) external {
        admin = newAdmin;
    }

    // Safe contrast: inline guard using msg.sender.
    function setAdminSafely(address newAdmin) external {
        require(msg.sender == admin, "not admin");
        admin = newAdmin;
    }
}
