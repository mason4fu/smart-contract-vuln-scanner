// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract HelperSensitiveActions {
    address public owner;
    address public treasury;
    mapping(address => bool) public admins;

    constructor() {
        owner = msg.sender;
    }

    function setOwnerViaHelper(address newOwner) external {
        _applyOwner(newOwner);
    }

    function setTreasuryViaNestedHelper(address newTreasury) external {
        _stageTreasuryUpdate(newTreasury);
    }

    function grantRoleViaHelper(address user) external {
        _grantAdmin(user);
    }

    function setOwnerViaGuardedHelper(address newOwner) external {
        _requireOwner();
        _applyOwner(newOwner);
    }

    function _stageTreasuryUpdate(address newTreasury) internal {
        _applyTreasury(newTreasury);
    }

    function _applyOwner(address newOwner) internal {
        owner = newOwner;
    }

    function _applyTreasury(address newTreasury) internal {
        treasury = newTreasury;
    }

    function _grantAdmin(address user) internal {
        admins[user] = true;
    }

    function _requireOwner() internal view {
        require(msg.sender == owner, "not owner");
    }
}
