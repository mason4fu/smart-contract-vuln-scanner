// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Withdraws before updating balance (classic reentrancy ordering).
contract VulnerableReentrancy {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

/// @notice Checks-effects-interactions: state updated before external call.
contract SafeReentrancyCEI {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
