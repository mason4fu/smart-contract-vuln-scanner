// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Class demo: checks-effects-interactions — state updated before external call.
contract DemoReentrancySafe {
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
