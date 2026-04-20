// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Class demo: external ETH transfer before balance update (CEI violation).
contract DemoReentrancyVulnerable {
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
