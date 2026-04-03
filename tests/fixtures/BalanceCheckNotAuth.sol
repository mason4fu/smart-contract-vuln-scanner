// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract BalanceCheckNotAuth {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(amount <= balances[msg.sender], "insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}