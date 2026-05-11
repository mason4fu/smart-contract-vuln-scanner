// SPDX-License-Identifier: MIT
pragma solidity 0.4.25;

contract ArithmeticAdvanced {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function multiIssue(uint256 amount, uint256 price) public payable {
        require(msg.value == amount * price);
        balances[msg.sender] += amount;
    }

    function safeUsingHelper(uint256 amount) public {
        totalSupply = safeAdd(totalSupply, amount);
    }

    function guardedSub(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
    }

    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }
}
