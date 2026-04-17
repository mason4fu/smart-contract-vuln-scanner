// SPDX-License-Identifier: MIT
pragma solidity 0.4.25;

contract ArithmeticPatterns {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function unguardedAdd(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function guardedAdd(uint256 amount) external {
        require(balances[msg.sender] + amount >= balances[msg.sender], "overflow");
        balances[msg.sender] = balances[msg.sender] + amount;
    }

    function safeMathAdd(uint256 amount) external {
        balances[msg.sender] = add(balances[msg.sender], amount);
    }

    function payout(uint256 amount, uint256 multiplier) external {
        uint256 value = amount * multiplier;
        totalSupply = totalSupply + value;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        require(a + b >= a, "overflow");
        return a + b;
    }
}
