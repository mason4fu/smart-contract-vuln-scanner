// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SampleToken
/// @notice Minimal sample contract for use as scanner input.
///         Copy this into samples/contracts/ as a reference fixture.
contract SampleToken {
    string public name = "SampleToken";
    string public symbol = "SMPL";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 initialSupply) {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
