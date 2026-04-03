// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UninitializedOwner {
    address public owner;  // never set!
    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }
    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
