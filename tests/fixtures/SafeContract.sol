// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SafeContract
/// @notice Properly guarded sensitive functions - no findings expected
contract SafeContract {
    address public owner;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
