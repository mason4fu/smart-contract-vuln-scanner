// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SimpleStorage
/// @notice Minimal fixture contract for testing the toolchain.
///         This is NOT a vulnerability example.
contract SimpleStorage {
    uint256 private _value;

    event ValueChanged(uint256 newValue);

    /// @notice Store a new value.
    /// @param newValue The value to store.
    function store(uint256 newValue) external {
        _value = newValue;
        emit ValueChanged(newValue);
    }

    /// @notice Retrieve the stored value.
    /// @return The current stored value.
    function retrieve() external view returns (uint256) {
        return _value;
    }
}
