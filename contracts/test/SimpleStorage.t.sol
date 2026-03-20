// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/SimpleStorage.sol";

contract SimpleStorageTest is Test {
    SimpleStorage store;

    function setUp() public {
        store = new SimpleStorage();
    }

    function test_StoreAndRetrieve() public {
        store.store(42);
        assertEq(store.retrieve(), 42);
    }

    function test_InitialValueIsZero() public view {
        assertEq(store.retrieve(), 0);
    }
}
