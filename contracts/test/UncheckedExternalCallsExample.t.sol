// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/UncheckedExternalCallsExample.sol";

contract UncheckedExternalCallsExampleTest is Test {
    function testDeploysExample() public {
        UncheckedExternalCallsExample example = new UncheckedExternalCallsExample();
        assertEq(example.count(), 0);
    }
}
