pragma solidity 0.4.25;

contract LegacyUncheckedExternalCalls {
    function legacySend(address target) public {
        target.send(1);
    }

    function legacyCallValue(address target) public payable {
        target.call.value(1)();
    }

    function legacyChecked(address target) public {
        require(target.call());
    }
}
