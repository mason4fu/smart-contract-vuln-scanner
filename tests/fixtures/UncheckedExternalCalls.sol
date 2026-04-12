// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract UncheckedExternalCalls {
    event Result(bool ok);

    uint256 public count;

    function uncheckedCall(address target) external {
        target.call("");
        count += 1;
    }

    function uncheckedDelegate(address target) external {
        target.delegatecall("");
    }

    function uncheckedStatic(address target) external view {
        target.staticcall("");
    }

    function uncheckedSend(address payable target) external payable {
        target.send(1 wei);
    }

    function tupleAssignedNeverChecked(address target) external {
        (bool success, bytes memory data) = target.call("");
        data;
        count += 1;
    }

    function onlyReturndataCaptured(address target) external {
        (, bytes memory data) = target.call("");
        require(data.length >= 0, "returndata touched");
    }

    function successOnlyLogged(address payable target) external payable {
        bool ok = target.send(1 wei);
        emit Result(ok);
    }

    function checkedRequire(address target) external {
        (bool success,) = target.call("");
        require(success, "call failed");
        count += 1;
    }

    function checkedAssert(address payable target) external payable {
        bool success = target.send(1 wei);
        assert(success);
    }

    function checkedIfRevert(address payable target) external payable {
        bool success = target.send(1 wei);
        if (!success) {
            revert("send failed");
        }
        count += 1;
    }

    function uncheckedIfObserver(address payable target) external payable {
        if (!target.send(1 wei)) {
            count += 1;
        }
    }

    function uncheckedIfOrObserver(address payable target) external payable {
        if (!target.send(1 wei) || true) {
            count += 1;
        }
    }

    function checkedDirectIfReturn(address payable target) external payable {
        if (!target.send(1 wei)) {
            return;
        }
        count += 1;
    }

    function checkedDirectIfElseRevert(address payable target) external payable {
        if (target.send(1 wei)) {
            count += 1;
        } else {
            revert("send failed");
        }
    }

    function checkedHelper(address target) external {
        (bool success,) = target.call("");
        _requireSuccess(success);
        count += 1;
    }

    function returnsSuccess(address payable target) external payable returns (bool) {
        return target.send(1 wei);
    }

    function mixed(address target) external {
        target.call("");
        (bool success,) = target.call("");
        require(success, "checked");
    }

    function _requireSuccess(bool success) internal pure {
        require(success, "low-level call failed");
    }
}
