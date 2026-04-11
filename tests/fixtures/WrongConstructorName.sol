pragma solidity ^0.4.24;

contract WrongConstructorName {
    address public owner;

    function Constructor() public {
        owner = msg.sender;
    }

    function withdraw() public {
        require(msg.sender == owner, "not owner");
        msg.sender.transfer(address(this).balance);
    }
}
