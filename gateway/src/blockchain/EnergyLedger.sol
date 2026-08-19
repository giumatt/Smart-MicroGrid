// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EnergyLedger {
    // Event issued after every transaction
    event TransferRecorded(string fromNode, string toNode, uint256 whAmount, uint256 timestamp, string signature);

    // On-chain data structure
    struct Transfer {
        string fromNode;
        string toNode;
        uint256 whAmount;
        uint256 timestamp;
        string signature; // Original ESP ECDSA sign to guarantee non repudiation
    }

    Transfer[] public ledger;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "EnergyLedger: caller is not the authorized relayer");
        _;
    }

    constructor() {
        owner = msg.sender; // deployer = relayer's deployer_account
    }

    function recordTransfer(string memory _from, string memory _to, uint256 _whAmount, uint256 _timestamp, string memory _sig) public onlyOwner {
        ledger.push(Transfer(_from, _to, _whAmount, _timestamp, _sig));
        emit TransferRecorded(_from, _to, _whAmount, _timestamp, _sig);
    }

    function getLedgerSize() public view returns (uint256) {
        return ledger.length;
    }
}
