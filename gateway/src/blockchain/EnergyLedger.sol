// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EnergyLedger {
    // Event issued after every transaction
    event TransferRecorded(string fromNode, string toNode, uint256 mwhAmount, uint256 timestamp, uint256 seq, string signature);

    // On-chain data structure
    struct Transfer {
        string fromNode;
        string toNode;
        uint256 mwhAmount;   // Energy in milli-Wh (integer, a few seconds of production is below 1 Wh)
        uint256 timestamp;
        uint256 seq;         // Device anti-replay sequence, covered by the signature
        string signature; // Original ESP ECDSA sign to guarantee non repudiation
    }

    Transfer[] public ledger;

    // Highest sequence recorded per node: the same signed telemetry cannot be recorded twice
    mapping(string => uint256) public lastSequence;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "EnergyLedger: caller is not the authorized relayer");
        _;
    }

    constructor() {
        owner = msg.sender; // deployer = relayer's deployer_account
    }

    function recordTransfer(string memory _from, string memory _to, uint256 _mwhAmount, uint256 _timestamp, uint256 _seq, string memory _sig) public onlyOwner {
        require(_seq > lastSequence[_from], "EnergyLedger: replayed or out-of-order sequence");
        lastSequence[_from] = _seq;

        ledger.push(Transfer(_from, _to, _mwhAmount, _timestamp, _seq, _sig));
        emit TransferRecorded(_from, _to, _mwhAmount, _timestamp, _seq, _sig);
    }

    function getLedgerSize() public view returns (uint256) {
        return ledger.length;
    }
}
