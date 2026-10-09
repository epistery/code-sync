// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * An identity as they were deployed before the registrar: it publishes a name
 * about itself and knows nothing of a registrar. Here so the migration path —
 * such a contract claiming a name and being confirmed on its own assertion —
 * is proven rather than assumed. Not part of the system.
 */
contract LegacyNamedEntity {
    string private _name;
    constructor(string memory name_) { _name = name_; }
    function profileName() external view returns (string memory) { return _name; }
    function claim(address registrar, string calldata name) external {
        (bool ok, ) = registrar.call(abi.encodeWithSignature("claim(string)", name));
        require(ok, "claim failed");
    }
}
