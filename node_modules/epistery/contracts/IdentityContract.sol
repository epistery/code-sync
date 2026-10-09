// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./EpisteryAccess.sol";

/**
 * @title IdentityContract — the root contract of a legal entity
 *
 * A legal entity is a uniqueness that can hold value and other traits. Both kinds
 * of entity are this contract: an individual, and a corporation — a domain, which
 * extends it as {DomainContract}. What they share is here; what is unique to a
 * domain (its DNS binding, the names it issues, the prices it charges) is there.
 *
 * A multisig smart wallet whose signers (rivets) are interchangeable owners: any
 * active rivet can act, add/remove rivets, sign as the entity (ERC-1271), and
 * manage its sections. Add a device, lose a device and remove it with another —
 * no seed phrase, no single owner. A signer may itself be an entity contract, in
 * which case that entity's rivets sign here too.
 *
 * Access + data for everything the entity owns (sessions, plugin data) uses the
 * common {EpisteryAccess} section mechanism: a session is a section; collaborators
 * are ACL entries on it; a plugin's config/keys are the section's attributes. The
 * rivets are the stewards — implicit role 4 on every section.
 *
 * Backup is a signer the owner adds. There is no recovery slot and no server
 * signer: a party everyone must go through is the thing being replaced.
 *
 * **The name.** An entity may bind a name in a domain's registrar, claimed in this
 * constructor so an entity exists only with a name that is unique in that domain.
 * It is written once and never changed: a different name is a different entity.
 * The binding is two-way — the registrar records the holder, this contract records
 * `registrar` and `entityName` — and it is worth nothing until both agree.
 *
 * If every server we run vanished, any one rivet + this contract + Storj is enough
 * to read and write all of the entity's data and its collaborators' shared data.
 */
/** The claim side of a domain's registrar — see {DomainContract}. */
interface IDomainRegistrar {
    function claim(string calldata name) external;
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract IdentityContract is EpisteryAccess, IERC1271 {

    bytes4 constant internal EIP1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant internal EIP1271_INVALID = 0xffffffff;

    // ── the entity (interchangeable owners = rivets) ───────────────────────
    //
    // The first rivet is not recorded as anything: it is one rivet among
    // interchangeable ones, and is as likely to be the technician who ran the
    // deploy as the person it is for. Its address is in the creation event, which
    // is the log, and nothing reads it as an authority.
    address[] private authorizedRivets;
    mapping(address => bool) public isAuthorized;
    mapping(address => bool) public rivetActive;
    mapping(address => string) public rivetNames;
    mapping(address => uint256) public rivetAddedAt;
    mapping(address => string) public rivetPublicKeys;  // per-device key (communications fabric)
    uint256 public rivetCount;

    uint256 public removeRivetThreshold = 1;    // N-of-M to remove a rivet (governance knob)
    uint256 public messageCount;

    // ── the name, in a domain's registrar (both written once, at construction) ──
    address public immutable registrar;         // the DomainContract that issued the name
    string public entityName;                   // the name it issued, lowercase

    // Reserved section for the entity's own world-readable profile — whatever it
    // chooses to publish about itself. The NAME is not here: it is `entityName`,
    // written once and confirmed by its registrar, because a second copy of it
    // would be a copy that can disagree.
    string public constant PROFILE_SECTION = "_profile";

    // ── events ─────────────────────────────────────────────────────────────
    event IdentityCreated(address indexed firstRivet, address indexed registrar, string name, uint256 timestamp);
    event RivetAdded(address indexed rivet, address indexed addedBy, string name, uint256 timestamp);
    event RivetRemoved(address indexed rivet, address indexed removedBy, uint256 timestamp);
    event PublicKeyRegistered(address indexed rivet, string publicKey, uint256 timestamp);
    event TransactionExecuted(address indexed target, uint256 value, address indexed sender, uint256 timestamp);
    event ETHSent(address indexed recipient, uint256 amount, address indexed sender);
    event TokenSent(address indexed token, address indexed recipient, uint256 amount, address indexed sender);
    event RemoveRivetThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
    event MessageReceived(address indexed from, bytes data, uint256 value, uint256 indexed messageIndex, uint256 timestamp);

    /**
     * @param firstRivet the entity's first device (the owner). Not msg.sender, so a
     *        deployer can create it on the user's behalf.
     * @param firstRivetName human name for the first device.
     * @param firstRivetPubKey the device's communications public key (empty for none) —
     *        stored in rivetPublicKeys[firstRivet] so peers can encrypt to it immediately.
     * @param registrar_ the DomainContract to claim the name from (address(0) for an
     *        entity that carries no name).
     * @param name_ the name to claim there. The claim runs in this constructor, so a
     *        name already held makes the whole mint revert: an entity exists only
     *        with a name that is unique in its domain, or with none at all.
     *
     * Folding the name + pubkey into the constructor makes a mint a single deploy tx:
     * no follow-up claim/setPublicKey round-trips.
     */
    constructor(
        address firstRivet,
        string memory firstRivetName,
        string memory firstRivetPubKey,
        address registrar_,
        string memory name_
    ) {
        require(firstRivet != address(0), "first rivet required");
        _addRivet(firstRivet, bytes(firstRivetName).length > 0 ? firstRivetName : "device");
        if (bytes(firstRivetPubKey).length > 0) rivetPublicKeys[firstRivet] = firstRivetPubKey;

        registrar = registrar_;
        if (registrar_ != address(0) && bytes(name_).length > 0) {
            entityName = name_;
            IDomainRegistrar(registrar_).claim(name_);
        } else {
            require(registrar_ == address(0) && bytes(name_).length == 0, "name needs a registrar");
        }
        emit IdentityCreated(firstRivet, registrar_, name_, block.timestamp);
    }

    /** The entity's name — the one this contract claims, and the one a registrar
     *  confirms. Kept under its old name so existing readers keep working. */
    function profileName() external view returns (string memory) {
        return entityName;
    }

    // ── stewardship: the identity itself, and any active rivet, are owners ──
    // `who == address(this)` is load-bearing: the app authorizes callers by
    // their canonical identityAddress, which for an adopted user IS this
    // contract's address (not the raw rivet EOA). So the owner accessing a
    // section on their own IdentityContract arrives as address(this) and must
    // read the top role. Active rivets are stewards too (device-level signing
    // before/without adoption, and cross-contract ERC-1271 proofs).
    function _isSteward(address who) internal view override returns (bool) {
        return who == address(this) || (isAuthorized[who] && rivetActive[who]);
    }

    modifier onlyRivet() {
        require(_isSteward(msg.sender), "caller is not an active rivet");
        _;
    }

    // ── rivet management ────────────────────────────────────────────────────

    function addRivet(address rivet, string memory name) external onlyRivet {
        require(rivet != address(0), "invalid rivet");
        require(!isAuthorized[rivet], "rivet already added");
        require(bytes(name).length > 0, "name required");
        _addRivet(rivet, name);
        emit RivetAdded(rivet, msg.sender, name, block.timestamp);
    }

    function removeRivet(address rivet) external onlyRivet {
        require(isAuthorized[rivet], "rivet not found");
        require(rivetCount > 1, "cannot remove last rivet");
        // (removeRivetThreshold is the intended N-of-M knob; enforcement lands with governance.)

        isAuthorized[rivet] = false;
        rivetActive[rivet] = false;
        rivetCount--;
        delete rivetPublicKeys[rivet];

        emit RivetRemoved(rivet, msg.sender, block.timestamp);
    }

    function setRemoveRivetThreshold(uint256 newThreshold) external onlyRivet {
        require(newThreshold > 0 && newThreshold <= rivetCount, "invalid threshold");
        emit RemoveRivetThresholdChanged(removeRivetThreshold, newThreshold);
        removeRivetThreshold = newThreshold;
    }

    function _addRivet(address rivet, string memory name) private {
        authorizedRivets.push(rivet);
        isAuthorized[rivet] = true;
        rivetActive[rivet] = true;
        rivetNames[rivet] = name;
        rivetAddedAt[rivet] = block.timestamp;
        rivetCount++;
    }

    // ── per-device public key (communications fabric) ──────────────────────

    function setPublicKey(string memory publicKey) external onlyRivet {
        rivetPublicKeys[msg.sender] = publicKey;
        emit PublicKeyRegistered(msg.sender, publicKey, block.timestamp);
    }

    function getRivets() external view returns (address[] memory) {
        address[] memory active = new address[](rivetCount);
        uint256 n;
        for (uint256 i; i < authorizedRivets.length; i++) {
            address r = authorizedRivets[i];
            if (isAuthorized[r] && rivetActive[r]) { active[n++] = r; }
        }
        return active;
    }

    function isRivet(address rivet) external view returns (bool) {
        return isAuthorized[rivet] && rivetActive[rivet];
    }

    // ── act as the identity ─────────────────────────────────────────────────

    function executeTransaction(address target, uint256 value, bytes memory data)
        external payable onlyRivet returns (bool success, bytes memory returnData)
    {
        require(target != address(0), "invalid target");
        require(address(this).balance >= value, "insufficient balance");
        (success, returnData) = target.call{value: value}(data);
        require(success, "transaction failed");
        emit TransactionExecuted(target, value, msg.sender, block.timestamp);
    }

    function sendETH(address payable recipient, uint256 amount) external onlyRivet {
        require(recipient != address(0), "zero recipient");
        require(address(this).balance >= amount, "insufficient balance");
        recipient.transfer(amount);
        emit ETHSent(recipient, amount, msg.sender);
    }

    function sendToken(address token, address recipient, uint256 amount) external onlyRivet {
        require(token != address(0) && recipient != address(0), "zero address");
        require(IERC20(token).transfer(recipient, amount), "token transfer failed");
        emit TokenSent(token, recipient, amount, msg.sender);
    }

    function approveToken(address token, address spender, uint256 amount) external onlyRivet {
        require(token != address(0) && spender != address(0), "zero address");
        require(IERC20(token).approve(spender, amount), "token approval failed");
    }

    function getBalance() external view returns (uint256) { return address(this).balance; }

    // ── ERC-1271: the identity signs when any active rivet signed ──────────

    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        require(signature.length == 65, "invalid signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address signer = ecrecover(ethHash, v, r, s);
        return (isAuthorized[signer] && rivetActive[signer]) ? EIP1271_MAGIC_VALUE : EIP1271_INVALID;
    }

    // ── receive value / accept messages ────────────────────────────────────

    receive() external payable {}

    fallback() external payable {
        messageCount++;
        emit MessageReceived(msg.sender, msg.data, msg.value, messageCount, block.timestamp);
    }
}
