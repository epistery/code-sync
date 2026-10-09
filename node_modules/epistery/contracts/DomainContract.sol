// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IdentityContract.sol";

/** What a named entity reports back, for the other half of the binding. */
interface INamedEntity {
    function registrar() external view returns (address);
    function entityName() external view returns (string memory);
}

/** What an entity deployed before the registrar existed can report: the name it
 *  publishes about itself. Such a contract can claim through executeTransaction,
 *  and this is the only assertion it has — so it is read rather than forcing
 *  every identity already on chain to be minted again. */
interface ILegacyNamedEntity {
    function profileName() external view returns (string memory);
}

/**
 * @title DomainContract — a domain as a legal entity, and the registrar of its names
 *
 * The corporation to {IdentityContract}'s individual: the same rivets, sections,
 * treasury and ERC-1271, plus the three things only a domain has — the domain it is
 * bound to, the names it issues, and the prices it charges.
 *
 * **The chain of bindings.** DNS binds the domain to this contract, and this
 * contract names the domain back; an entity binds its name to this registrar, and
 * this registrar records the holder; a session binds to the entity that owns it.
 * Every link is two-way and public, so anyone can walk it without asking us.
 *
 * The domain is this contract's own name. It is not registered anywhere and maps to
 * nothing: a name in DNS already belongs to whoever answers for it, and a second
 * register of domains would be a second copy of that fact.
 *
 * **What the domain cannot do.** There is no function here through which the domain
 * can assign, move, rename or take a name. It sets prices and it is paid; a name is
 * claimed by the entity that will hold it, and leaves only by lapsing. A server that
 * can make a claim succeed can also make it fail, and nobody should live at its
 * pleasure.
 */
contract DomainContract is IdentityContract {

    // ── the domain ─────────────────────────────────────────────────────────
    string public domain;                       // bound by DNS; written once, at construction

    // ── the names it issues ────────────────────────────────────────────────
    //
    // A name is rented. The first year comes with the claim; each renewal buys a
    // year FROM THE CURRENT EXPIRY, so paying late buys no extra time. Once the
    // grace period after expiry has passed the name is available again — no
    // transaction releases it, the next claim takes it.
    struct NameRecord { address holder; uint64 expiresAt; }

    uint64 public constant TERM  = 365 days;    // what one payment buys
    uint64 public constant GRACE = 365 days;    // how long a lapsed name is still its holder's

    mapping(string => NameRecord) private _names;   // name => record
    mapping(address => string) private _held;       // holder => the one name it holds

    // ── the prices it charges ──────────────────────────────────────────────
    //
    // Named prices in wei, readable by anyone, set by a rivet. The keys are plain
    // strings so a price list reads as one: "name.renewal", "relay.toll",
    // "identity.starter". Whatever quotes a price reads it here; a copy kept
    // elsewhere is a copy that can disagree.
    mapping(string => uint256) private _fees;
    string[] private _feeKeys;
    mapping(string => bool) private _feeKeySeen;

    string public constant FEE_NAME_RENEWAL = "name.renewal";

    // ── events ─────────────────────────────────────────────────────────────
    event DomainBound(string domain, address indexed creator);
    event NameClaimed(string name, address indexed holder, uint64 expiresAt);
    event NameRenewed(string name, address indexed holder, uint64 expiresAt, uint256 paid, address indexed payer);
    event NameReleased(string name, address indexed priorHolder, address indexed newHolder);
    event FeeSet(string key, uint256 amount, address indexed by);

    /**
     * @param firstRivet the domain's first device — its rivets wield it, as an
     *        individual's wield theirs. A signer may be an entity contract.
     * @param domain_ the domain this contract answers for, e.g. "epistery.com".
     *        DNS is the other half of the binding.
     */
    constructor(
        address firstRivet,
        string memory firstRivetName,
        string memory firstRivetPubKey,
        string memory domain_
    ) IdentityContract(firstRivet, firstRivetName, firstRivetPubKey, address(0), "") {
        require(bytes(domain_).length > 0, "domain required");
        domain = domain_;
        emit DomainBound(domain_, firstRivet);
    }

    // ── claiming ───────────────────────────────────────────────────────────

    /**
     * Claim `name` for the caller. Called by an entity's constructor, so the mint
     * of an entity whose name is taken reverts as a whole.
     *
     * The caller claims for ITSELF — there is no address argument, and so no way
     * for anyone to place a name on anyone else. Nothing here checks what the
     * caller is: an address with nothing to report back can hold a name, and will
     * never be confirmed, which is the same rule everyone is read by.
     */
    function claim(string calldata name) external {
        _requireValidName(name);
        NameRecord storage rec = _names[name];
        address prior = rec.holder;
        if (prior != address(0)) {
            require(block.timestamp > uint256(rec.expiresAt) + GRACE, "name is held");
            delete _held[prior];
            emit NameReleased(name, prior, msg.sender);
        }
        require(bytes(_held[msg.sender]).length == 0, "caller already holds a name");

        rec.holder = msg.sender;
        rec.expiresAt = uint64(block.timestamp) + TERM;   // the first year comes with the claim
        _held[msg.sender] = name;
        emit NameClaimed(name, msg.sender, rec.expiresAt);
    }

    /**
     * Pay for `years_` more years of `name`, from its current expiry. Anyone may
     * pay: it only ever extends the term of whoever holds the name, so paying for
     * someone else needs no path of its own.
     */
    function renew(string calldata name, uint16 years_) external payable {
        require(years_ > 0, "nothing to renew");
        NameRecord storage rec = _names[name];
        require(rec.holder != address(0), "name not held");
        require(block.timestamp <= uint256(rec.expiresAt) + GRACE, "name has lapsed");
        require(msg.value == _fees[FEE_NAME_RENEWAL] * years_, "wrong amount");

        rec.expiresAt += TERM * uint64(years_);           // from the expiry, never from today
        emit NameRenewed(name, rec.holder, rec.expiresAt, msg.value, msg.sender);
    }

    // ── reading (facts, no verdict) ────────────────────────────────────────

    function holderOf(string calldata name) external view returns (address) { return _names[name].holder; }
    function expiresAt(string calldata name) external view returns (uint64) { return _names[name].expiresAt; }
    function nameOf(address holder) external view returns (string memory) { return _held[holder]; }

    /** When this name stops being its holder's, if nothing more is paid. */
    function graceEndsAt(string calldata name) external view returns (uint64) {
        NameRecord storage rec = _names[name];
        return rec.holder == address(0) ? 0 : rec.expiresAt + GRACE;
    }

    /** True if a claim would succeed: never held, or held and past its grace. */
    function available(string calldata name) external view returns (bool) {
        NameRecord storage rec = _names[name];
        return rec.holder == address(0) || block.timestamp > uint256(rec.expiresAt) + GRACE;
    }

    /**
     * The binding, checked in both directions: this registrar records the holder,
     * and the holder reports this registrar and this name back. A claim that
     * cannot answer — an address with no code, or an entity carrying some other
     * name — is a claim and nothing more.
     */
    function confirmed(string calldata name) external view returns (bool) {
        address holder = _names[name].holder;
        // Nothing to ask: no holder, or an address with no code to answer with.
        // A call to a codeless address succeeds with empty data, which decodes to
        // a revert the caller cannot catch, so this is checked before asking.
        if (holder == address(0) || holder.code.length == 0) return false;
        try INamedEntity(holder).registrar() returns (address r) {
            if (r != address(this)) return false;                  // bound to another registrar
            try INamedEntity(holder).entityName() returns (string memory n) {
                return keccak256(bytes(n)) == keccak256(bytes(name));
            } catch { return false; }
        } catch {
            // No registrar to report: an entity from before this contract existed.
            // The registrar already records it as the holder; the name it publishes
            // about itself is the other direction.
            try ILegacyNamedEntity(holder).profileName() returns (string memory n) {
                return keccak256(bytes(n)) == keccak256(bytes(name));
            } catch { return false; }
        }
    }

    // ── prices ─────────────────────────────────────────────────────────────

    function fee(string calldata key) external view returns (uint256) { return _fees[key]; }
    function feeKeys() external view returns (string[] memory) { return _feeKeys; }

    /** Set a price. A rivet's public transaction; terms already paid are untouched. */
    function setFee(string calldata key, uint256 amount) external onlyRivet {
        require(bytes(key).length > 0, "key required");
        if (!_feeKeySeen[key]) { _feeKeySeen[key] = true; _feeKeys.push(key); }
        _fees[key] = amount;
        emit FeeSet(key, amount, msg.sender);
    }

    // ── internals ──────────────────────────────────────────────────────────

    /** Lowercase a-z, 0-9, hyphen and underscore, 1..32 characters. One spelling
     *  per name: a name that differs only by case is the same name, so only one
     *  form is accepted rather than folded silently. */
    function _requireValidName(string calldata name) private pure {
        bytes calldata b = bytes(name);
        require(b.length > 0 && b.length <= 32, "name length");
        for (uint256 i; i < b.length; i++) {
            bytes1 c = b[i];
            bool ok = (c >= 0x61 && c <= 0x7a)      // a-z
                   || (c >= 0x30 && c <= 0x39)      // 0-9
                   || c == 0x2d || c == 0x5f;       // - _
            require(ok, "name characters");
        }
    }
}
