// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title EpisteryAccess — common access + data mechanism for all epistery contracts
 *
 * The one ACL-and-data primitive shared by IdentityContract, DomainAgent, and
 * CampaignContract. A contract is organized into named **sections** — mini-folders,
 * one per plugin or per session. Each section carries, together:
 *
 *   - an **ACL** (who may touch it, by role), and
 *   - its **data**: public attributes (world-readable) and secret attributes
 *     (gated by the section's ACL). Public and secret are equal citizens.
 *
 * Authorization is on-chain and blind: a relay/plugin asks `roleOf(section, addr)`
 * (or `authorized(section, addr, minRole)`) and the chain answers — no off-chain
 * gatekeeper decides access. Bulk data still lives in Storj rooted at the contract;
 * a section holds the authoritative small stuff (membership, keys, config).
 *
 * Roles: 0 none · 1 read · 2 write · 3 admin · 4 owner.
 *
 * The base is agnostic about WHO the contract's base authorities are. A concrete
 * contract defines that by overriding `_isSteward` — e.g. any rivet of an identity,
 * or the owner/host of a domain, or the advertiser/agency of a campaign. Stewards
 * have implicit role 4 on every section; anyone else has exactly the role the
 * section's ACL grants them.
 */
abstract contract EpisteryAccess {

    // ── roles ──────────────────────────────────────────────────────────────
    uint8 constant ROLE_NONE  = 0;
    uint8 constant ROLE_READ  = 1;
    uint8 constant ROLE_WRITE = 2;
    uint8 constant ROLE_ADMIN = 3;
    uint8 constant ROLE_OWNER = 4;

    // The "default" ACL list — the role every address gets on a section unless
    // explicitly listed. It IS a normal ACL entry, keyed on this sentinel address
    // and set with the ordinary setMember(section, DEFAULT_MEMBER, role) (an admin
    // act); roleOf falls back to it. This makes the chain the ONE membership
    // system's answer for unlisted identities — a "public" session is just one
    // whose default grants READ. Mirrors epistery-host's "default" list / the
    // app's off-chain defaultRole, but on-chain so every authorizer reads the
    // same source. address(uint160(...)) casts a plain number → address, sidestepping
    // the address-literal checksum rule for a reserved, non-EOA sentinel.
    address public constant DEFAULT_MEMBER = address(uint160(0xDEFA0117));

    // ── ACL ────────────────────────────────────────────────────────────────
    struct ACLEntry { address addr; string name; uint8 role; string meta; }
    struct Membership { string section; uint8 role; }

    mapping(string => ACLEntry[]) private _acl;            // section => entries
    mapping(string => mapping(address => uint256)) private _aclIndex; // section => addr => index+1 (0 = absent)
    mapping(address => Membership[]) private _memberships; // addr => sections it's in

    string[] private _sectionNames;                        // every section ever created
    mapping(string => bool) private _sectionSeen;

    // ── attributes (the section's data) ────────────────────────────────────
    mapping(string => mapping(string => string)) private _public;  // section => key => public value
    mapping(string => mapping(string => bytes))  private _secret;   // section => key => secret value
    mapping(string => string[]) private _publicKeyList;             // section => public key names
    mapping(string => mapping(string => bool)) private _publicKeySeen;
    mapping(string => string[]) private _secretKeyList;
    mapping(string => mapping(string => bool)) private _secretKeySeen;

    // ── invites (join a section without a pre-known address) ────────────────
    struct Invite { string section; uint8 role; address issuer; bool used; }
    mapping(bytes32 => Invite) private _invites;           // codeHash => invite

    // ── events ─────────────────────────────────────────────────────────────
    event MemberSet(string section, address indexed addr, uint8 role, address indexed by);
    event MemberRemoved(string section, address indexed addr, address indexed by);
    event PublicSet(string section, string key, address indexed by);
    event SecretSet(string section, string key, address indexed by);
    event InviteCreated(bytes32 indexed codeHash, string section, uint8 role, address indexed by);
    event InviteRedeemed(bytes32 indexed codeHash, string section, address indexed redeemer);

    // ── stewardship (defined by the concrete contract) ─────────────────────
    /**
     * @dev Is `who` a base authority over this whole contract? Concrete contracts
     *      answer: any active rivet (IdentityContract), owner||host (DomainAgent),
     *      advertiser||agency (CampaignContract). Stewards get implicit role 4 on
     *      every section — they are the interchangeable owners.
     */
    function _isSteward(address who) internal view virtual returns (bool);

    modifier onlySteward() { require(_isSteward(msg.sender), "not a steward"); _; }

    // ── authorization queries (the blind check callers use) ────────────────

    /** Effective role of `who` on `section`: 4 for any steward, else the ACL grant (0 if none). */
    function roleOf(string memory section, address who) public view returns (uint8) {
        if (_isSteward(who)) return ROLE_OWNER;
        uint256 i = _aclIndex[section][who];
        if (i != 0) return _acl[section][i - 1].role;
        // Unlisted → the section's DEFAULT_MEMBER role (0/none if no default set,
        // preserving the old private-by-default behavior). This is the single
        // source the relay/plugins already read; nothing re-derives access.
        uint256 d = _aclIndex[section][DEFAULT_MEMBER];
        return d == 0 ? ROLE_NONE : _acl[section][d - 1].role;
    }

    /** True if `who` holds at least `minRole` on `section` (minRole must be > 0). */
    function authorized(string memory section, address who, uint8 minRole) public view returns (bool) {
        return minRole != ROLE_NONE && roleOf(section, who) >= minRole;
    }

    /** True if `who` is on the section at all (any role) — the cheap membership test. */
    function isMember(string memory section, address who) external view returns (bool) {
        return roleOf(section, who) != ROLE_NONE;
    }

    /** Who may change a section's membership/attributes: a steward, or a section admin. */
    function _canManage(string memory section, address who) internal view returns (bool) {
        return roleOf(section, who) >= ROLE_ADMIN;
    }

    // ── ACL management ─────────────────────────────────────────────────────

    /** Add or update a member's role on a section. Caller must manage the section. */
    function setMember(string memory section, address addr, string memory name, uint8 role, string memory meta) external {
        require(role <= ROLE_OWNER, "invalid role");
        require(role != ROLE_NONE, "use removeMember");
        require(addr != address(0), "zero address");
        require(_canManage(section, msg.sender), "not authorized to manage section");
        _trackSection(section);

        uint256 idx = _aclIndex[section][addr];
        if (idx == 0) {
            _acl[section].push(ACLEntry({ addr: addr, name: name, role: role, meta: meta }));
            _aclIndex[section][addr] = _acl[section].length; // index+1
            _memberships[addr].push(Membership({ section: section, role: role }));
        } else {
            _acl[section][idx - 1].role = role;
            _acl[section][idx - 1].name = name;
            _acl[section][idx - 1].meta = meta;
            _updateMembershipRole(addr, section, role);
        }
        emit MemberSet(section, addr, role, msg.sender);
    }

    /** Remove a member from a section. Caller must manage the section. */
    function removeMember(string memory section, address addr) external {
        require(_canManage(section, msg.sender), "not authorized to manage section");
        uint256 idx = _aclIndex[section][addr];
        require(idx != 0, "not a member");

        ACLEntry[] storage a = _acl[section];
        uint256 last = a.length - 1;
        if (idx - 1 != last) {
            a[idx - 1] = a[last];
            _aclIndex[section][a[idx - 1].addr] = idx; // moved entry keeps index+1
        }
        a.pop();
        _aclIndex[section][addr] = 0;
        _removeMembership(addr, section);
        emit MemberRemoved(section, addr, msg.sender);
    }

    // ── attributes ─────────────────────────────────────────────────────────

    /** Set a world-readable attribute on a section. Caller must manage the section. */
    function setPublic(string memory section, string memory key, string memory value) external {
        require(_canManage(section, msg.sender), "not authorized to manage section");
        _setPublic(section, key, value);
    }

    /** Internal writer — lets a concrete contract seed public attributes from its
     *  constructor (before any external call can be made), without duplicating the
     *  section/key bookkeeping. External callers go through setPublic's ACL gate. */
    function _setPublic(string memory section, string memory key, string memory value) internal {
        _trackSection(section);
        if (!_publicKeySeen[section][key]) { _publicKeySeen[section][key] = true; _publicKeyList[section].push(key); }
        _public[section][key] = value;
        emit PublicSet(section, key, msg.sender);
    }

    /** Read a public attribute — open to anyone. */
    function getPublic(string memory section, string memory key) external view returns (string memory) {
        return _public[section][key];
    }

    /** Internal read, for concrete contracts exposing their own public attrs. */
    function _getPublic(string memory section, string memory key) internal view returns (string memory) {
        return _public[section][key];
    }

    /** Set a secret attribute on a section. Caller must manage the section. */
    function setSecret(string memory section, string memory key, bytes memory value) external {
        require(_canManage(section, msg.sender), "not authorized to manage section");
        _trackSection(section);
        if (!_secretKeySeen[section][key]) { _secretKeySeen[section][key] = true; _secretKeyList[section].push(key); }
        _secret[section][key] = value;
        emit SecretSet(section, key, msg.sender);
    }

    /** Read a secret attribute — caller must hold read+ on the section. */
    function getSecret(string memory section, string memory key) external view returns (bytes memory) {
        require(authorized(section, msg.sender, ROLE_READ), "not authorized");
        return _secret[section][key];
    }

    // ── invites ────────────────────────────────────────────────────────────

    /** Issue an invite to join a section at `role`. `codeHash` = keccak256 of an off-chain code. */
    function createInvite(bytes32 codeHash, string memory section, uint8 role) external {
        require(role != ROLE_NONE && role <= ROLE_OWNER, "invalid role");
        require(_canManage(section, msg.sender), "not authorized to manage section");
        require(_invites[codeHash].issuer == address(0), "invite exists");
        _trackSection(section);
        _invites[codeHash] = Invite({ section: section, role: role, issuer: msg.sender, used: false });
        emit InviteCreated(codeHash, section, role, msg.sender);
    }

    /** Redeem an invite, adding `redeemer` to its section. Anyone holding the code can redeem. */
    function redeemInvite(bytes32 codeHash, address redeemer, string memory name) external {
        Invite storage inv = _invites[codeHash];
        require(inv.issuer != address(0) && !inv.used, "invalid invite");
        require(redeemer != address(0), "zero address");
        inv.used = true;

        if (_aclIndex[inv.section][redeemer] == 0) {
            _acl[inv.section].push(ACLEntry({ addr: redeemer, name: name, role: inv.role, meta: '{"via":"invite"}' }));
            _aclIndex[inv.section][redeemer] = _acl[inv.section].length;
            _memberships[redeemer].push(Membership({ section: inv.section, role: inv.role }));
        } else {
            _acl[inv.section][_aclIndex[inv.section][redeemer] - 1].role = inv.role;
            _updateMembershipRole(redeemer, inv.section, inv.role);
        }
        emit InviteRedeemed(codeHash, inv.section, redeemer);
    }

    // ── enumeration / getters ──────────────────────────────────────────────

    function getSectionNames() external view returns (string[] memory) { return _sectionNames; }
    function getACL(string memory section) external view returns (ACLEntry[] memory) { return _acl[section]; }
    function getSectionsForMember(address who) external view returns (Membership[] memory) { return _memberships[who]; }
    function getPublicKeys(string memory section) external view returns (string[] memory) { return _publicKeyList[section]; }
    function getSecretKeys(string memory section) external view returns (string[] memory) { return _secretKeyList[section]; }

    // ── internals ──────────────────────────────────────────────────────────

    function _trackSection(string memory section) private {
        if (!_sectionSeen[section]) { _sectionSeen[section] = true; _sectionNames.push(section); }
    }

    function _updateMembershipRole(address addr, string memory section, uint8 role) private {
        Membership[] storage m = _memberships[addr];
        for (uint256 i; i < m.length; i++) {
            if (keccak256(bytes(m[i].section)) == keccak256(bytes(section))) { m[i].role = role; return; }
        }
    }

    function _removeMembership(address addr, string memory section) private {
        Membership[] storage m = _memberships[addr];
        for (uint256 i; i < m.length; i++) {
            if (keccak256(bytes(m[i].section)) == keccak256(bytes(section))) {
                m[i] = m[m.length - 1];
                m.pop();
                return;
            }
        }
    }
}
