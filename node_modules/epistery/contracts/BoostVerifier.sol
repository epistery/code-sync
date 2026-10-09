// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BoostVerifier — gas money drawn on an identity's own treasury
 *
 * A device at zero cannot act. Every exit from {IdentityContract}'s treasury is
 * `onlyRivet` on `msg.sender`, so a flat rivet cannot reach the identity's own
 * money however much of it is sitting there, and no contract can pay the gas
 * for a transaction it did not send. That is the corner this closes.
 *
 * A **Boost** is a statement signed by a rivet while it still has funds, naming
 * a device of the same identity and a ceiling. It costs nothing to issue and
 * consumes no nonce, so a device can leave itself a reserve. Later, anyone may
 * present it here: this contract checks it, pays the named device out of the
 * treasury, and reimburses the presenter's gas in the same transaction. The
 * carrier fronts gas for one block and is made whole; nothing is given away,
 * because the money is the identity's own, released by its own rivet.
 *
 * **No upgrade is needed.** A rivet does not have to be a key — it can be code.
 * Membership is a fact the identity contract holds about an address, and the
 * mint path already relies on that when the factory holds authority for the
 * length of one transaction. So one deployment of this contract, added as a
 * rivet by one ordinary transaction, gives Boosts to identities that are
 * already deployed and cannot be changed.
 *
 * **What adopting it costs.** Rivet membership is total authority: once added,
 * this contract could also add members, remove them, and move the whole
 * treasury. It is written to be small enough to read in one sitting and has no
 * administrator, no owner, and nothing that can be pointed at new code later.
 * Withdrawal is `removeRivet(address(this))` and takes effect immediately,
 * which is a better position than an upgradeable contract would leave.
 *
 * The signed bytes are defined once, in `client/boost-message.mjs`, and every
 * issuer imports that module. `digest()` below is the same construction in
 * Solidity and the test asserts the two agree.
 */

interface IIdentity {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
    function isAuthorized(address rivet) external view returns (bool);
    function rivetActive(address rivet) external view returns (bool);
    function sendETH(address payable recipient, uint256 amount) external;
    function getBalance() external view returns (uint256);
}

contract BoostVerifier {

    bytes32 public constant BOOST_TYPEHASH = keccak256(
        "EpisteryBoost(address verifier,address identity,uint256 chainId,address recipient,uint256 capWei,uint256 tipWei,uint256 writes,uint256 notAfter,uint256 boostId,uint256 epoch)"
    );

    /// ERC-1271's "this signature is valid" answer.
    bytes4 private constant EIP1271_MAGIC = 0x1626ba7e;

    /// Gas one ordinary identity write costs. Matches the relay's `setMember`
    /// budget, which is the dearest of the everyday writes, so a Boost sized in
    /// writes errs high rather than short. Public so anyone can check the
    /// arithmetic rather than trust it.
    uint256 public constant GAS_PER_WRITE = 250_000;

    /// Multiple of the current base fee a Boost funds to, so a device that is
    /// topped up can still act when the next block is dearer than this one.
    uint256 public constant FEE_HEADROOM = 2;

    /// Gas this call spends outside the metered span — the two payouts, the
    /// final accounting, and the transaction's own 21k. Deliberately a rough
    /// over-estimate: a carrier that is under-reimbursed will not carry.
    uint256 public constant PRESENT_OVERHEAD = 90_000;

    /**
     * The signed statement. Passed as a calldata struct rather than as loose
     * arguments because the checks plus the accounting overflow the EVM's stack
     * otherwise, and because a caller assembling seven positional numbers in
     * the right order is a bug waiting to be written.
     */
    struct Boost {
        address identity;            // the IdentityContract it is drawn on
        address payable recipient;   // the device to be paid
        uint256 capWei;              // total this Boost may cost the treasury
        uint256 tipWei;              // what the carrier earns for carrying it
        uint256 writes;              // ordinary writes it should cover
        uint256 notAfter;            // unix seconds; required, never 0
        uint256 boostId;             // presentable once
        uint256 epoch;               // the epoch it belongs to
    }

    /// identity => the epoch outstanding Boosts must belong to.
    mapping(address => uint256) public currentEpoch;

    /// identity => boostId => already presented.
    mapping(address => mapping(uint256 => bool)) public spent;

    event BoostPresented(
        address indexed identity,
        address indexed recipient,
        uint256 boostId,
        uint256 paid,
        uint256 reimbursed,
        uint256 tip,
        address carrier
    );

    event EpochAdvanced(address indexed identity, uint256 epoch, address by);

    /**
     * @notice The 32 bytes an issuer signs. Mirror of client/boost-message.mjs.
     * @dev `address(this)` is in the digest as the EIP-712 domain separator's
     * verifying contract. Without it an identity that had adopted two verifiers
     * could have one Boost presented at each, since each keeps its own spent
     * map, and the ceiling would be paid twice.
     */
    function digest(
        address identity,
        address recipient,
        uint256 capWei,
        uint256 tipWei,
        uint256 writes,
        uint256 notAfter,
        uint256 boostId,
        uint256 epoch
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            BOOST_TYPEHASH,
            address(this),
            identity,
            block.chainid,
            recipient,
            capWei,
            tipWei,
            writes,
            notAfter,
            boostId,
            epoch
        ));
    }

    /**
     * @notice Present a Boost. Callable by anyone holding one.
     *
     * Four checks carry the safety, and each is evaluated NOW rather than when
     * the Boost was issued, which is what makes revocation free:
     *
     * 1. the device being paid is an active rivet of this identity, so a Boost
     *    is a gas instrument for an identity's own devices and retiring a lost
     *    device voids every Boost aimed at it;
     * 2. the issuer is an active rivet, so removing a compromised device voids
     *    everything it ever issued, retroactively;
     * 3. the id is unspent and the epoch is current, so one Boost pays once
     *    and advancing the epoch voids the whole reserve at one stroke;
     * 4. the reimbursement is measured and the ceiling bounds the payout, the
     *    reimbursement and the tip together, so a Boost can never cost more
     *    than its stated figure and presenting is never a way to drain a
     *    treasury.
     *
     * A carrier should simulate before presenting: an empty treasury means it
     * pays the gas and collects nothing.
     */
    function present(Boost calldata b, bytes calldata signature) external {
        uint256 gasStart = gasleft();
        IIdentity id = IIdentity(b.identity);

        // Fail closed and legibly, in the order that costs least to discover.
        require(b.notAfter != 0, "boost has no expiry");
        require(block.timestamp <= b.notAfter, "boost expired");
        require(b.capWei != 0, "boost has no ceiling");
        require(!spent[b.identity][b.boostId], "boost already presented");
        require(currentEpoch[b.identity] == b.epoch, "boost epoch superseded");
        require(
            id.isAuthorized(address(this)) && id.rivetActive(address(this)),
            "this verifier is not a rivet of that identity"
        );
        require(
            id.isAuthorized(b.recipient) && id.rivetActive(b.recipient),
            "recipient is not an active rivet"
        );

        // The issuer check IS the identity contract's own ERC-1271: it recovers
        // the signer from the personal_sign wrapper and answers only for an
        // authorised, active rivet. Delegating it means no second copy of the
        // rivet rule and no ecrecover here to get wrong.
        require(
            id.isValidSignature(
                digest(b.identity, b.recipient, b.capWei, b.tipWei, b.writes, b.notAfter, b.boostId, b.epoch),
                signature
            ) == EIP1271_MAGIC,
            "boost not issued by an active rivet"
        );

        spent[b.identity][b.boostId] = true;

        uint256 paid;
        uint256 tip;
        uint256 reimbursed;
        {
            // Three claims on one ceiling, settled in priority order.
            //
            // The carrier's costs come first: a carrier that is not made whole
            // does not carry, and then nothing else in this transaction
            // happens. Its tip comes second, because the tip is the reason a
            // stranger spent a nonce on someone else's device — a Boost that is
            // unprofitable to carry is a Boost that does not work. The device
            // takes what remains, which is the point of the instrument, so the
            // floor below refuses to settle at all rather than deliver it an
            // amount too small to act on.
            reimbursed = (gasStart - gasleft() + PRESENT_OVERHEAD) * tx.gasprice;
            if (reimbursed > b.capWei) reimbursed = b.capWei;

            uint256 remaining = b.capWei - reimbursed;
            tip = b.tipWei > remaining ? remaining : b.tipWei;
            remaining -= tip;

            // Sized on presentation, not at issue. A fixed amount rots: one
            // written when fees were low is worthless in a busy market. The
            // ceiling is what the issuer fixed; the amount is what the chain
            // says that work costs now. A chain with no base fee (non-1559)
            // reports zero, where the only honest answer is what is left.
            uint256 fee = block.basefee;
            paid = fee == 0 ? remaining : b.writes * GAS_PER_WRITE * fee * FEE_HEADROOM;
            if (paid > remaining) paid = remaining;

            // One write's gas is the least useful outcome. Below it the device
            // is still stuck, so a ceiling that cannot reach it is a mistake to
            // report, not a payment to make.
            require(paid >= (fee == 0 ? 1 : GAS_PER_WRITE * fee), "boost ceiling too low at the current fee");
        }

        require(id.getBalance() >= paid + reimbursed + tip, "treasury cannot cover this boost");

        // `sendETH` forwards only the 2300-gas stipend, so both payees must be
        // ordinary accounts. A carrier with logic in its fallback cannot be
        // reimbursed, which is a documented condition of carrying rather than a
        // case to work around here.
        id.sendETH(b.recipient, paid);
        // The carrier's costs and its tip are one payment: two transfers to the
        // same address would just burn more of the ceiling on gas.
        if (reimbursed + tip > 0) id.sendETH(payable(msg.sender), reimbursed + tip);

        emit BoostPresented(b.identity, b.recipient, b.boostId, paid, reimbursed, tip, msg.sender);
    }

    /**
     * @notice Void every outstanding Boost of an identity at one stroke.
     *
     * Any active rivet may do this, because a reserve is the identity's own
     * paper and the hour it leaks is not the hour to look for a quorum. It is
     * an ordinary transaction, so it needs a solvent device — a flat one cannot
     * revoke, which is the accepted limit of this version.
     */
    function advanceEpoch(address identity) external returns (uint256) {
        IIdentity id = IIdentity(identity);
        require(
            id.isAuthorized(msg.sender) && id.rivetActive(msg.sender),
            "only an active rivet may advance the epoch"
        );
        uint256 next = ++currentEpoch[identity];
        emit EpochAdvanced(identity, next, msg.sender);
        return next;
    }
}
