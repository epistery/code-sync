// The ONE definition of an epistery Boost — the signed statement that releases
// gas money from an identity's treasury to one of its own devices.
//
// A Boost exists because of a corner in the gas model. The rivet always pays
// its own gas, and every exit from the IdentityContract treasury is onlyRivet
// on msg.sender, so a device at zero cannot reach the identity's own money
// however much of it is sitting there. A pre-signed TRANSACTION does not fix
// that: it is welded to the signer's nonce, to a fee ceiling that raises the
// balance the signer must hold, and above all its sender still pays its own
// gas. Signing in advance changes who must be present, never who pays.
//
// So a Boost is not a transaction. It is a message, signed while the device
// still has funds, that any third party can carry to BoostVerifier later. The
// carrier fronts the gas for one transaction and is reimbursed inside it.
//
// Every party that issues a Boost — the browser rivet, a host wallet, a CLI —
// and the contract that honours it MUST agree on these exact bytes, which is
// why this is a module and not a string copied into three clients. Same reason
// as storage-message.mjs: one definition, imported, never re-inlined.
//
// Pure ESM with no imports. `ethers` is passed in, following the convention in
// client/wallet.js, so the identical module loads in Node and in a browser.
//
// Wire shape: keccak256 over the ABI encoding of the typehash and ten fields,
// then signed with personal_sign over those 32 bytes. That is deliberate — it
// is the same construction IdentityContract.isValidSignature already performs,
// so the verifier delegates the rivet check to the deployed identity contract
// rather than re-implementing ecrecover. Changing the type string, the field
// order, or the encoding breaks every issuer and the verifier at once.

export const BOOST_TYPE_STRING =
  'EpisteryBoost(address verifier,address identity,uint256 chainId,address recipient,uint256 capWei,uint256 tipWei,uint256 writes,uint256 notAfter,uint256 boostId,uint256 epoch)';

// The ABI types of the encoded statement, typehash first. Mirrors
// BoostVerifier.digest() exactly.
const BOOST_ABI_TYPES = [
  'bytes32',   // BOOST_TYPEHASH
  'address',   // verifier  — which BoostVerifier may honour this
  'address',   // identity  — the IdentityContract it is drawn on
  'uint256',   // chainId
  'address',   // recipient — the device to be paid
  'uint256',   // capWei    — total this Boost may cost the treasury
  'uint256',   // tipWei    — what the carrier earns for fronting the gas
  'uint256',   // writes    — how many ordinary writes it should cover
  'uint256',   // notAfter  — unix seconds, required, never 0
  'uint256',   // boostId   — presentable once
  'uint256',   // epoch     — the epoch it belongs to
];

export function boostTypehash(ethers) {
  return ethers.utils.id(BOOST_TYPE_STRING);
}

// The 32 bytes an issuer signs and the verifier recomputes.
//
// `verifier` is in the digest on purpose. It is the EIP-712 domain separator's
// job: without it, an identity that had added two verifiers could have the same
// Boost presented at each, since each keeps its own spent-ids map, and the cap
// would be paid twice.
//
// `tipWei` is what makes carrying worth doing. Reimbursement alone leaves a
// carrier exactly whole, which is not a reason to spend a nonce, so a Boost
// nobody will carry is a Boost that does not work. The tip is signed rather
// than configured because the price of the favour is the issuer's to set, and a
// figure baked into immutable bytecode could not be changed when the market
// moved. It is also the ONLY thing a taker of a leaked reserve can earn, and
// they can earn it only by actually delivering the gas to the named device.
export function boostDigest(boost, ethers) {
  const fields = [
    boostTypehash(ethers),
    boost.verifier,
    boost.identity,
    boost.chainId,
    boost.recipient,
    boost.capWei,
    boost.tipWei,
    boost.writes,
    boost.notAfter,
    boost.boostId,
    boost.epoch,
  ];
  for (const [i, v] of fields.entries()) {
    if (v === undefined || v === null) throw new Error(`boostDigest: ${BOOST_ABI_TYPES[i]} field ${i} is missing`);
  }
  return ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(BOOST_ABI_TYPES, fields));
}

// Issue a Boost: sign the digest with a rivet key that is solvent NOW, for a
// device that may be flat LATER. Costs no gas and consumes no nonce, so a
// device can issue a reserve of these in one sitting.
//
// Returns the statement plus its signature — the whole redeemable artifact,
// which is safe to store anywhere a flat device can read without paying,
// because the recipient is named in the signed fields and a taker can only
// force payment to that device.
export async function issueBoost(boost, signer, ethers) {
  const signature = await signer.signMessage(ethers.utils.arrayify(boostDigest(boost, ethers)));
  return { ...boost, signature };
}
