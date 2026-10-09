// BoostVerifier — against a real IdentityContract on the local network.
//
// Runs entirely in-process: no RPC, no funded key, nothing to configure. That
// is deliberate, because the thing most worth proving here cannot be checked by
// reading either file — that client/boost-message.mjs and BoostVerifier.digest()
// produce the same 32 bytes. If those ever drift, every Boost ever issued stops
// verifying, and the failure looks like a bad signature rather than like a
// changed encoding.
//
//   npx hardhat test test/BoostVerifier.js
//
// Plain node:assert and a hand-rolled revert helper on purpose: this repo has
// neither hardhat-chai-matchers nor waffle, and chai 6 is ESM-only, so
// `require('chai')` would not load in a CommonJS mocha test.

const assert = require('node:assert/strict');
const { ethers } = require('hardhat');

async function expectRevert(promise, fragment) {
  try {
    await promise;
  } catch (e) {
    assert.ok(
      e.message.includes(fragment),
      `expected a revert containing "${fragment}", got: ${e.message}`
    );
    return;
  }
  assert.fail(`expected a revert containing "${fragment}", but the call succeeded`);
}

describe('BoostVerifier', function () {
  let boostlib;
  let identity, verifier;
  let owner, device, carrier, stranger;
  let chainId;

  before(async function () {
    // The canonical issuer module is ESM; this test file is CommonJS.
    boostlib = await import('../client/boost-message.mjs');
  });

  beforeEach(async function () {
    [owner, device, carrier, stranger] = await ethers.getSigners();
    chainId = (await ethers.provider.getNetwork()).chainId;

    // owner is the first rivet; device is added as a second one — a backup is a
    // signer the owner adds — so it is a legitimate recipient.
    const Identity = await ethers.getContractFactory('IdentityContract');
    identity = await Identity.deploy(owner.address, 'first', '', ethers.constants.AddressZero, '');
    await identity.deployed();
    await identity.connect(owner).addRivet(device.address, 'device');

    const Verifier = await ethers.getContractFactory('BoostVerifier');
    verifier = await Verifier.deploy();
    await verifier.deployed();

    // The treasury, and the one ordinary transaction that adopts the verifier.
    await owner.sendTransaction({ to: identity.address, value: ethers.utils.parseEther('10') });
    await identity.connect(owner).addRivet(verifier.address, 'boost');
  });

  async function makeBoost(overrides = {}, signer = owner) {
    const now = (await ethers.provider.getBlock('latest')).timestamp;
    const boost = {
      verifier: verifier.address,
      identity: identity.address,
      chainId,
      recipient: device.address,
      capWei: ethers.utils.parseEther('1'),
      tipWei: ethers.utils.parseEther('0.01'),
      writes: 3,
      notAfter: now + 3600,
      boostId: 1,
      epoch: 0,
      ...overrides,
    };
    return boostlib.issueBoost(boost, signer, ethers);
  }

  // The contract takes the statement as a struct; the issuer module produces a
  // flat object plus a signature. This is the one place the two shapes meet.
  function present(boost, as = carrier) {
    return verifier.connect(as).present({
      identity: boost.identity,
      recipient: boost.recipient,
      capWei: boost.capWei,
      tipWei: boost.tipWei,
      writes: boost.writes,
      notAfter: boost.notAfter,
      boostId: boost.boostId,
      epoch: boost.epoch,
    }, boost.signature);
  }

  it('agrees with the JavaScript issuer on the digest', async function () {
    const boost = await makeBoost();
    const onChain = await verifier.digest(
      boost.identity, boost.recipient, boost.capWei, boost.tipWei,
      boost.writes, boost.notAfter, boost.boostId, boost.epoch
    );
    assert.equal(onChain, boostlib.boostDigest(boost, ethers));
  });

  it('pays a flat device from the treasury and reimburses the carrier', async function () {
    const boost = await makeBoost();

    const deviceBefore = await ethers.provider.getBalance(device.address);
    const carrierBefore = await ethers.provider.getBalance(carrier.address);
    const treasuryBefore = await identity.getBalance();

    const receipt = await (await present(boost)).wait();

    const paid = (await ethers.provider.getBalance(device.address)).sub(deviceBefore);
    assert.ok(paid.gt(0), 'the device should have been paid');

    // The carrier fronted gas, was reimbursed and took its tip, all inside the
    // same transaction — so it should be AHEAD, not merely whole. Break-even is
    // not a reason to spend a nonce on someone else's device.
    const spent = receipt.gasUsed.mul(receipt.effectiveGasPrice);
    const carrierNet = (await ethers.provider.getBalance(carrier.address)).sub(carrierBefore);
    assert.ok(
      carrierNet.gt(0),
      `carrier should profit by roughly the tip; net ${carrierNet.toString()} after gas ${spent.toString()}`
    );
    const event = receipt.events.find((e) => e.event === 'BoostPresented');
    assert.equal(event.args.tip.toString(), boost.tipWei.toString(), 'the tip should be paid in full');
    assert.ok(event.args.reimbursed.gte(spent), 'reimbursement should cover the gas actually spent');

    // The ceiling bounds the payout and the reimbursement together.
    const treasuryDrop = treasuryBefore.sub(await identity.getBalance());
    assert.ok(treasuryDrop.lte(boost.capWei), 'a boost must never cost more than its ceiling');
  });

  it('keeps the payout, the reimbursement and the tip inside the ceiling', async function () {
    // A tip larger than the ceiling cannot reach past it, and what is left over
    // must still be enough for the device to act — otherwise the whole
    // presentation is refused rather than half-delivered.
    const greedy = await makeBoost({ boostId: 20, tipWei: ethers.utils.parseEther('5') });
    await expectRevert(present(greedy), 'boost ceiling too low at the current fee');

    const treasuryBefore = await identity.getBalance();
    const boost = await makeBoost({ boostId: 21, capWei: ethers.utils.parseEther('0.5') });
    const receipt = await (await present(boost)).wait();
    const drop = treasuryBefore.sub(await identity.getBalance());
    assert.ok(drop.lte(boost.capWei), `treasury dropped ${drop.toString()}, ceiling ${boost.capWei.toString()}`);
    const e = receipt.events.find((x) => x.event === 'BoostPresented');
    assert.ok(
      e.args.paid.add(e.args.reimbursed).add(e.args.tip).lte(boost.capWei),
      'the three claims together must not exceed the ceiling'
    );
  });

  it('refuses a ceiling too small to leave the device anything useful', async function () {
    const boost = await makeBoost({ boostId: 22, capWei: 1000, tipWei: 0 });
    await expectRevert(present(boost), 'boost ceiling too low at the current fee');
  });

  it('refuses a second presentation of the same boost', async function () {
    const boost = await makeBoost();
    await present(boost);
    await expectRevert(present(boost), 'boost already presented');
  });

  it('refuses a boost signed by someone who is not a rivet', async function () {
    const boost = await makeBoost({}, stranger);
    await expectRevert(present(boost), 'boost not issued by an active rivet');
  });

  it('refuses a boost issued by a rivet that has since been removed', async function () {
    // Issued BY device (the host rivet) and payable to owner, so that removing
    // the issuer is the only thing the presentation can fail on. Pointing it at
    // the issuer itself would fail the recipient check first and prove nothing
    // about retroactive revocation.
    const boost = await makeBoost({ recipient: owner.address, boostId: 7 }, device);
    await present(boost);                                  // valid while device is a rivet
    const again = await makeBoost({ recipient: owner.address, boostId: 8 }, device);
    await identity.connect(owner).removeRivet(device.address);
    await expectRevert(present(again), 'boost not issued by an active rivet');
  });

  it('refuses to pay an address that is not a device of this identity', async function () {
    const boost = await makeBoost({ recipient: stranger.address, boostId: 2 });
    await expectRevert(present(boost), 'recipient is not an active rivet');
  });

  it('refuses an expired boost and one with no expiry', async function () {
    const now = (await ethers.provider.getBlock('latest')).timestamp;
    await expectRevert(present(await makeBoost({ notAfter: now - 1, boostId: 3 })), 'boost expired');
    await expectRevert(present(await makeBoost({ notAfter: 0, boostId: 4 })), 'boost has no expiry');
  });

  it('voids the whole reserve when the epoch is advanced', async function () {
    const reserve = [
      await makeBoost({ boostId: 10 }),
      await makeBoost({ boostId: 11 }),
    ];
    await expectRevert(
      verifier.connect(stranger).advanceEpoch(identity.address),
      'only an active rivet may advance the epoch'
    );
    await verifier.connect(owner).advanceEpoch(identity.address);
    assert.equal((await verifier.currentEpoch(identity.address)).toNumber(), 1);
    for (const boost of reserve) {
      await expectRevert(present(boost), 'boost epoch superseded');
    }
    // A freshly issued boost on the new epoch still works.
    await present(await makeBoost({ boostId: 12, epoch: 1 }));
  });

  it('refuses to act for an identity that has not adopted it', async function () {
    const boost = await makeBoost({ boostId: 5 });
    await identity.connect(owner).removeRivet(verifier.address);
    await expectRevert(present(boost), 'this verifier is not a rivet of that identity');
  });

  it('refuses when the treasury cannot cover the boost', async function () {
    // Move the treasury out from under it, leaving less than the ceiling.
    const balance = await identity.getBalance();
    await identity.connect(owner).sendETH(owner.address, balance);
    await expectRevert(present(await makeBoost({ boostId: 6 })), 'treasury cannot cover this boost');
  });
});
