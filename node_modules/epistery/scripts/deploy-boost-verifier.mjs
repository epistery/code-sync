#!/usr/bin/env node
// Deploy BoostVerifier and print what is needed to adopt it.
//
// Usage:
//   node scripts/deploy-boost-verifier.mjs <domain> [--dry-run]
//
// <domain> names the epistery config whose wallet pays the gas and whose provider
// says which chain this lands on — the same config the relay loads. Omit it for
// root config. --dry-run estimates and prints without sending.
//
// The contract takes no constructor arguments: everything it needs is a constant
// in its own bytecode. It has no owner, no administrator and nothing repointable,
// which is the point — and also why deploying it is only half the job.
//
// ADOPTION IS THE OTHER HALF AND CANNOT BE DONE HERE. Adding the verifier as a
// rivet is `addRivet`, which is onlyRivet: it must be sent BY an existing rivet of
// the identity adopting it. Those keys are non-extractable and live in a browser,
// which is the whole design — so no script, this one included, can adopt on
// someone's behalf. The address is printed for the person holding the device to
// add on the Identity page.
//
// WHAT ADOPTING COSTS. Rivet membership is total authority: once added, this
// contract can also add members, remove them, and move the whole treasury. It is
// small enough to read in one sitting, and a fault in it is a fault in every
// identity that adopted it. Deploy it for one identity, live with it, and only
// then offer it to others.

import { ethers } from 'ethers';
import { Config } from '../index.mjs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const artifact = require('../artifacts/contracts/BoostVerifier.sol/BoostVerifier.json');

const args = process.argv.slice(2).filter((a) => a !== '--dry-run');
const dryRun = process.argv.includes('--dry-run');
const domain = args[0] || null;

const die = (msg) => { console.error(`\n${msg}\n`); process.exit(1); };

const cfg = new Config();
await cfg.setPath(domain ? `/${domain}` : '/');
const data = cfg.data || {};
const wallet = data.wallet || {};
const provider = data.provider || {};

if (!wallet.mnemonic && !wallet.privateKey) {
  die(`No wallet in ${domain ? `~/.epistery/${domain}` : 'root'} config. This script spends real gas; point it at a config whose [wallet] is funded.`);
}
if (!provider.rpc && !provider.privateRpc) {
  die(`No [provider] rpc in that config — nothing to say which chain to deploy to.`);
}

const rpc = provider.privateRpc || provider.rpc;
const chainId = parseInt(provider.chainId, 10) || undefined;
const rpcProvider = new ethers.providers.JsonRpcProvider(rpc, chainId ? { name: provider.name || 'chain', chainId } : undefined);
const signer = wallet.mnemonic
  ? ethers.Wallet.fromMnemonic(wallet.mnemonic).connect(rpcProvider)
  : new ethers.Wallet(wallet.privateKey, rpcProvider);

const net = await rpcProvider.getNetwork();
const balance = await rpcProvider.getBalance(signer.address);
const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, signer);
const deployTx = factory.getDeployTransaction();
const gas = await rpcProvider.estimateGas({ ...deployTx, from: signer.address });
// Polygon will not include a transaction whose PRIORITY fee is below roughly 25
// gwei, however generous its max fee is. The provider's own suggestion is well
// under that, so a transaction built from getFeeData alone is silently dropped
// from the mempool rather than mined or rejected. This mirrors the relay's
// polygonFee() rather than inventing a second fee rule — the estate has already
// paid to learn this one.
const MIN_PRIORITY_GWEI = 30;
async function quote() {
  const f = await rpcProvider.getFeeData();
  const isPolygon = net.chainId === 137 || net.chainId === 80002;
  let maxFee = (f.maxFeePerGas || f.gasPrice).mul(120).div(100);
  let priority = (f.maxPriorityFeePerGas || f.gasPrice).mul(120).div(100);
  const floor = ethers.utils.parseUnits(String(MIN_PRIORITY_GWEI), 'gwei');
  if (isPolygon && priority.lt(floor)) priority = floor;
  if (maxFee.lt(priority)) maxFee = priority.mul(2);
  return { maxFee, priority };
}
const fee = await quote();
const price = fee.maxFee;
const cost = gas.mul(price);

console.log(`\nBoostVerifier`);
console.log(`  chain      : ${net.name} (${net.chainId})`);
console.log(`  deployer   : ${signer.address}`);
console.log(`  balance    : ${ethers.utils.formatEther(balance)}`);
console.log(`  gas        : ${gas.toString()} at ${ethers.utils.formatUnits(price, 'gwei')} gwei max, ${ethers.utils.formatUnits(fee.priority, 'gwei')} gwei priority`);
console.log(`  est. cost  : ${ethers.utils.formatEther(cost)}`);

if (balance.lt(cost)) die(`Deployer holds less than the estimated cost. Fund ${signer.address} and run again.`);
if (dryRun) { console.log(`\n--dry-run: nothing sent.\n`); process.exit(0); }

console.log(`\nDeploying…`);
const contract = await factory.deploy({ maxFeePerGas: fee.maxFee, maxPriorityFeePerGas: fee.priority });
console.log(`  tx         : ${contract.deployTransaction.hash}`);
await contract.deployed();
console.log(`  deployed   : ${contract.address}`);

console.log(`\nTwo things remain, neither of which this script can do:\n`);
console.log(`  1. ADOPT it on each identity that wants Boosts. From that identity's own`);
console.log(`     device: Identity → Add signer → ${contract.address}`);
console.log(`     (addRivet is onlyRivet — it must be signed by a rivet already on the contract.)\n`);
console.log(`  2. TELL THE CARRIER where it is, so the relay will present against it:`);
console.log(`     [relay] boostVerifier=${contract.address}\n`);
