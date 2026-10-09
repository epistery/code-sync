import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
import { withPeerCapability } from '../src/utils/PeerCapability';

describe('withPeerCapability', () => {
  it('advertises the capability the browser wallets carry', () => {
    const w = withPeerCapability(ethers.Wallet.createRandom());
    expect(w.canPeerEncrypt).toBe(true);
    expect(typeof w.computeSharedSecret).toBe('function');
  });

  it('computes the raw ECDH shared secret both sides agree on', async () => {
    const a = withPeerCapability(ethers.Wallet.createRandom());
    const b = withPeerCapability(ethers.Wallet.createRandom());
    const ab = await a.computeSharedSecret(b.publicKey);
    const ba = await b.computeSharedSecret(a.publicKey, ethers);
    expect(ab).toBeInstanceOf(Uint8Array);
    expect(ab.length).toBe(32);
    expect(ethers.utils.hexlify(ab)).toBe(ethers.utils.hexlify(ba));
  });

  it('leaves the wallet a normal ethers signer', async () => {
    const w = withPeerCapability(ethers.Wallet.createRandom());
    const sig = await w.signMessage('hello');
    expect(ethers.utils.verifyMessage('hello', sig)).toBe(w.address);
  });
});
