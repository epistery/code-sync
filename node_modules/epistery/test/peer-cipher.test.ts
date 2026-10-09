import { describe, it, expect } from 'vitest';
import { createHash, createDecipheriv, createCipheriv, randomBytes } from 'crypto';
import { ethers } from 'ethers';
import {
  randomKey, ecdhShared, wrapKey, unwrapKey, encryptText, decryptText, encryptBytes, decryptBytes,
  sealWithShared, openWithShared, toHex, fromHex,
} from '../client/peer-cipher.mjs';

// FROZEN VECTORS, produced by the previous server implementation
// (@epistery/sessions bot-identity.mjs, node:crypto) on 2026-09-30, before it was
// replaced by this module. They are the wire: a wrap a device wrote months ago
// must open here, and what this module writes must open there.
const V = {
  "wrapper": {
    "priv": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "pub": "0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1"
  },
  "peer": {
    "priv": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "pub": "0x04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276728176c3c6431f8eeda4538dc37c865e2784f3a9e77d044f33e407797e1278a"
  },
  "K": "0xabababababababababababababababababababababababababababababababab",
  "wrap": {
    "ciphertext": "0x30b7c8bb9b7e56249ebbe0fa4022c1b9279443ef9afcf3a90f2f5e289fa1227c",
    "iv": "0x84705ece6ea5ee22d5319248",
    "tag": "0xfbe54e1be5468c1cf40360b90436d69c",
    "wrapperPubKey": "0x044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1"
  },
  "text": "frozen vector \u2014 the existing construction, 2026-09-30 \u2713",
  "blob": {
    "iv": "0xea00c799d12f1db94af4e0ea",
    "ciphertext": "0x0b77d07111badc4de47cda1a0f9e2f604436a1ec161f77da674d4b8ffbae06725354406c9ad773a6de09bc63665ef2f075f8fdd51995e12fa87e18745b7fe3b9f68b3f52f5573313da7aeb"
  }
};

const wrapper = new ethers.Wallet(V.wrapper.priv);
const peer = new ethers.Wallet(V.peer.priv);

describe('peer-cipher — the one construction, frozen against the previous implementation', () => {
  it('opens a wrap the previous server implementation wrote', async () => {
    expect(await unwrapKey(V.wrap, V.wrapper.pub, peer, ethers)).toBe(V.K);
  });

  it('opens content the previous server implementation sealed', async () => {
    expect(await decryptText(V.K, V.blob)).toBe(V.text);
  });

  it('writes a wrap the previous construction opens (node:crypto, SHA-256(ECDH) + AES-256-GCM, tag split off)', async () => {
    const w = await wrapKey(V.K, V.peer.pub, wrapper, ethers);
    expect(fromHex(w.ciphertext)).toHaveLength(32);
    expect(fromHex(w.iv)).toHaveLength(12);
    expect(fromHex(w.tag)).toHaveLength(16);
    const shared = new ethers.utils.SigningKey(V.peer.priv).computeSharedSecret(V.wrapper.pub);
    const key = createHash('sha256').update(Buffer.from(ethers.utils.arrayify(shared))).digest();
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(fromHex(w.iv)));
    d.setAuthTag(Buffer.from(fromHex(w.tag)));
    const pt = Buffer.concat([d.update(Buffer.from(fromHex(w.ciphertext))), d.final()]);
    expect('0x' + pt.toString('hex')).toBe(V.K);
  });

  it('writes content the previous construction opens (AES-256-GCM under K, tag appended)', async () => {
    const b = await encryptText(V.K, V.text);
    const data = Buffer.from(fromHex(b.ciphertext));
    const d = createDecipheriv('aes-256-gcm', Buffer.from(fromHex(V.K)), Buffer.from(fromHex(b.iv)));
    d.setAuthTag(data.subarray(data.length - 16));
    expect(Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]).toString('utf8')).toBe(V.text);
  });

  it('round-trips a wrap in both directions and content, bytes and text', async () => {
    const K = randomKey();
    expect(fromHex(K)).toHaveLength(32);
    const w = await wrapKey(K, peer.publicKey, wrapper, ethers);
    expect(await unwrapKey(w, wrapper.publicKey, peer, ethers)).toBe(K);
    const w2 = await wrapKey(K, wrapper.publicKey, peer, ethers);
    expect(await unwrapKey(w2, peer.publicKey, wrapper, ethers)).toBe(K);
    const bytes = randomBytes(1000);
    const eb = await encryptBytes(K, bytes);
    expect(Buffer.from(await decryptBytes(K, eb.iv, eb.ciphertext)).equals(bytes)).toBe(true);
    const et = await encryptText(K, 'ünïcode ✓');
    expect(await decryptText(K, et)).toBe('ünïcode ✓');
  });

  it('ecdhShared is the raw X coordinate ethers computes, and sealWithShared/openWithShared agree', async () => {
    const shared = ecdhShared(V.wrapper.priv, V.peer.pub, ethers);
    expect(toHex(shared)).toBe(new ethers.utils.SigningKey(V.wrapper.priv).computeSharedSecret(V.peer.pub));
    const s = await sealWithShared(shared, new TextEncoder().encode('x'));
    expect(new TextDecoder().decode(await openWithShared(ecdhShared(V.peer.priv, V.wrapper.pub, ethers), s.ciphertext, s.iv, s.tag))).toBe('x');
  });

  it('asks a wallet by capability: a rivet-shaped wallet wraps through encryptForPeer', async () => {
    const rivet = {
      publicKey: peer.publicKey,
      encryptForPeer: async (pub, bytes, e) => sealWithShared(ecdhShared(peer.privateKey, pub, e), bytes),
      decryptFromPeer: async (pub, ct, iv, tag, e) => openWithShared(ecdhShared(peer.privateKey, pub, e), ct, iv, tag),
    };
    const K = randomKey();
    const w = await wrapKey(K, wrapper.publicKey, rivet, ethers);
    expect(await unwrapKey(w, peer.publicKey, wrapper, ethers)).toBe(K);
    const w2 = await wrapKey(K, peer.publicKey, wrapper, ethers);
    expect(await unwrapKey(w2, wrapper.publicKey, rivet, ethers)).toBe(K);
    await expect(wrapKey(K, peer.publicKey, {}, ethers)).rejects.toThrow(/neither/);
  });

  it('a tampered record does not open', async () => {
    const b = await encryptText(V.K, 'hello');
    const bad = { ...b, ciphertext: b.ciphertext.slice(0, -2) + (b.ciphertext.endsWith('00') ? '01' : '00') };
    await expect(decryptText(V.K, bad)).rejects.toThrow();
  });
});
