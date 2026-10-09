import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { ethers } from 'ethers';
import {
  STORAGE_WRITE_TAG, storageWriteMessage, parseStorageWriteMessage,
  encodeStorageCredential, decodeStorageCredential, storageAuthorization, signStorageWrite,
  sha256hex, isAddress, ADDRESS_RE, base64urlEncode, base64urlDecode,
} from '../client/storage-message.mjs';

// The bytes the relay, relay-client, sessions and the console produced by hand
// before this module owned them. Frozen here so the one home can never drift
// from what is already stored and verified in production.
const legacyCredential = (fields: Record<string, string>) =>
  Buffer.from(JSON.stringify(fields)).toString('base64url');

describe('storage-write wire — the one home', () => {
  const contract = '0x80f84221dcCC8d049f34b449DFC825B6940BD85f';
  const fields = { method: 'PUT', contract, subpath: 'abc/post-1.json', bodyHashHex: 'ff'.repeat(32), ts: 1790000000000 };

  it('builds the six-line message and reads it back', () => {
    const m = storageWriteMessage(fields);
    expect(m.split('\n')).toHaveLength(6);
    expect(m.startsWith(STORAGE_WRITE_TAG + '\n')).toBe(true);
    expect(parseStorageWriteMessage(m)).toEqual(fields);
  });

  it('refuses anything that is not exactly a storage-write message', () => {
    expect(parseStorageWriteMessage('epistery-storage-write\nPUT\nx')).toBeNull();
    expect(parseStorageWriteMessage(storageWriteMessage({ ...fields, ts: 'soon' as any }))).toBeNull();
    expect(parseStorageWriteMessage(['other-tag', 'PUT', contract, 'p', 'h', '1'].join('\n'))).toBeNull();
    expect(parseStorageWriteMessage(undefined as any)).toBeNull();
  });

  it('encodes the credential byte-for-byte as the legacy Buffer builders did, with and without identity', () => {
    const c = { address: contract, signature: '0xsig', message: 'm' };
    expect(encodeStorageCredential(c)).toBe(legacyCredential(c));
    const ci = { ...c, identity: '0x78b738f3D02d67256D603C46F4aB01F9D587997b' };
    expect(encodeStorageCredential(ci)).toBe(legacyCredential(ci));
    // identity absent or empty is the three-field form, not a null field
    expect(encodeStorageCredential({ ...c, identity: null })).toBe(legacyCredential(c));
  });

  it('decodes what Node decodes, and reads the Bot header form too', () => {
    const ci = { address: contract, signature: '0xsig', message: 'm', identity: '0x78b738f3D02d67256D603C46F4aB01F9D587997b' };
    const cred = encodeStorageCredential(ci);
    expect(JSON.parse(Buffer.from(cred, 'base64url').toString('utf8'))).toEqual(ci);
    expect(decodeStorageCredential(cred)).toEqual(ci);
    expect(decodeStorageCredential(storageAuthorization(cred))).toEqual(ci);
    expect(decodeStorageCredential(encodeStorageCredential({ address: contract, signature: '0xsig', message: 'm' }))).toEqual({ address: contract, signature: '0xsig', message: 'm', identity: null });
  });

  it('refuses a credential that names no address, signature or message', () => {
    expect(decodeStorageCredential('not base64!')).toBeNull();
    expect(decodeStorageCredential(base64urlEncode(JSON.stringify({ address: 'x', signature: 's', message: 'm' })))).toBeNull();
    expect(decodeStorageCredential(base64urlEncode(JSON.stringify({ address: contract, message: 'm' })))).toBeNull();
    expect(decodeStorageCredential(base64urlEncode('"just a string"'))).toBeNull();
  });

  it('base64url round-trips UTF-8 and matches Buffer', () => {
    const s = 'sub/ünïcode — path';
    expect(base64urlEncode(s)).toBe(Buffer.from(s).toString('base64url'));
    expect(new TextDecoder().decode(base64urlDecode(base64urlEncode(s)))).toBe(s);
  });

  it('signs a write that recovers to the signer and verifies as the relay does', async () => {
    const w = ethers.Wallet.createRandom();
    const { message, credential, authorization } = await signStorageWrite({
      sign: (m: string) => w.signMessage(m), address: w.address, identity: contract,
      method: 'POST', contract, subpath: 'abc/_ds/commit', bodyHashHex: await sha256hex('bytes'), ts: fields.ts,
    });
    expect(authorization).toBe(`Bot ${credential}`);
    const c = decodeStorageCredential(credential)!;
    expect(c.message).toBe(message);
    expect(ethers.utils.verifyMessage(c.message, c.signature)).toBe(w.address);
    expect(c.identity).toBe(contract);
    expect(parseStorageWriteMessage(c.message)!.bodyHashHex).toBe(createHash('sha256').update('bytes').digest('hex'));
  });

  it('sha256hex is node:crypto sha256, over strings and bytes', async () => {
    expect(await sha256hex('')).toBe(createHash('sha256').update('').digest('hex'));
    const bytes = new Uint8Array([1, 2, 3, 250]);
    expect(await sha256hex(bytes)).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(await sha256hex(bytes.buffer)).toBe(createHash('sha256').update(bytes).digest('hex'));
  });

  it('names an address by the one regex', () => {
    expect(isAddress(contract)).toBe(true);
    expect(isAddress(contract.toLowerCase())).toBe(true);
    expect(isAddress(contract.slice(0, 41))).toBe(false);
    expect(isAddress('80f84221dcCC8d049f34b449DFC825B6940BD85f')).toBe(false);
    expect(ADDRESS_RE.test('0x' + 'g'.repeat(40))).toBe(false);
  });
});
