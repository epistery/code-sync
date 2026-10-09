import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
import { createHash } from 'crypto';
import { botAuthorization, parseBotEnvelope, messageForEnvelope, EMPTY_BODY_SHA256 } from '../client/bot-auth-message.mjs';

const decode = (header: string) => JSON.parse(Buffer.from(header.slice(4), 'base64').toString('utf8'));

describe('botAuthorization — the one header builder, for any signer', () => {
  const w = ethers.Wallet.createRandom();
  const signer = { sign: (m: string) => w.signMessage(m), address: w.address };

  it('builds the versioned envelope the server parses, bound to method, uri, audience and body', async () => {
    const body = JSON.stringify({ a: 1 });
    const h = await botAuthorization({ ...signer, method: 'post', url: 'https://Example.com:8443/mcp?x=1', body });
    expect(h.startsWith('Bot ')).toBe(true);
    const env = parseBotEnvelope(decode(h))!;
    expect(env).toBeTruthy();
    expect(env.method).toBe('POST');
    expect(env.uri).toBe('/mcp?x=1');
    expect(env.aud).toBe('example.com');
    expect(env.bodyHash).toBe(createHash('sha256').update(body).digest('hex'));
    expect(ethers.utils.verifyMessage(messageForEnvelope(env), env.signature)).toBe(w.address);
    expect(env.address).toBe(w.address);
  });

  it('commits to an empty body, and takes uri + aud without a url', async () => {
    const h = await botAuthorization({ ...signer, method: 'GET', uri: '/x', aud: 'host.test:443' });
    const env = parseBotEnvelope(decode(h))!;
    expect(env.bodyHash).toBe(EMPTY_BODY_SHA256);
    expect(env.aud).toBe('host.test');
  });

  it('refuses a request it cannot name', async () => {
    await expect(botAuthorization({ ...signer })).rejects.toThrow(/name the request/);
    await expect(botAuthorization({ address: w.address, url: 'https://x/y' } as any)).rejects.toThrow(/sign/);
  });

  it('never repeats a nonce', async () => {
    const a = parseBotEnvelope(decode(await botAuthorization({ ...signer, url: 'https://x/y' })))!;
    const b = parseBotEnvelope(decode(await botAuthorization({ ...signer, url: 'https://x/y' })))!;
    expect(a.nonce).not.toBe(b.nonce);
  });
});
