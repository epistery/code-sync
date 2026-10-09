import { describe, it, expect, beforeAll } from 'vitest';
import { ethers } from 'ethers';
import request from 'supertest';
import {
  createTestApp,
  createBotAuthHeader,
  getClient1Wallet,
  TestApp,
} from '../utils';

/**
 * Bot auth is a *message* signature, not a bearer token.
 *
 * Each test below fails on the pre-binding implementation, where the signed
 * bytes were a fixed banner plus a timestamp and the server checked only that
 * the signature recovered the claimed address. Under that scheme a single
 * captured header authorised every endpoint, on every host, with any body,
 * indefinitely — these cases are the specification of what that cost.
 */
describe('Bot authentication — the signature covers the request', () => {
  let testApp: TestApp;
  let wallet: ethers.Wallet;

  beforeAll(async () => {
    testApp = await createTestApp();
    wallet = getClient1Wallet();

    // A probe that reports whatever identity epistery proved.
    testApp.app.post('/probe', (req: any, res) => {
      res.json({
        authType: req.episteryClient?.authType ?? null,
        signerAddress: req.episteryClient?.signerAddress ?? null,
        identityAddress: req.episteryClient?.identityAddress ?? null,
      });
    });
    testApp.app.post('/other', (req: any, res) => {
      res.json({ authType: req.episteryClient?.authType ?? null });
    });
  });

  const post = (uri: string) => request(testApp.app).post(uri).set('Host', 'localhost');

  it('accepts a signature bound to this exact request', async () => {
    const body = { hello: 'world' };
    const payload = JSON.stringify(body);
    const auth = await createBotAuthHeader(wallet, {
      method: 'POST',
      uri: '/probe',
      aud: 'localhost',
      body: payload,
    });

    const res = await post('/probe')
      .set('Authorization', auth)
      .set('Content-Type', 'application/json')
      .send(payload)
      .expect(200);

    expect(res.body.authType).toBe('bot');
    expect(res.body.signerAddress.toLowerCase()).toBe(wallet.address.toLowerCase());
    expect(res.body.identityAddress.toLowerCase()).toBe(wallet.address.toLowerCase());
  });

  it('accepts a bodyless request that commits to having no body', async () => {
    const auth = await createBotAuthHeader(wallet, { method: 'POST', uri: '/probe', aud: 'localhost' });
    const res = await post('/probe').set('Authorization', auth).expect(200);
    expect(res.body.authType).toBe('bot');
  });

  it('rejects the same header replayed a second time', async () => {
    const payload = JSON.stringify({ n: 1 });
    const auth = await createBotAuthHeader(wallet, {
      method: 'POST', uri: '/probe', aud: 'localhost', body: payload,
    });

    const first = await post('/probe')
      .set('Authorization', auth).set('Content-Type', 'application/json')
      .send(payload).expect(200);
    expect(first.body.authType).toBe('bot');

    const second = await post('/probe')
      .set('Authorization', auth).set('Content-Type', 'application/json')
      .send(payload).expect(200);
    expect(second.body.authType).toBeNull();
  });

  it('rejects a header lifted onto a different endpoint', async () => {
    const auth = await createBotAuthHeader(wallet, { method: 'POST', uri: '/probe', aud: 'localhost' });
    const res = await post('/other').set('Authorization', auth).expect(200);
    expect(res.body.authType).toBeNull();
  });

  it('rejects a header minted for a different host', async () => {
    const auth = await createBotAuthHeader(wallet, {
      method: 'POST', uri: '/probe', aud: 'evil.example',
    });
    const res = await post('/probe').set('Authorization', auth).expect(200);
    expect(res.body.authType).toBeNull();
  });

  it('rejects a body swapped after signing', async () => {
    const signed = JSON.stringify({ amount: 1 });
    const sent = JSON.stringify({ amount: 1000000 });
    const auth = await createBotAuthHeader(wallet, {
      method: 'POST', uri: '/probe', aud: 'localhost', body: signed,
    });

    const res = await post('/probe')
      .set('Authorization', auth).set('Content-Type', 'application/json')
      .send(sent).expect(200);
    expect(res.body.authType).toBeNull();
  });

  it('rejects a stale envelope', async () => {
    const auth = await createBotAuthHeader(
      wallet,
      { method: 'POST', uri: '/probe', aud: 'localhost' },
      { ts: Date.now() - 10 * 60 * 1000 }
    );
    const res = await post('/probe').set('Authorization', auth).expect(200);
    expect(res.body.authType).toBeNull();
  });

  it('rejects a future-dated envelope beyond clock skew', async () => {
    const auth = await createBotAuthHeader(
      wallet,
      { method: 'POST', uri: '/probe', aud: 'localhost' },
      { ts: Date.now() + 10 * 60 * 1000 }
    );
    const res = await post('/probe').set('Authorization', auth).expect(200);
    expect(res.body.authType).toBeNull();
  });

  it('rejects an envelope whose bodyHash does not match its own signed bytes', async () => {
    // Signed with one digest, transported claiming another: the message the
    // verifier rebuilds from the envelope no longer recovers the address.
    const payload = JSON.stringify({ ok: true });
    const auth = await createBotAuthHeader(
      wallet,
      { method: 'POST', uri: '/probe', aud: 'localhost', body: payload },
      { bodyHash: 'f'.repeat(64) }
    );
    const res = await post('/probe')
      .set('Authorization', auth).set('Content-Type', 'application/json')
      .send(payload).expect(200);
    expect(res.body.authType).toBeNull();
  });

  it('does not judge the relay storage-write credential — the other `Bot` wire', async () => {
    // The relay's storage credential shares the scheme name: `Bot <base64 JSON>`
    // with a signed `message` and no envelope version. It is the relay's to
    // verify, not a malformed bot-auth envelope: no identity here, no warning.
    const message = `epistery-storage-write\nmethod: PUT\ncontract: 0x0\n`;
    const signature = await wallet.signMessage(message);
    const credential =
      'Bot ' +
      Buffer.from(JSON.stringify({ address: wallet.address, signature, message, identity: wallet.address })).toString('base64');
    const warnings: string[] = [];
    const warn = console.warn;
    console.warn = (...a: any[]) => { warnings.push(a.join(' ')); };
    try {
      const res = await post('/probe').set('Authorization', credential).expect(200);
      expect(res.body.authType).toBeNull();
    } finally {
      console.warn = warn;
    }
    expect(warnings.filter((w) => /Bot auth rejected/.test(w))).toEqual([]);
  });

  it('rejects the legacy unbound header format', async () => {
    // The pre-binding wire: a banner string, signed, with no request context.
    const message = `Rhonda Bot Authentication - ${new Date().toISOString()}`;
    const signature = await wallet.signMessage(message);
    const legacy =
      'Bot ' +
      Buffer.from(JSON.stringify({ address: wallet.address, signature, message })).toString('base64');

    const res = await post('/probe').set('Authorization', legacy).expect(200);
    expect(res.body.authType).toBeNull();
  });

  it('rejects a signature from a different key', async () => {
    const other = ethers.Wallet.createRandom();
    const auth = await createBotAuthHeader(other, { method: 'POST', uri: '/probe', aud: 'localhost' });
    // Claim client1's address over a signature made by someone else.
    const decoded = JSON.parse(Buffer.from(auth.substring(4), 'base64').toString('utf8'));
    decoded.address = wallet.address;
    const forged = 'Bot ' + Buffer.from(JSON.stringify(decoded)).toString('base64');

    const res = await post('/probe').set('Authorization', forged).expect(200);
    expect(res.body.authType).toBeNull();
  });
});
