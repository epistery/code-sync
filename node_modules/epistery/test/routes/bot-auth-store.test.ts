import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ethers } from 'ethers';
import request from 'supertest';
import {
  createTestApp,
  createBotAuthHeader,
  getClient1Wallet,
  TestApp,
} from '../utils';
import { setBotNonceStore, createInProcessNonceStore } from '../../index.mjs';

/**
 * The replay gate is a pluggable, atomic store (setBotNonceStore). On a single
 * instance the in-process default suffices; a multi-instance host (the relay
 * behind a load balancer) injects a shared store so a nonce claimed on one
 * instance is refused on the others. These prove the injected store IS the
 * authority for replay — the reason the in-process default alone is not enough
 * for the relay.
 */
describe('Bot authentication — pluggable shared nonce store', () => {
  let testApp: TestApp;
  let wallet: ethers.Wallet;

  beforeAll(async () => {
    testApp = await createTestApp();
    wallet = getClient1Wallet();
    testApp.app.post('/probe', (req: any, res) => {
      res.json({ authType: req.episteryClient?.authType ?? null });
    });
  });

  afterAll(() => {
    setBotNonceStore(createInProcessNonceStore()); // restore default for other files
  });

  const post = () => request(testApp.app).post('/probe').set('Host', 'localhost');

  it('routes replay through the injected store, and refuses what it rejects (cross-instance)', async () => {
    const claimed = new Set<string>();
    const seenNonces: string[] = [];
    // Stands in for a shared store two instances write to: the second sighting
    // of a nonce (as if on a sibling instance) is already claimed → false.
    setBotNonceStore({
      async claim(nonce: string) {
        seenNonces.push(nonce);
        if (claimed.has(nonce)) return false;
        claimed.add(nonce);
        return true;
      },
    });

    const auth = await createBotAuthHeader(wallet, {
      method: 'POST',
      uri: '/probe',
      aud: 'localhost',
    });

    // First request: the store admits the nonce.
    const first = await post().set('Authorization', auth).expect(200);
    expect(first.body.authType).toBe('bot');

    // Same header again (as if it landed on a sibling instance sharing the
    // store): the store reports the nonce already claimed, so it is refused.
    const replay = await post().set('Authorization', auth).expect(200);
    expect(replay.body.authType).toBeNull();

    // The store — not an in-process Map — decided both outcomes.
    expect(seenNonces.length).toBe(2);
    expect(seenNonces[0]).toBe(seenNonces[1]);
  });

  it('fails closed when the store throws (e.g. Mongo unreachable)', async () => {
    setBotNonceStore({
      async claim() {
        throw new Error('nonce store unreachable');
      },
    });

    const auth = await createBotAuthHeader(wallet, {
      method: 'POST',
      uri: '/probe',
      aud: 'localhost',
    });

    const res = await post().set('Authorization', auth).expect(200);
    expect(res.body.authType).toBeNull(); // rejected, not admitted
  });

  it('the in-process default still rejects a same-process replay', async () => {
    setBotNonceStore(createInProcessNonceStore());

    const auth = await createBotAuthHeader(wallet, {
      method: 'POST',
      uri: '/probe',
      aud: 'localhost',
    });

    const first = await post().set('Authorization', auth).expect(200);
    expect(first.body.authType).toBe('bot');
    const replay = await post().set('Authorization', auth).expect(200);
    expect(replay.body.authType).toBeNull();
  });
});
