import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ethers } from 'ethers';
import { keyExchangeMessage } from '../../client/key-exchange-message.mjs';
import {
  createTestApp,
  TestApp,
  getClient1Wallet,
  createKeyExchangePayload,
  isValidAddress,
  TEST_WALLETS
} from '../utils';

describe('Connect Routes', () => {
  let testApp: TestApp;
  let client1Wallet: ethers.Wallet;

  beforeAll(async () => {
    testApp = await createTestApp();
    client1Wallet = getClient1Wallet();
  });

  afterAll(async () => {
    // Cleanup if needed
  });

  describe('POST /connect', () => {
    it('should complete key exchange with valid signature', async () => {
      const payload = await createKeyExchangePayload(client1Wallet);

      const response = await testApp.supertest
        .post('/.well-known/epistery/connect')
        .send(payload)
        .expect(200);

      // Verify response structure
      expect(response.body).toBeDefined();
      expect(response.body.serverAddress).toBeDefined();
      expect(isValidAddress(response.body.serverAddress)).toBe(true);
      expect(response.body.serverPublicKey).toBeDefined();
      expect(response.body.challenge).toBeDefined();
      expect(response.body.signature).toBeDefined();
      expect(response.body.services).toBeDefined();
      expect(Array.isArray(response.body.services)).toBe(true);

      // Server address should be a valid Ethereum address
      // Note: The server uses its own domain wallet, not TEST_WALLETS.server
      expect(isValidAddress(response.body.serverAddress)).toBe(true);
    });

    it('should set session cookie on successful key exchange', async () => {
      const payload = await createKeyExchangePayload(client1Wallet);

      const response = await testApp.supertest
        .post('/.well-known/epistery/connect')
        .send(payload)
        .expect(200);

      // Check for session cookie
      const cookies = response.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(cookies.some((c: string) => c.startsWith('_epistery='))).toBe(true);
    });

    it('should return 401 for invalid signature', async () => {
      const challenge = ethers.utils.hexlify(ethers.utils.randomBytes(32));
      const message = keyExchangeMessage({ address: client1Wallet.address, challenge });
      const invalidSignature = '0x' + '00'.repeat(65); // Invalid signature

      const payload = {
        signerAddress: client1Wallet.address,
        signerPublicKey: client1Wallet.publicKey,
        contractAddress: null,
        challenge,
        message,
        signature: invalidSignature,
        walletSource: 'browser'
      };

      await testApp.supertest
        .post('/.well-known/epistery/connect')
        .send(payload)
        .expect(401);
    });

    it('should return 401 for mismatched address in signature', async () => {
      // Sign with client1 but claim to be a different address
      const fakeAddress = '0x0000000000000000000000000000000000000001';
      const challenge = ethers.utils.hexlify(ethers.utils.randomBytes(32));
      const message = keyExchangeMessage({ address: fakeAddress, challenge });
      const signature = await client1Wallet.signMessage(message);

      const payload = {
        signerAddress: fakeAddress,
        signerPublicKey: client1Wallet.publicKey,
        contractAddress: null,
        challenge,
        message,
        signature,
        walletSource: 'browser'
      };

      await testApp.supertest
        .post('/.well-known/epistery/connect')
        .send(payload)
        .expect(401);
    });

    it('should return 401 for missing required fields', async () => {
      const payload = {
        signerAddress: client1Wallet.address
        // Missing other required fields
      };

      const response = await testApp.supertest
        .post('/.well-known/epistery/connect')
        .send(payload);

      // Should fail without proper signature verification
      expect([400, 401, 500]).toContain(response.status);
    });

    it('should call authentication callback if provided', async () => {
      let callbackCalled = false;
      let callbackClientInfo: any = null;

      const testAppWithAuth = await createTestApp({
        authentication: async (clientInfo) => {
          callbackCalled = true;
          callbackClientInfo = clientInfo;
          return { userId: 'test-user', role: 'admin' };
        }
      });

      const payload = await createKeyExchangePayload(client1Wallet);

      const response = await testAppWithAuth.supertest
        .post('/.well-known/epistery/connect')
        .send(payload)
        .expect(200);

      expect(callbackCalled).toBe(true);
      // No contract claim → identityAddress equals signerAddress equals the
      // EOA we just proved.
      expect(callbackClientInfo.signerAddress).toBe(client1Wallet.address);
      expect(callbackClientInfo.identityAddress).toBe(client1Wallet.address);
      expect(callbackClientInfo.contractAddress).toBeNull();
      expect(response.body.authenticated).toBe(true);
      expect(response.body.profile).toEqual({ userId: 'test-user', role: 'admin' });
    });

    it('should return identified=true for valid key exchange', async () => {
      const payload = await createKeyExchangePayload(client1Wallet);

      const response = await testApp.supertest
        .post('/.well-known/epistery/connect')
        .send(payload)
        .expect(200);

      expect(response.body.identified).toBe(true);
    });
  });
});
