import { ethers } from 'ethers';
import { keyExchangeMessage } from '../client/key-exchange-message.mjs';
import { createHash, randomBytes } from 'crypto';
import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';

// Load .test.env BEFORE importing fixtures that depend on env vars
const testEnvPath = path.resolve(__dirname, '..', '.test.env');
if (fs.existsSync(testEnvPath)) {
  dotenv.config({ path: testEnvPath });
}

import { TEST_WALLETS, TEST_PROVIDER, TEST_CONTRACT_ADDRESS, WalletInfo } from './fixtures/wallets';

// Re-export fixtures for convenience
export { TEST_WALLETS, TEST_PROVIDER, TEST_CONTRACT_ADDRESS };

/**
 * Test application wrapper with utility methods
 */
export interface TestApp {
  app: Express;
  epistery: any;
  supertest: ReturnType<typeof request>;
}

/**
 * Creates an Express app with Epistery attached for testing
 */
export async function createTestApp(options?: {
  authentication?: (clientInfo: any) => Promise<any>;
  domain?: string;
  rootPath?: string;
}): Promise<TestApp> {
  // Set up environment before importing Epistery
  const testConfigPath = path.resolve(__dirname, 'config');
  process.env.EPISTERY_HOME = testConfigPath;
  process.env.HOME = testConfigPath;
  process.env.CHAIN_RPC_URL = TEST_PROVIDER.rpc;
  process.env.CHAIN_ID = String(TEST_PROVIDER.chainId);
  process.env.SERVER_DOMAIN = 'localhost';

  // Dynamic import to ensure environment is set first
  const { Epistery, captureRawBody } = await import('../index.mjs');

  const app = express();
  // Bot signatures commit to a digest of the raw body, and express.json()
  // consumes the stream. captureRawBody keeps the bytes so the verifier can
  // reproduce what was signed. Hosts accepting bot-signed bodies must do this.
  app.use(express.json({ verify: captureRawBody }));
  app.use(cookieParser());

  // Initialize Epistery
  const epistery = await Epistery.connect({
    authentication: options?.authentication
  });

  await epistery.setDomain(options?.domain || 'localhost');
  await epistery.attach(app, options?.rootPath);

  return {
    app,
    epistery,
    supertest: request(app)
  };
}

/**
 * Get an ethers Wallet instance for a test wallet
 */
export function getWallet(walletKey: keyof typeof TEST_WALLETS): ethers.Wallet {
  const walletInfo = TEST_WALLETS[walletKey];
  const provider = new ethers.providers.JsonRpcProvider(TEST_PROVIDER.rpc);
  return ethers.Wallet.fromMnemonic(walletInfo.mnemonic).connect(provider);
}

/**
 * Get server wallet
 */
export function getServerWallet(): ethers.Wallet {
  return getWallet('server');
}

/**
 * Get client1 wallet
 */
export function getClient1Wallet(): ethers.Wallet {
  return getWallet('client1');
}

/**
 * Get client2 wallet
 */
export function getClient2Wallet(): ethers.Wallet {
  return getWallet('client2');
}

/**
 * Create a ClientWalletInfo object from a wallet
 */
export function createClientWalletInfo(wallet: ethers.Wallet): {
  address: string;
  publicKey: string;
  mnemonic: string;
  privateKey: string;
} {
  return {
    address: wallet.address,
    publicKey: wallet.publicKey,
    mnemonic: wallet.mnemonic?.phrase || '',
    privateKey: wallet.privateKey
  };
}

/**
 * Create key exchange request payload — signer-only (no contract claim).
 * Tests that exercise the contract verification path build their own
 * payload with `contractAddress` set.
 */
export async function createKeyExchangePayload(wallet: ethers.Wallet): Promise<{
  signerAddress: string;
  signerPublicKey: string;
  contractAddress: string | null;
  challenge: string;
  message: string;
  signature: string;
  walletSource: string;
}> {
  const challenge = ethers.utils.hexlify(ethers.utils.randomBytes(32));
  const message = keyExchangeMessage({ address: wallet.address, challenge });
  const signature = await wallet.signMessage(message);

  return {
    signerAddress: wallet.address,
    signerPublicKey: wallet.publicKey,
    contractAddress: null,
    challenge,
    message,
    signature,
    walletSource: 'browser'
  };
}

/**
 * Perform key exchange and return session cookie
 */
export async function performKeyExchange(
  supertest: ReturnType<typeof request>,
  wallet: ethers.Wallet
): Promise<{ cookie: string; response: any }> {
  const payload = await createKeyExchangePayload(wallet);

  const response = await supertest
    .post('/.well-known/epistery/connect')
    .send(payload)
    .expect(200);

  // Extract session cookie
  const cookies = response.headers['set-cookie'];
  const sessionCookie = cookies?.find((c: string) => c.startsWith('_epistery='));

  return {
    cookie: sessionCookie || '',
    response: response.body
  };
}

/**
 * Create a Bot authentication header bound to a specific request.
 *
 * Mirrors CliWallet.createBotAuthHeader; both build their bytes with
 * client/bot-auth-message.mjs so a drift between signer and verifier shows up
 * as a test failure rather than as an accepted signature.
 *
 * Overrides let a test mint a deliberately wrong envelope (stale ts, foreign
 * audience, mismatched body hash) without hand-rolling the wire shape.
 */
export async function createBotAuthHeader(
  wallet: ethers.Wallet,
  req: {
    method?: string;
    uri?: string;
    aud?: string;
    body?: string | Buffer | null;
  } = {},
  overrides: Partial<{ ts: number; nonce: string; bodyHash: string; aud: string; uri: string; method: string }> = {}
): Promise<string> {
  const { botAuthMessage, audienceFor, EMPTY_BODY_SHA256 } = await import(
    '../client/bot-auth-message.mjs' as string
  );

  const method = (overrides.method ?? req.method ?? 'POST').toUpperCase();
  const uri = overrides.uri ?? req.uri ?? '/';
  const aud = audienceFor(overrides.aud ?? req.aud ?? 'localhost');
  const body = req.body;
  const bodyHash =
    overrides.bodyHash ??
    (body === undefined || body === null || body.length === 0
      ? EMPTY_BODY_SHA256
      : createHash('sha256')
          .update(Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8'))
          .digest('hex'));
  const ts = overrides.ts ?? Date.now();
  const nonce = overrides.nonce ?? randomBytes(16).toString('hex');

  const signature = await wallet.signMessage(
    botAuthMessage({ method, uri, aud, bodyHashHex: bodyHash, ts, nonce })
  );

  const payload = { v: '1', address: wallet.address, signature, method, uri, aud, bodyHash, ts, nonce };
  return 'Bot ' + Buffer.from(JSON.stringify(payload)).toString('base64');
}

/**
 * Create a session cookie for authenticated requests.
 *
 * Matches the three-fact session shape the auth middleware reads
 * (index.mjs: s.signerAddress / s.contractAddress / s.publicKey). The old field
 * name `rivetAddress` predated the identity-vocabulary migration and was silently
 * ignored by the middleware (no signerAddress → unauthenticated).
 */
export function createSessionCookie(signerAddress: string, publicKey?: string, contractAddress?: string | null): string {
  const sessionData = {
    signerAddress,
    contractAddress: contractAddress || null,
    publicKey: publicKey || '',
    authenticated: true,
    timestamp: new Date().toISOString()
  };
  return Buffer.from(JSON.stringify(sessionData)).toString('base64');
}

/**
 * Generate a unique test identifier
 */
export function uniqueId(): string {
  return `test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Generate a unique file name for testing
 */
export function uniqueFileName(): string {
  return `test-file-${uniqueId()}`;
}

/**
 * Generate a unique list name for testing
 */
export function uniqueListName(): string {
  return `test-list-${uniqueId()}`;
}

/**
 * Generate unique test data
 */
export function uniqueTestData(): object {
  return {
    testId: uniqueId(),
    timestamp: Date.now(),
    message: `Test data created at ${new Date().toISOString()}`
  };
}

/**
 * Wait for a transaction to be confirmed
 */
export async function waitForTransaction(
  txHash: string,
  timeout: number = 60000
): Promise<ethers.providers.TransactionReceipt> {
  const provider = new ethers.providers.JsonRpcProvider(TEST_PROVIDER.rpc);
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    const receipt = await provider.getTransactionReceipt(txHash);
    if (receipt) {
      return receipt;
    }
    await sleep(2000);
  }

  throw new Error(`Transaction ${txHash} not confirmed within ${timeout}ms`);
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Check if a string is a valid Ethereum address
 */
export function isValidAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/**
 * Check if a string is a valid transaction hash
 */
export function isValidTxHash(hash: string): boolean {
  return /^0x[a-fA-F0-9]{64}$/.test(hash);
}

/**
 * Get provider instance
 */
export function getProvider(): ethers.providers.JsonRpcProvider {
  return new ethers.providers.JsonRpcProvider(TEST_PROVIDER.rpc);
}

/**
 * Check wallet balance
 */
export async function getBalance(address: string): Promise<ethers.BigNumber> {
  const provider = getProvider();
  return provider.getBalance(address);
}

/**
 * Skip test if contract is not deployed
 */
export function skipIfNoContract(): void {
  if (!TEST_CONTRACT_ADDRESS) {
    throw new Error('Contract not deployed - skipping test');
  }
}

/**
 * Retry a function with exponential backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  initialDelay: number = 1000
): Promise<T> {
  let lastError: Error | undefined;

  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      const delay = initialDelay * Math.pow(2, i);
      await sleep(delay);
    }
  }

  throw lastError;
}
