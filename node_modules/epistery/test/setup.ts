import { ethers } from 'ethers';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';

/**
 * Global test setup
 * Runs once before all tests
 */
export default async function globalSetup() {
  console.log('\n=== Epistery Test Suite Setup ===\n');

  // 0. Load .test.env file FIRST before importing fixtures
  const testEnvPath = path.resolve(__dirname, '..', '.test.env');
  if (fs.existsSync(testEnvPath)) {
    dotenv.config({ path: testEnvPath });
    console.log(`Loaded test env: ${testEnvPath}`);
  } else {
    throw new Error(
      `.test.env file not found at ${testEnvPath}\n` +
      'Copy .test.env.example to .test.env and fill in the values.'
    );
  }

  // Now import fixtures after env is loaded
  const { TEST_WALLETS, TEST_PROVIDER } = await import('./fixtures/wallets');

  // 1. Override HOME to use test config directory
  const testConfigPath = path.resolve(__dirname, 'config');
  process.env.EPISTERY_HOME = testConfigPath;
  process.env.HOME = testConfigPath;
  process.env.USERPROFILE = testConfigPath; // Windows compatibility

  console.log(`Config directory: ${testConfigPath}`);

  // 2. Set required environment variables
  process.env.CHAIN_RPC_URL = TEST_PROVIDER.rpc;
  process.env.CHAIN_ID = String(TEST_PROVIDER.chainId);
  process.env.SERVER_DOMAIN = 'localhost';

  // 3. Generate test config files from environment variables.
  // Config reads HOME/.epistery (configDir = join(HOME, '.epistery')), so the
  // fixtures must live under .epistery — NOT directly under HOME. (They used to
  // be written one level too high, so Config never saw them and auto-seeded
  // defaults + random wallets.)
  const episteryDir = path.join(testConfigPath, '.epistery');
  const localhostDir = path.join(episteryDir, 'localhost');
  fs.mkdirSync(localhostDir, { recursive: true });

  // Write root config
  const rootConfig = `[profile]
name=Test Profile
email=test@epistery.test

[default.provider]
chainId=${TEST_PROVIDER.chainId}
name=${TEST_PROVIDER.name}
rpc=${TEST_PROVIDER.rpc}
nativeCurrencyName=${TEST_PROVIDER.nativeCurrencyName}
nativeCurrencySymbol=${TEST_PROVIDER.nativeCurrencySymbol}
nativeCurrencyDecimals=${TEST_PROVIDER.nativeCurrencyDecimals}

[cli]
default_domain=localhost
`;
  fs.writeFileSync(path.join(episteryDir, 'config.ini'), rootConfig);

  // Write localhost domain config
  const localhostConfig = `domain=localhost

[wallet]
address=${TEST_WALLETS.server.address}
mnemonic=${TEST_WALLETS.server.mnemonic}
publicKey=${TEST_WALLETS.server.publicKey}
privateKey=${TEST_WALLETS.server.privateKey}

[provider]
name=${TEST_PROVIDER.name}
chainId=${TEST_PROVIDER.chainId}
rpc=${TEST_PROVIDER.rpc}
nativeCurrencySymbol=${TEST_PROVIDER.nativeCurrencySymbol}
nativeCurrencyName=${TEST_PROVIDER.nativeCurrencyName}
nativeCurrencyDecimals=${TEST_PROVIDER.nativeCurrencyDecimals}
`;
  fs.writeFileSync(path.join(localhostDir, 'config.ini'), localhostConfig);

  console.log('Test config files: Generated from .test.env');

  // 4. Verify testnet connectivity
  const provider = new ethers.providers.JsonRpcProvider(TEST_PROVIDER.rpc);
  try {
    const network = await provider.getNetwork();
    console.log(`Connected to: ${network.name} (chainId: ${network.chainId})`);

    if (network.chainId !== TEST_PROVIDER.chainId) {
      throw new Error(`Chain ID mismatch: expected ${TEST_PROVIDER.chainId}, got ${network.chainId}`);
    }
  } catch (error) {
    console.error('Failed to connect to testnet:', error);
    throw new Error('Testnet connectivity required for tests. Ensure Polygon Amoy RPC is accessible.');
  }

  // 5. Check server wallet balance
  const serverBalance = await provider.getBalance(TEST_WALLETS.server.address);
  const balanceInPol = ethers.utils.formatEther(serverBalance);
  console.log(`Server wallet balance: ${balanceInPol} POL`);

  if (serverBalance.lt(ethers.utils.parseEther('0.01'))) {
    console.warn('\nWARNING: Server wallet has low balance!');
    console.warn(`Fund address ${TEST_WALLETS.server.address} with testnet POL`);
    console.warn('Get testnet POL from: https://faucet.polygon.technology/\n');
  }

  console.log('\n=== Setup Complete ===\n');
}
