/**
 * Test Wallet Configuration
 *
 * Wallet credentials are loaded from .test.env file.
 * See .test.env.example for the required format.
 *
 * IMPORTANT: Fund the server wallet with ~0.5 POL before running tests.
 * Faucet: https://faucet.polygon.technology/
 */

export interface WalletInfo {
  address: string;
  mnemonic: string;
  publicKey: string;
  privateKey: string;
}

function getEnvOrThrow(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}. Ensure .test.env is loaded.`);
  }
  return value;
}

function getEnvOrDefault(key: string, defaultValue: string): string {
  return process.env[key] || defaultValue;
}

export const TEST_WALLETS: {
  server: WalletInfo;
  client1: WalletInfo;
  client2: WalletInfo;
} = {
  // Server wallet - Contract sponsor, has admin privileges
  server: {
    get address() { return getEnvOrThrow('TEST_SERVER_ADDRESS'); },
    get mnemonic() { return getEnvOrThrow('TEST_SERVER_MNEMONIC'); },
    get publicKey() { return getEnvOrThrow('TEST_SERVER_PUBLIC_KEY'); },
    get privateKey() { return getEnvOrThrow('TEST_SERVER_PRIVATE_KEY'); }
  },

  // Client wallet 1 - for standard client operations and admin role testing
  client1: {
    get address() { return getEnvOrThrow('TEST_CLIENT1_ADDRESS'); },
    get mnemonic() { return getEnvOrThrow('TEST_CLIENT1_MNEMONIC'); },
    get publicKey() { return getEnvOrThrow('TEST_CLIENT1_PUBLIC_KEY'); },
    get privateKey() { return getEnvOrThrow('TEST_CLIENT1_PRIVATE_KEY'); }
  },

  // Client wallet 2 - for multi-wallet scenarios (moderator role testing)
  client2: {
    get address() { return getEnvOrThrow('TEST_CLIENT2_ADDRESS'); },
    get mnemonic() { return getEnvOrThrow('TEST_CLIENT2_MNEMONIC'); },
    get publicKey() { return getEnvOrThrow('TEST_CLIENT2_PUBLIC_KEY'); },
    get privateKey() { return getEnvOrThrow('TEST_CLIENT2_PRIVATE_KEY'); }
  }
};

// Address of an existing on-chain contract for binding tests (e.g. an
// IdentityContract that prepare-add-rivet targets). Loaded from .test.env.
// Originally the agent contract; with that removed, any deployed contract on
// the test chain works for the binding flow.
export const TEST_CONTRACT_ADDRESS = process.env.TEST_CONTRACT_ADDRESS || '';

export const TEST_PROVIDER = {
  get name() { return getEnvOrDefault('TEST_PROVIDER_NAME', 'Polygon Amoy Testnet'); },
  get chainId() { return parseInt(getEnvOrDefault('TEST_PROVIDER_CHAIN_ID', '80002'), 10); },
  get rpc() { return getEnvOrDefault('TEST_PROVIDER_RPC', 'https://rpc-amoy.polygon.technology'); },
  get nativeCurrencySymbol() { return getEnvOrDefault('TEST_PROVIDER_CURRENCY_SYMBOL', 'POL'); },
  get nativeCurrencyName() { return getEnvOrDefault('TEST_PROVIDER_CURRENCY_NAME', 'POL'); },
  get nativeCurrencyDecimals() { return parseInt(getEnvOrDefault('TEST_PROVIDER_CURRENCY_DECIMALS', '18'), 10); }
};
