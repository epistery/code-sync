export interface NativeCurrency {
  name: string;
  symbol: string;
  decimals: number;
}

export interface ProviderConfig {
  chainId: number | undefined;
  name: string;
  rpc: string;
  nativeCurrencySymbol?: string;
  nativeCurrencyName?: string;
  nativeCurrencyDecimals?: number;
}

export interface WalletConfig {
  address: string;
  mnemonic: string;
  publicKey: string;
  privateKey: string;
}

export interface DomainConfig {
  domain: string;
  provider?: ProviderConfig;
  wallet?: WalletConfig;
}

export interface ProfileConfig {
    email?: string;
}

export interface IPFSConfig {
  url: string;
  gateway?: string;
}

export interface RootDefaults {
  provider: ProviderConfig;
}

export interface RootConfig {
  profile?: ProfileConfig;
  ipfs?: IPFSConfig;
  default?: RootDefaults;
}

export interface ClientWalletInfo {
  address: string;
  publicKey: string;

  // Resolved from whitelist entries on the domain agent contract
  // (first non-empty `name` field across the address's memberships)
  name?: string;

  // Used by legacy (browser) data-wallets -- left in for backward compatibility
  mnemonic?: string;
  privateKey?: string;

  // Used by RivetWallets / FidoWallets
  walletType?: 'web3' | 'rivet' | 'fido';

  // (For client-side signed operations) This contains the complete signed transaction
  signedTransaction?: string;
}

// The wire shape for POST /connect.
//
// Two facts the client can state, one of which carries a proof:
//   - signerAddress: the rivet (must equal the address recovered from
//     `signature` over `message`).
//   - contractAddress: an IdentityContract this signer CLAIMS to speak for.
//     Server verifies the claim on-chain via isAuthorized(contract, signer).
//
// There is no `clientAddress` here, and no `identityAddress`: the client
// never tells the server which role its address plays; the server derives
// identityAddress = contractAddress || signerAddress.
export interface KeyExchangeRequest {
  signerAddress: string;
  signerPublicKey: string;
  contractAddress?: string | null;
  challenge: string;
  message: string;
  signature: string;
  walletSource?: string;
}

export interface KeyExchangeResponse {
  serverAddress: string;
  serverPublicKey: string;
  services: string[];
  challenge: string;
  signature: string;
  identified: boolean;
  authenticated: boolean;
  profile?: object | null;
  /** The origin certificate the host issued for this rivet, when it could. */
  certificate?: object | null;
}
