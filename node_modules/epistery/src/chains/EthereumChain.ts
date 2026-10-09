import { Chain } from './Chain';
import { registerChain } from './registry';

/**
 * Ethereum mainnet (chainId 1).
 *
 * Standard EIP-1559 behavior — ethers' getFeeData is accurate here.
 * No floors, no special multipliers. The base class default works as-is;
 * this subclass exists for the registry and for future overrides.
 */
export class EthereumChain extends Chain {
  static chainId = 1;
  static defaults = {
    name: 'Ethereum Mainnet',
    aliases: ['ethereum', 'eth', 'mainnet'],
    rpc: 'https://ethereum-rpc.publicnode.com',
    nativeCurrencyName: 'Ether',
    nativeCurrencySymbol: 'ETH',
    nativeCurrencyDecimals: 18,
  };
}

/**
 * Sepolia testnet (chainId 11155111). Same behavior as Ethereum mainnet.
 */
export class SepoliaChain extends Chain {
  static chainId = 11155111;
  static defaults = {
    name: 'Sepolia Testnet',
    aliases: ['sepolia'],
    rpc: 'https://ethereum-sepolia-rpc.publicnode.com',
    nativeCurrencyName: 'Ether',
    nativeCurrencySymbol: 'ETH',
    nativeCurrencyDecimals: 18,
  };
}

registerChain(EthereumChain.chainId, EthereumChain);
registerChain(SepoliaChain.chainId, SepoliaChain);