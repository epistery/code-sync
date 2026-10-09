import { ethers } from 'ethers';
import { ProviderConfig } from '../utils/types';

/**
 * Per-chain fee data, returned in the shape ethers v5 expects on a transaction.
 * EIP-1559 chains return maxFeePerGas/maxPriorityFeePerGas.
 * Legacy chains return gasPrice.
 */
export interface ChainFeeData {
  maxFeePerGas?: ethers.BigNumber;
  maxPriorityFeePerGas?: ethers.BigNumber;
  gasPrice?: ethers.BigNumber;
}

/**
 * Optional per-chain knobs that root config can override without editing code.
 * Each subclass reads only what it cares about.
 */
export interface ChainPolicy {
  // EIP-1559 floors (in gwei)
  minPriorityFeeGwei?: number;
  maxFeeMultiplier?: number;        // applied to max(networkMax, minPriority * 2)
  // EIP-1559 ceiling (in gwei) — refuse to send if the chain reports a
  // base fee above this. Bumping the cap is a manual config change so a
  // legitimate market spike can't silently drain a wallet.
  maxFeePerGasGwei?: number;
  // Legacy gas
  minGasPriceGwei?: number;
  maxGasPriceGwei?: number;         // legacy-chain analogue of maxFeePerGasGwei
  // Gas limit estimation safety
  gasLimitMultiplier?: number;      // applied to estimateGas result
}

/**
 * Extended provider config that may carry per-chain policy + a private RPC URL.
 * The plain `ProviderConfig` from utils/types stays the wire/storage shape;
 * `ChainConfig` is what the Chain object actually holds in memory.
 */
export interface ChainConfig extends ProviderConfig {
  publicRpc?: string;
  privateRpc?: string;
  policy?: ChainPolicy;
  /**
   * Short names a user may type instead of the chainId — `epistery
   * initialize --chain polygon`. Lowercase, no spaces. Must be unique across
   * registered chains; the first exact alias match wins.
   */
  aliases?: string[];
}

/**
 * Base class for an EVM chain. Subclasses override only the policy hooks
 * that are actually different from the EIP-1559 default.
 *
 * The Chain object owns:
 *   - the JsonRpcProvider (with explicit network info, fixing "could not detect network")
 *   - per-chain fee policy (getFeeData)
 *   - the contract Proxy that injects fee data into write calls
 *   - gas-limit estimation with a per-chain safety multiplier
 *
 * The Chain object does NOT own:
 *   - wallets / private keys
 *   - contract ABIs
 *   - domain config storage
 */
/**
 * The ONE rule for which endpoint a server sends through: the credentialed
 * `privateRpc` when one is configured, else `rpc`. `publicRpcOf` is the one
 * safe to hand to a browser or print on a status page: `publicRpc`, else
 * `rpc`. Every reader of a provider block (the Chain itself, the config
 * flattener, the relay) applies these; none restates them.
 */
export function serverRpcOf(config: ChainConfig): string {
  return config.privateRpc || config.rpc;
}
export function publicRpcOf(config: ChainConfig): string | undefined {
  return config.publicRpc || config.rpc;
}

export class Chain {
  /**
   * Subclasses override `defaults` to carry the canonical network details.
   * `chainFor({chainId: 137})` merges caller config on top of these defaults
   * so only the chainId is required — name, public RPC, currency etc. are
   * all built in.
   */
  static defaults: Partial<ChainConfig> = {};

  readonly chainId: number;
  readonly name: string;
  readonly rpc: string;                       // private/server-side RPC (with API key if any)
  readonly publicRpc: string | undefined;     // public RPC (safe to expose to browsers)
  readonly currency: { name: string; symbol: string; decimals: number };
  readonly policy: ChainPolicy;

  private _provider: ethers.providers.JsonRpcProvider | null = null;

  constructor(config: ChainConfig) {
    if (config.chainId == null) {
      throw new Error(`Chain config missing chainId: ${JSON.stringify(config)}`);
    }
    this.chainId = Number(config.chainId);
    this.name = config.name || '';
    this.rpc = serverRpcOf(config);
    this.publicRpc = publicRpcOf(config);
    this.currency = {
      name: config.nativeCurrencyName || '',
      symbol: config.nativeCurrencySymbol || '',
      decimals: config.nativeCurrencyDecimals || 18,
    };
    this.policy = config.policy || {};
  }

  /**
   * Lazily-built provider with explicit network info.
   *
   * Passing `{ name, chainId }` to the constructor avoids ethers' "could not
   * detect network" error when the RPC is briefly unreachable at startup, but
   * it does NOT stop the per-read probe: ethers v5 runs
   * getNetwork() -> detectNetwork() before EVERY read (eth_call, getBalance,
   * etc.), and detectNetwork re-sends eth_chainId each time (its memo only
   * survives a single event-loop tick, so sequentially-awaited reads each fire
   * their own). That doubled reads into "eth_chainId + <read>" pairs.
   *
   * Overriding detectNetwork to return the known static network collapses each
   * pair into one RPC call — roughly halving read volume on hot paths. This is
   * pure liveness plumbing: it's independent of which RPC endpoint is chosen,
   * so it stays correct behind an owned node or a fallback provider.
   */
  get provider(): ethers.providers.JsonRpcProvider {
    if (!this._provider) {
      const network: ethers.providers.Network = {
        name: this.name,
        chainId: this.chainId,
      };
      this._provider = new ethers.providers.JsonRpcProvider(this.rpc, network);
      this._provider.detectNetwork = async () => network;
    }
    return this._provider;
  }

  /** EIP-1559 by default. Subclasses override for legacy gasPrice chains. */
  supportsEIP1559(): boolean {
    return true;
  }

  /**
   * Default fee policy: pass through whatever the network reports via
   * eth_feeHistory / eth_gasPrice. Subclasses override to apply per-chain
   * floors (Polygon's 25 gwei priority floor, JOC's gasPrice floor, etc.).
   */
  async getFeeData(): Promise<ChainFeeData> {
    const fd = await this.provider.getFeeData();
    if (this.supportsEIP1559() && fd.maxFeePerGas && fd.maxPriorityFeePerGas) {
      return {
        maxFeePerGas: fd.maxFeePerGas,
        maxPriorityFeePerGas: fd.maxPriorityFeePerGas,
      };
    }
    if (fd.gasPrice) {
      return { gasPrice: fd.gasPrice };
    }
    throw new Error(`Chain ${this.name} (${this.chainId}) returned no usable fee data`);
  }

  /**
   * Estimate gas limit with this chain's safety multiplier.
   * Used by callers that need to populate gasLimit explicitly (e.g. for
   * pre-funding calculations). Most write calls will let ethers estimate
   * automatically; this is for the cases where ethers' estimate is unsafe
   * (Polygon Amoy, JOC) and a multiplier is required.
   */
  async estimateGas(
    populated: ethers.providers.TransactionRequest
  ): Promise<ethers.BigNumber> {
    const estimate = await this.provider.estimateGas(populated);
    const multiplier = this.policy.gasLimitMultiplier ?? 1.3;
    // Multiply via integer math to stay in BigNumber-land.
    const num = Math.round(multiplier * 100);
    return estimate.mul(num).div(100);
  }

  /** Convenience: gwei → BigNumber wei */
  protected gwei(n: number): ethers.BigNumber {
    return ethers.utils.parseUnits(String(n), 'gwei');
  }
}