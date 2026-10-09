import { ethers } from 'ethers';
import { Chain, ChainFeeData } from './Chain';
import { registerChain } from './registry';

/**
 * Polygon mainnet (chainId 137).
 *
 * Why this class exists: Polygon enforces a hard 25 gwei minimum priority fee
 * at the RPC level. Transactions submitted with a lower priority fee are
 * rejected with "max fee per gas less than block base fee" or simply silently
 * dropped. ethers v5's getFeeData() does NOT know about this floor and will
 * happily return ~1.5 gwei from eth_feeHistory.
 *
 * The fix: clamp maxPriorityFeePerGas to at least 25 gwei (overridable via
 * policy.minPriorityFeeGwei in root config) and ensure maxFeePerGas >=
 * 2 * maxPriorityFeePerGas.
 */
export class PolygonChain extends Chain {
  static chainId = 137;
  static defaults = {
    name: 'Polygon Mainnet',
    aliases: ['polygon', 'pol', 'matic'],
    rpc: 'https://polygon-bor-rpc.publicnode.com',
    nativeCurrencyName: 'POL',
    nativeCurrencySymbol: 'POL',
    nativeCurrencyDecimals: 18,
  };

  protected minPriorityFee(): ethers.BigNumber {
    return this.gwei(this.policy.minPriorityFeeGwei ?? 25);
  }

  async getFeeData(): Promise<ChainFeeData> {
    const fd = await this.provider.getFeeData();
    const floor = this.minPriorityFee();

    const networkPriority = fd.maxPriorityFeePerGas ?? floor;
    const maxPriorityFeePerGas = networkPriority.gt(floor) ? networkPriority : floor;

    const multiplier = this.policy.maxFeeMultiplier ?? 2;
    const minMaxFee = maxPriorityFeePerGas.mul(multiplier);
    const networkMax = fd.maxFeePerGas ?? minMaxFee;
    const maxFeePerGas = networkMax.gt(minMaxFee) ? networkMax : minMaxFee;

    // Hard ceiling: refuse to send if the chain wants more than the operator
    // is willing to pay. Default 1000 gwei: real Polygon congestion can hit
    // 500–800 gwei legitimately, so the cap should catch only catastrophic
    // anomalies that would drain a wallet. Override via policy.maxFeePerGasGwei.
    const ceiling = this.gwei(this.policy.maxFeePerGasGwei ?? 1000);
    if (maxFeePerGas.gt(ceiling)) {
      throw new Error(
        `Polygon fee ${ethers.utils.formatUnits(maxFeePerGas, 'gwei')} gwei exceeds ` +
        `cap ${ethers.utils.formatUnits(ceiling, 'gwei')} gwei. ` +
        `Raise policy.maxFeePerGasGwei in config.ini if intentional.`
      );
    }
    return { maxPriorityFeePerGas, maxFeePerGas };
  }
}

/**
 * Polygon Amoy testnet (chainId 80002).
 *
 * Same fee floor concerns as Polygon mainnet — Amoy is the canonical Polygon
 * PoS testnet and the RPC enforces an identical 25 gwei priority floor.
 * Subclassing PolygonChain keeps the policy in one place.
 */
export class AmoyChain extends PolygonChain {
  static chainId = 80002;
  static defaults = {
    name: 'Polygon Amoy Testnet',
    aliases: ['amoy', 'polygonamoy'],
    rpc: 'https://rpc-amoy.polygon.technology',
    nativeCurrencyName: 'POL',
    nativeCurrencySymbol: 'POL',
    nativeCurrencyDecimals: 18,
  };
}

registerChain(PolygonChain.chainId, PolygonChain);
registerChain(AmoyChain.chainId, AmoyChain);