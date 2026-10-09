import { ethers } from 'ethers';
import { Chain, ChainFeeData } from './Chain';
import { registerChain } from './registry';

/**
 * Japan Open Chain (chainId 81).
 *
 * Why this class exists: JOC is a legacy gasPrice chain. Its base fee is
 * effectively zero, but the RPC enforces a high *minimum* gas price (around
 * 30 gwei). EIP-1559 fields are not honored — submitting a transaction with
 * maxFeePerGas/maxPriorityFeePerGas instead of gasPrice gets rejected.
 *
 * The base class would happily try to use EIP-1559; we override
 * supportsEIP1559() to false and return only `gasPrice`, clamped to the
 * configured floor.
 */
export class JapanOpenChain extends Chain {
  static chainId = 81;
  static defaults = {
    name: 'Japan Open Chain',
    aliases: ['joc', 'japan'],
    rpc: 'https://rpc-2.japanopenchain.org:8545',
    nativeCurrencyName: 'JOC',
    nativeCurrencySymbol: 'JOC',
    nativeCurrencyDecimals: 18,
  };

  supportsEIP1559(): boolean {
    return false;
  }

  protected minGasPrice(): ethers.BigNumber {
    return this.gwei(this.policy.minGasPriceGwei ?? 30);
  }

  async getFeeData(): Promise<ChainFeeData> {
    const fd = await this.provider.getFeeData();
    const floor = this.minGasPrice();
    const networkPrice = fd.gasPrice ?? floor;
    const gasPrice = networkPrice.gt(floor) ? networkPrice : floor;

    // Hard ceiling matching PolygonChain — refuse to send if the chain
    // wants more than the operator is willing to pay. Default 200 gwei.
    const ceiling = this.gwei(this.policy.maxGasPriceGwei ?? 1000);
    if (gasPrice.gt(ceiling)) {
      throw new Error(
        `JOC gas price ${ethers.utils.formatUnits(gasPrice, 'gwei')} gwei exceeds ` +
        `cap ${ethers.utils.formatUnits(ceiling, 'gwei')} gwei. ` +
        `Raise policy.maxGasPriceGwei in config.ini if intentional.`
      );
    }

    return { gasPrice };
  }
}

registerChain(JapanOpenChain.chainId, JapanOpenChain);