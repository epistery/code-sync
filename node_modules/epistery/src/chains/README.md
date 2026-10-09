# `epistery/chains`

Each EVM chain epistery talks to is represented by a `Chain` object. The
`Chain` class owns everything chain-specific: the JSON-RPC provider, the fee
policy, the gas-limit estimation strategy, and the contract Proxy that
injects per-chain fee data into write transactions. Wallets, ABIs, and
domain config storage are *not* the chain's job.

## Adding a new chain

A new chain is one file. No edits to `Chain.ts`, `registry.ts`, or any
existing chain class.

```ts
// src/chains/MyNewChain.ts
import { ethers } from 'ethers';
import { Chain, ChainFeeData } from './Chain';
import { registerChain } from './registry';

export class MyNewChain extends Chain {
  static chainId = 1234;

  // Network details + the short names `epistery initialize --chain` accepts.
  // Aliases must be unique across registered chains.
  static defaults = {
    name: 'My New Chain',
    aliases: ['mynew', 'mnc'],
    rpc: 'https://rpc.mynewchain.example',
    nativeCurrencyName: 'MNC',
    nativeCurrencySymbol: 'MNC',
    nativeCurrencyDecimals: 18,
  };

  // Override only what's actually different from the EIP-1559 default.
  // Skip this method entirely if the network behaves normally.
  async getFeeData(): Promise<ChainFeeData> {
    const fd = await this.provider.getFeeData();
    // ... whatever this chain needs ...
    return { maxFeePerGas: ..., maxPriorityFeePerGas: ... };
  }
}

registerChain(MyNewChain.chainId, MyNewChain);
```

Then add **one** line to `src/chains/index.ts`:

```ts
export { MyNewChain } from './MyNewChain';
```

That export both makes the class importable and triggers the
`registerChain()` call at module load.

## Adding a chain *without* editing the package

A downstream consumer (e.g. an agent, a host, an app) can register its own
chain without forking epistery. Write the same kind of file in your own
codebase, then `import` it once during startup:

```ts
import 'my-app/chains/MyNewChain';
```

The registry is a module-scoped `Map`, so the registration is idempotent
and survives across the entire process. Once registered, the chain shows up in
`epistery chains` and can be selected with `epistery initialize --chain`.

## What goes in a Chain subclass

Override only the hooks that are actually different from the generic
EIP-1559 default. The base class is intentionally usable as-is for any
well-behaved EVM chain — you don't need a subclass to support a new chain
unless that chain misbehaves in some way.

| Hook                  | Why you'd override it                                          |
| --------------------- | -------------------------------------------------------------- |
| `getFeeData()`        | Network ignores `eth_feeHistory`, has a fee floor, etc.        |
| `supportsEIP1559()`   | Legacy gasPrice-only chain (e.g. Japan Open Chain).            |
| `estimateGas()`       | RPC's gas estimate is unreliable; need a different multiplier. |
| `wrapContract()`      | Almost never. Only if the chain needs different override merging. |

## Per-chain config knobs

Each chain reads its policy knobs from the `policy` field of the provider
config in epistery's root config file. These are *optional* — defaults are
in code, so a fresh install Just Works:

```ini
[default.rpc.137]
name = "Polygon Mainnet"
publicRpc = "https://polygon-bor-rpc.publicnode.com"
privateRpc = "https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY"
nativeCurrencyName = "POL"
nativeCurrencySymbol = "POL"

; Policy knobs, all optional (defaults are in code).
[default.rpc.137.policy]
minPriorityFeeGwei = 25     ; Polygon's RPC floor
maxFeeMultiplier = 2        ; maxFeePerGas >= 2 * maxPriorityFeePerGas
gasLimitMultiplier = 1.3    ; estimateGas safety margin

; Attestation reads (who may seat a device, roles) go to OWNED nodes, k-of-n:
[chains.polygon]
attest = ["https://node.rootz.global/"]
quorum = 1
```

If you find yourself adding a new policy field, add it to `ChainPolicy` in
`Chain.ts` and document it here. Don't smuggle ad-hoc fields in via casts.

## What this replaces

Before this module, gas/fee logic lived in three different places:

1. `epistery/src/utils/Utils.ts` — `getGasPriceWithBuffer`, `addGasBuffer`,
   `FALLBACK_GAS_LIMIT`, hard-coded constants for Polygon mainnet/Amoy.
2. `epistery-host/utils/DomainChain.mjs` — a parallel `getFeeData()` and a
   contract-mutation wrapper that crashed under ESM strict mode.
3. Anywhere a developer constructed a bare `new ethers.providers.JsonRpcProvider(rpc)`
   without an explicit network — the source of every "could not detect network"
   warning in the logs.

All three should call `chainFor(domainConfig.provider)` and use the
returned `Chain` instance.
